"""Offline U6 preparation checks. Synthetic bytes/identities only; no signing or browser launch."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_webhost", ROOT / "scripts/prepare-webhost-release.py")
web = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web)


class FakeInspector:
    def __init__(self):
        self.known = {}
        self.paths = []
        self.hook = None

    def register(self, data, signed_as, **changes):
        fields = {"identifier": signed_as, "team": web.installer.TEAM, "cdhash": hashlib.sha1(data).hexdigest(),
                  "hardened": True, "get_task_allow": False}
        fields.update(changes)
        found = web.installer.CodeIdentity(**fields)
        self.known[web.digest(data)] = found
        return found

    def identity(self, path):
        self.paths.append(Path(path))
        if self.hook:
            self.hook(Path(path))
        found = self.known.get(web.digest(Path(path).read_bytes()))
        if found is None:
            raise web.Refusal("synthetic code is not recognized")
        return found

    def satisfies(self, path, requirement):
        found = self.identity(path)
        return requirement == web.installer.requirement(found.identifier, found.cdhash) and found.team == web.installer.TEAM


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="av-webhost-preparation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.now = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
        self.inspector = FakeInspector()
        self.host = b"\xcf\xfa\xed\xfesynthetic-host"
        self.browser = b"\xcf\xfa\xed\xfesynthetic-browser"
        self.helper = b"\xcf\xfa\xed\xfesynthetic-library"
        self.version = "149.0.7000.1"
        self.url = f"https://storage.googleapis.com/chrome-for-testing-public/{self.version}/mac-arm64/chrome-headless-shell-mac-arm64.zip"
        (self.root / "browser").mkdir()
        for name, data in {"host": self.host, "browser/chrome-headless-shell": self.browser,
                           "browser/libfixture.dylib": self.helper, "browser/LICENSE": b"synthetic notice",
                           "p0-report.txt": b"SYNTHETIC ONLY: not an OS proof"}.items():
            (self.root / name).write_bytes(data)
        (self.root / "host").chmod(0o755)
        (self.root / "browser/chrome-headless-shell").chmod(0o755)
        with zipfile.ZipFile(self.root / "archive.zip", "w") as archive:
            for path in sorted((self.root / "browser").iterdir()):
                archive.writestr(web.BROWSER_ROOT + "/" + path.name, path.read_bytes())
        self.host_identity = self.inspector.register(self.host, web.HOST_ID)
        main = self.inspector.register(self.browser, web.BROWSER_ID)
        helper = self.inspector.register(self.helper, web.BROWSER_ID + ".libfixture")
        self.policy = {"format": "agent-vault-webhost-entitlements-v1", "reportSHA256": web.digest((self.root / "p0-report.txt").read_bytes()),
                       "host": {}, "browser": {"chrome-headless-shell": {}, "libfixture.dylib": {}}}
        self.write("policy.json", self.policy)
        self.pin = {"format": "agent-vault-chromium-pin-v1", "platform": "mac-arm64", "version": self.version,
                    "archiveURL": self.url, "archiveSHA256": web.digest((self.root / "archive.zip").read_bytes()),
                    "files": web.inventory(self.root / "browser")[0],
                    "code": {"chrome-headless-shell": {"identifier": main.identifier, "cdhash": main.cdhash},
                             "libfixture.dylib": {"identifier": helper.identifier, "cdhash": helper.cdhash}},
                    "p0PolicySHA256": web.digest((self.root / "policy.json").read_bytes()),
                    "p0ReportSHA256": self.policy["reportSHA256"]}
        self.write("pin.json", self.pin)
        self.metadata = {"timestamp": "2026-10-15T10:00:00Z", "channels": {"Stable": {"channel": "Stable", "version": self.version,
                         "downloads": {"chrome-headless-shell": [{"platform": "mac-arm64", "url": self.url}]}}}}
        self.write_metadata()
        pins = {program.identifier: (str(index) * 40) for index, program in enumerate(web.installer.PROGRAMS, 1)}
        (self.root / "broker.json").write_bytes(web.installer.render_config(pins, 201, 501, b"\x04" + b"x" * 64))
        self.args = argparse.Namespace(pin=self.root / "pin.json", stable_metadata=self.root / "stable.json",
            metadata_receipt=self.root / "receipt.json", p0_policy=self.root / "policy.json", p0_report=self.root / "p0-report.txt",
            host=self.root / "host", host_sha256=web.digest(self.host), browser=self.root / "browser",
            archive=self.root / "archive.zip", broker_config=self.root / "broker.json", host_uid=202, output=self.root / "prepared")

    def write(self, name, value):
        (self.root / name).write_bytes(web.json_bytes(value))

    def write_metadata(self, retrieved="2026-10-15T11:00:00Z"):
        self.write("stable.json", self.metadata)
        self.write("receipt.json", {"format": "agent-vault-cft-metadata-receipt-v1", "sourceURL": web.METADATA_URL,
                   "retrievedAt": retrieved, "sha256": web.digest((self.root / "stable.json").read_bytes())})

    def prepare(self):
        return web.prepare(self.args, self.inspector, self.now)

    def refused(self, message=None):
        with self.assertRaises((web.Refusal, OSError)) as caught:
            self.prepare()
        if message:
            self.assertIn(message, str(caught.exception))
        self.assertFalse(self.args.output.exists())

    def test_stages_exact_signed_inventory_and_never_installs_or_enables(self):
        with mock.patch.object(web.installer, "run_command", side_effect=AssertionError("external command")):
            manifest = self.prepare()
        self.assertFalse(manifest["installable"] or manifest["distributionReady"] or manifest["browserEnabled"])
        self.assertFalse(manifest["runtimeProofVerified"] or manifest["notarized"] or manifest["offlineEvidenceAuthenticated"])
        self.assertEqual((self.args.output / web.HOST_BINARY).read_bytes(), self.host)
        for name, entry in manifest["files"].items():
            self.assertEqual(web.digest((self.args.output / name).read_bytes()), entry["sha256"])
        config = json.loads((self.args.output / "deployment/webhost.json.disabled").read_bytes())
        plist = plistlib.loads((self.args.output / "deployment/dev.agentvault.webhost.plist.disabled").read_bytes())
        plan = json.loads((self.args.output / "deployment/install-plan.json").read_bytes())
        self.assertEqual(config["hostRequirement"], web.installer.requirement(web.HOST_ID, self.host_identity.cdhash))
        self.assertEqual(config["brokerUID"], 201)
        self.assertEqual(config["agentUID"], 501)
        self.assertEqual(config["hostUID"], 202)
        self.assertEqual(set(plist["MachServices"]), {config["serviceName"]})
        self.assertEqual(plist["Program"], web.HOST_PATH)
        self.assertEqual(plist["UserName"], "_agentvaultweb")
        self.assertEqual(plist["WorkingDirectory"], web.DATA_PATH)
        self.assertEqual(set(plan["unverifiedGates"]), {"P0", "P1", "P2", "P3", "P4"})
        self.assertFalse(plan["account"]["create"])
        for path in self.inspector.paths:
            self.assertNotEqual(path, self.args.host)
            self.assertIn(".agentvault-webhost-", str(path))
        sbom = json.loads((self.args.output / "sbom.cdx.json").read_bytes())
        self.assertEqual(sbom["components"][0]["externalReferences"][0]["hashes"][0]["content"], self.pin["archiveSHA256"])
        self.assertEqual(sbom["components"][1]["hashes"][0]["content"], self.args.host_sha256)
        self.assertEqual(web.installer.PROGRAMS[-1].identifier, "dev.agentvault.app")
        self.assertEqual(len(web.installer.PROGRAMS), 3)

    def test_checked_in_pin_fails_with_concrete_missing_prerequisite(self):
        self.args.pin = ROOT / "deploy/webhost/chromium.pin.json"
        self.refused("unconfigured")

    def test_stale_future_mismatched_and_nonstable_metadata_stop_preparation(self):
        for retrieved in ("2026-10-14T10:00:00Z", "2026-10-15T13:00:00Z"):
            self.write_metadata(retrieved)
            self.refused("stale or future")
        self.metadata["channels"]["Stable"]["version"] = "1.2.3.4"
        self.write_metadata()
        self.refused("latest Stable")
        self.metadata["channels"]["Stable"]["version"] = self.version
        self.metadata["timestamp"] = "2026-10-01T10:00:00Z"
        self.write_metadata()
        self.refused("timestamp is stale")

    def test_metadata_receipt_is_bound_to_exact_bytes(self):
        with (self.root / "stable.json").open("ab") as handle:
            handle.write(b"\n")
        self.refused("does not match")

    def test_nonofficial_or_ambiguous_archive_urls_are_rejected(self):
        for url in (self.url.replace("storage.googleapis.com", "storage.googleapis.com.evil.test"), self.url + "?override=1",
                    self.url.replace("https:", "http:"), self.url.replace("mac-arm64", "mac-x64")):
            self.pin["archiveURL"] = url
            self.write("pin.json", self.pin)
            self.refused("fixed official")

    def test_report_policy_archive_and_host_are_bound_to_their_pins(self):
        for name, expected in (("p0-report.txt", "P0 report"), ("policy.json", "entitlement policy"),
                               ("archive.zip", "source archive SHA-256"), ("host", "host bytes")):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            self.refused(expected)
            path.write_bytes(original)

    def test_no_json_approved_flag_can_substitute_for_measured_policy(self):
        self.write("policy.json", {"approved": True})
        self.pin["p0PolicySHA256"] = web.digest((self.root / "policy.json").read_bytes())
        self.write("pin.json", self.pin)
        self.refused("unexpected or missing keys")

    def test_all_browser_bytes_modes_and_code_files_are_inventoried(self):
        resource = self.root / "browser/LICENSE"
        resource.write_bytes(b"replacement")
        self.refused("signed-tree inventory")
        resource.write_bytes(b"synthetic notice")
        resource.chmod(0o755)
        self.refused("not inventoried Mach-O")
        resource.chmod(0o644)
        (self.root / "browser/extra").write_bytes(b"new file")
        self.refused("signed-tree inventory")

    def test_links_fifos_and_hardlinks_never_enter_payload(self):
        extra = self.root / "browser/extra"
        for create in (lambda: extra.symlink_to("LICENSE"), lambda: os.mkfifo(extra),
                       lambda: os.link(self.root / "browser/LICENSE", extra)):
            create()
            self.refused()
            extra.unlink()

    def test_nested_duplicate_json_keys_and_path_traversal_are_rejected(self):
        (self.root / "pin.json").write_text('{"status":"unconfigured","status":"configured"}')
        self.refused("duplicate")
        self.pin["files"]["../escape"] = {"sha256": "a" * 64, "executable": False}
        self.write("pin.json", self.pin)
        self.refused("relative paths")

    def test_foreign_ad_hoc_unhardened_or_debuggable_signatures_are_rejected(self):
        for overrides in ({"team": "-"}, {"team": "OTHERTEAM"}, {"hardened": False},
                          {"identifier": "dev.agentvault.app"}, {"get_task_allow": True},
                          {"entitlements": {"com.apple.security.cs.debugger": True}}):
            self.inspector.register(self.host, web.HOST_ID, **overrides)
            self.refused()

    def test_all_nested_macho_signatures_and_exact_entitlements_are_checked(self):
        self.inspector.register(self.helper, web.BROWSER_ID + ".libfixture", team="-")
        self.refused("exact Bite")
        self.inspector.register(self.helper, web.BROWSER_ID + ".libfixture", entitlements={"unexpected": True})
        self.refused("exact P0 policy")
        self.inspector.register(self.helper, web.BROWSER_ID + ".libfixture")
        self.pin["code"].pop("libfixture.dylib")
        self.write("pin.json", self.pin)
        self.refused("P0 policy must name")

    def test_three_uid_roles_and_existing_code_roles_cannot_alias(self):
        for uid in (0, True, 201, 501, 2**32 - 1):
            self.args.host_uid = uid
            self.refused("distinct non-root")

    def test_source_swapped_after_snapshot_cannot_change_published_bytes(self):
        def replace_source(_):
            self.args.host.write_bytes(b"unreviewed later host")
        self.inspector.hook = replace_source
        self.prepare()
        self.assertEqual((self.args.output / web.HOST_BINARY).read_bytes(), self.host)

    def test_staged_mutation_during_inspection_is_refused(self):
        def mutate_staged(path):
            if path.name == web.HOST_BINARY:
                (path.parent / web.BROWSER_ROOT / "LICENSE").write_bytes(b"unreviewed")
        self.inspector.hook = mutate_staged
        self.refused("changed during signature inspection")

    def test_never_replaces_an_existing_output(self):
        self.args.output.mkdir()
        (self.args.output / "keep").write_text("existing artifact")
        with self.assertRaisesRegex(web.Refusal, "already exists"):
            self.prepare()
        self.assertEqual((self.args.output / "keep").read_text(), "existing artifact")

    def test_read_only_verifier_rechecks_bytes_signatures_plan_and_supplied_freshness(self):
        original = self.prepare()
        manifest_hash = web.digest((self.args.output / "manifest.json").read_bytes())
        verified = web.verify_payload(self.args.output, manifest_hash, self.inspector, self.now)
        self.assertEqual(verified, original)
        with self.assertRaisesRegex(web.Refusal, "stale or future"):
            web.verify_payload(self.args.output, manifest_hash, self.inspector, self.now + timedelta(days=2))
        self.inspector.register(self.host, web.HOST_ID, team="-")
        with self.assertRaisesRegex(web.Refusal, "exact Bite"):
            web.verify_payload(self.args.output, manifest_hash, self.inspector, self.now)

    def test_payload_and_self_rewritten_manifest_cannot_replace_retained_hash(self):
        self.prepare()
        manifest_path = self.args.output / "manifest.json"
        retained = web.digest(manifest_path.read_bytes())
        (self.args.output / web.BROWSER_ROOT / "LICENSE").write_bytes(b"tampered")
        with self.assertRaisesRegex(web.Refusal, "payload bytes or modes"):
            web.verify_payload(self.args.output, retained, self.inspector, self.now)
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][web.BROWSER_ROOT + "/LICENSE"]["sha256"] = web.digest(b"tampered")
        manifest_path.write_bytes(web.json_bytes(manifest))
        with self.assertRaisesRegex(web.Refusal, "externally retained"):
            web.verify_payload(self.args.output, retained, self.inspector, self.now)

    def test_payload_permissions_are_bound_and_unsafe_directories_are_refused(self):
        self.prepare()
        retained = web.digest((self.args.output / "manifest.json").read_bytes())
        (self.args.output / web.BROWSER_ROOT / "LICENSE").chmod(0o600)
        with self.assertRaisesRegex(web.Refusal, "bytes or modes"):
            web.verify_payload(self.args.output, retained, self.inspector, self.now)
        (self.args.output / web.BROWSER_ROOT / "LICENSE").chmod(0o644)
        (self.args.output / "evidence").chmod(0o777)
        with self.assertRaisesRegex(web.Refusal, "unsafe permission"):
            web.verify_payload(self.args.output, retained, self.inspector, self.now)

    def test_changed_plan_is_rejected_even_if_a_new_manifest_hash_is_supplied(self):
        self.prepare()
        plan_path = self.args.output / "deployment/install-plan.json"
        plan = json.loads(plan_path.read_bytes())
        plan["account"]["create"] = True
        plan_path.write_bytes(web.json_bytes(plan))
        manifest_path = self.args.output / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"]["deployment/install-plan.json"]["sha256"] = web.digest(plan_path.read_bytes())
        manifest_path.write_bytes(web.json_bytes(manifest))
        with self.assertRaisesRegex(web.Refusal, "exact derived roles"):
            web.verify_payload(self.args.output, web.digest(manifest_path.read_bytes()), self.inspector, self.now)

    def test_missing_p0_policy_is_a_clear_prerequisite_failure(self):
        self.args.p0_policy.unlink()
        self.refused("P0 prerequisite missing")

    def rewrite_archive(self, entries):
        with zipfile.ZipFile(self.root / "archive.zip", "w") as archive:
            for name, data in entries:
                archive.writestr(name, data)
        self.pin["archiveSHA256"] = web.digest((self.root / "archive.zip").read_bytes())
        self.write("pin.json", self.pin)

    def test_archive_path_traversal_and_changed_resources_are_refused(self):
        self.rewrite_archive([("../escape", b"x")])
        self.refused("relative paths")
        self.rewrite_archive([(web.BROWSER_ROOT + "/LICENSE", b"changed upstream resource")])
        self.refused("changed an upstream resource")

    def test_archive_and_signed_tree_must_have_the_same_resource_and_code_paths(self):
        self.rewrite_archive([(web.BROWSER_ROOT + "/LICENSE", b"synthetic notice")])
        self.refused("different files")

    def test_broker_configuration_must_have_exact_pinned_production_roles(self):
        path = self.root / "broker.json"
        original = path.read_bytes()
        config = json.loads(original)
        config["ipc"]["development"] = True
        path.write_bytes(web.json_bytes(config))
        self.refused("fixed production roles")
        config = json.loads(original)
        config["ipc"]["brokerRequirement"] = web.installer.requirement("dev.agentvault.broker")
        path.write_bytes(web.json_bytes(config))
        self.refused("pinned requirement")
        path.write_bytes(original.replace(b'"development": false', b'"development": false, "development": false'))
        self.refused("duplicate")

    def test_host_and_main_browser_must_be_executable(self):
        self.args.host.chmod(0o644)
        self.refused("host bytes")
        self.args.host.chmod(0o755)
        self.pin["files"]["chrome-headless-shell"]["executable"] = False
        self.write("pin.json", self.pin)
        self.refused("main browser must be executable")

    def test_entitlement_types_are_exact_not_python_bool_integer_equality(self):
        self.policy["browser"]["libfixture.dylib"] = {"claim": 1}
        self.write("policy.json", self.policy)
        self.pin["p0PolicySHA256"] = web.digest((self.root / "policy.json").read_bytes())
        self.write("pin.json", self.pin)
        self.inspector.register(self.helper, web.BROWSER_ID + ".libfixture", entitlements={"claim": True})
        self.refused("exact P0 policy")

    def test_root_is_refused_before_any_artifact_reads(self):
        with mock.patch.object(web.os, "geteuid", return_value=0):
            self.refused("never run as root")


if __name__ == "__main__":
    unittest.main()
