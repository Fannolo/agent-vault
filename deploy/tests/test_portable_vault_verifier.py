"""The portable codec's evidence runner must detect leaks and respect ownership."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("portable_verifier", ROOT / "scripts/verify-portable-vault.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class EvidenceBoundaryTests(unittest.TestCase):
    def test_secret_output_is_detected_in_each_supported_representation(self):
        secret = b"synthetic-secret-never-a-real-account"
        for value in (secret, secret.hex().encode(), secret.hex().upper().encode(),
                      base64.b64encode(secret), base64.urlsafe_b64encode(secret)):
            with self.subTest(representation=value):
                self.assertTrue(verifier.rejects_secret_output(value.decode(), [secret]))
        self.assertFalse(verifier.rejects_secret_output("test passed", [secret]))

    def test_container_identity_requires_matching_owner_and_full_identifier(self):
        value = {"Id": "a" * 64, "Config": {"Labels": {"dev.agentvault.verification-owner": "ours"}}}
        self.assertEqual(verifier.owned_container(json.dumps([value]), "ours"), "a" * 64)
        self.assertIsNone(verifier.owned_container(json.dumps([value]), "other"))
        value["Id"] = "agent-vault-codec-name"
        self.assertIsNone(verifier.owned_container(json.dumps([value]), "ours"))
        self.assertIsNone(verifier.owned_container("not json", "ours"))
        self.assertIsNone(verifier.owned_container("[]", "ours"))

    def test_source_record_covers_dependency_pin_and_test_code(self):
        with tempfile.TemporaryDirectory(prefix="av-codec-evidence-") as temporary:
            package = Path(temporary)
            (package / "Sources").mkdir()
            (package / "Tests").mkdir()
            for relative in ("Package.swift", "Package.resolved", "Sources/Core.swift", "Tests/CoreTests.swift"):
                (package / relative).write_text(relative)
            with mock.patch.object(verifier, "PACKAGE", package):
                before = verifier.source_digest()
                (package / "Package.resolved").write_text("different dependency")
                changed = verifier.source_digest()
                self.assertNotEqual(before, changed)
                (package / "Tests/CoreTests.swift").write_text("weaker test")
                self.assertNotEqual(changed, verifier.source_digest())

    def test_private_output_cannot_overwrite_an_existing_evidence_file(self):
        with tempfile.TemporaryDirectory(prefix="av-codec-evidence-") as temporary:
            path = Path(temporary) / "evidence"
            verifier.private_write(path, b"first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                verifier.private_write(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"first")


class FailureReportingTests(unittest.TestCase):
    def scenario(self, *, create_fails=False, inspection_raises=False, removal_fails=False,
                 source_changes=False, wrong_rejection=False):
        with tempfile.TemporaryDirectory(prefix="av-codec-failure-") as temporary:
            root = Path(temporary)
            owner = None
            evidence = None

            def run(command, **_):
                nonlocal owner, evidence
                if command[:3] == ["docker", "image", "inspect"]:
                    return 0, json.dumps([{"Id": "sha256:" + "b" * 64,
                                          "Os": "linux", "Architecture": "arm64"}])
                if command[0] == "/usr/bin/env":
                    value = command[1]
                    if value.startswith("AV_TEST_WRITE_FIXTURE="):
                        path = Path(value.split("=", 1)[1])
                        evidence = path.parent
                        path.write_bytes(b"synthetic ciphertext")
                    if value.endswith("corrupt.seal"):
                        return 1, "unrelated build failure" if wrong_rejection else "fixtureExchange: badSignature"
                    return 0, "tests passed"
                if command[:2] == ["docker", "create"]:
                    owner = command[command.index("--label") + 1].split("=", 1)[1]
                    return (17, "docker create failed") if create_fails else (0, "a" * 64)
                if command[:2] == ["docker", "start"]:
                    (evidence / "linux.seal").write_bytes(b"other synthetic ciphertext")
                    return 0, "tests passed"
                if command[:2] == ["docker", "inspect"]:
                    if inspection_raises:
                        raise OSError("external text must stay out of the error record")
                    if create_fails:
                        return 1, "no container"
                    return 0, json.dumps([{"Id": "a" * 64, "State": {"ExitCode": 0},
                                          "Config": {"Labels": {"dev.agentvault.verification-owner": owner}}}])
                if command[:2] == ["docker", "rm"]:
                    return (18, "remove failed") if removal_fails else (0, "removed")
                return 0, "synthetic environment metadata"

            hashes = ["initial", "changed" if source_changes else "initial"]
            with mock.patch.object(verifier, "ROOT", root), \
                 mock.patch.object(verifier, "PACKAGE", root / "package"), \
                 mock.patch.object(verifier, "source_digest", side_effect=hashes), \
                 mock.patch.object(verifier.owned, "run_owned", side_effect=run), \
                 mock.patch.object(verifier.sys, "platform", "darwin"):
                with self.assertRaises(BaseException) as caught:
                    verifier.main()
            reports = list((root / "verification-logs" / "portable-vault").glob("*/result.json"))
            self.assertEqual(len(reports), 1)
            return caught.exception, json.loads(reports[0].read_text())

    def test_failed_create_preserves_first_error_and_reports_cleanup_separately(self):
        error, report = self.scenario(create_fails=True)
        self.assertEqual(str(error), "failed_linux_create")
        self.assertEqual(report["failure"]["code"], "failed_linux_create")
        self.assertEqual(report["cleanup"]["status"], "unconfirmed")
        self.assertEqual(report["cleanup"]["error"]["code"], "owned_container_cleanup_unconfirmed")

    def test_cleanup_exception_still_writes_report_and_preserves_create_failure(self):
        error, report = self.scenario(create_fails=True, inspection_raises=True)
        self.assertEqual(str(error), "failed_linux_create")
        self.assertEqual(report["cleanup"]["error"], {"type": "OSError"})
        self.assertNotIn("external text", json.dumps(report))

    def test_cleanup_failure_on_an_otherwise_passing_run_fails_verification(self):
        error, report = self.scenario(removal_fails=True)
        self.assertEqual(str(error), "failed_container_remove")
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["cleanup"]["error"]["code"], "failed_container_remove")

    def test_source_change_is_recorded_without_replacing_the_first_error(self):
        error, report = self.scenario(create_fails=True, source_changes=True)
        self.assertEqual(str(error), "failed_linux_create")
        self.assertFalse(report["source_unchanged"])
        self.assertEqual(report["source_check_error"]["code"], "source_changed_during_recording")

    def test_unrelated_nonzero_exit_does_not_count_as_corrupt_record_rejection(self):
        error, report = self.scenario(wrong_rejection=True)
        self.assertEqual(str(error), "corrupt_exchange_not_rejected")
        self.assertEqual(report["cleanup"]["status"], "removed")


if __name__ == "__main__":
    unittest.main()
