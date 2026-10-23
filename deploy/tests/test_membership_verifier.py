"""U0 driver regressions: mock only owned process boundaries; no Swift/Docker execution.

The text fixtures use the Swift Testing event shape in retained codec logs. N1's
location comes from the badAuthentication source assertion, not a loose error token.
Actual Mac/Linux execution is a separate frozen-source recording gate.
"""
import base64
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import zlib
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("membership_controls_tested", ROOT / "scripts/verify-membership-controls.py")
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)
v = controls.verifier
NAMES = sorted([v.TARGET] + ["codecCase" + str(i) for i in range(20)])


def passing(names):
    count = len(names)
    return "\n".join(["◇ Test run started.", "↳ Testing Library Version: 6.2.4 (5ee435b15ad40ec)",
                      "↳ Target Platform: aarch64-unknown-linux-gnu"] + [f"◇ Test {name}() started." for name in names]
                     + [f"✔ Test {name}() passed after 0.001 seconds." for name in names]
                     + [f"✔ Test run with {count} test{'s' if count != 1 else ''} in 0 suites passed after 0.010 seconds.", ""])


def n1_failure(location=(2, 20)):
    line, column = location
    issue = f"✘ Test {v.TARGET}() recorded an issue at LowOrderTests.swift:{line}:{column}: Issue recorded"
    return "\n".join(["◇ Test run started.", "↳ Testing Library Version: 6.2.4 (5ee435b15ad40ec)",
                      "↳ Target Platform: aarch64-unknown-linux-gnu", f"◇ Test {v.TARGET}() started."]
                     + [value for _ in range(14) for value in (issue, "↳ Expected fixed codec error")]
                     + [f"✘ Test {v.TARGET}() failed after 0.010 seconds with 14 issues.",
                        "✘ Test run with 1 test in 0 suites failed after 0.010 seconds with 14 issues.", ""])


class Fixture:
    def __init__(self, root):
        root = root.resolve()
        self.root = root
        self.package = root / "Packages/VaultCore"
        self.owner = None
        self.calls = []
        self.fail_create = self.fail_cleanup = self.change_source = False
        self.wrong_owner = self.fail_mutant = False
        self.image = {"Id": "sha256:" + "b" * 64, "Os": "linux", "Architecture": "arm64", "RepoDigests": [v.IMAGE]}
        for name in (*v.HARNESS, "Package.swift", "Package.resolved"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            v.private_write(path, ("synthetic input " + name).encode())
        for part in ("Sources", "Tests"):
            (root / part).mkdir(mode=0o700)
        files = {"Package.swift": b"synthetic manifest", "Package.resolved": b"synthetic lock",
                 controls.RELATIVE: b"synthetic source\n" + controls.REMOVED,
                 "Tests/VaultCoreTests/LowOrderTests.swift": (
                     "@Test func " + v.TARGET + "() throws {\n"
                     "        expectError(.badAuthentication) { _ = try fixture.open(bytes) }\n}\n"
                     + "\n".join("@Test func " + name + "() throws {}" for name in NAMES if name != v.TARGET)).encode()}
        for name, data in files.items():
            path = self.package / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            v.private_write(path, data)

    @contextlib.contextmanager
    def patched(self):
        digest = v.package_snapshot(self.package)["sha256"]
        with contextlib.ExitStack() as stack:
            for obj, attr, value in ((v, "ROOT", self.root), (v, "PACKAGE", self.package),
                                     (v, "EXPECTED_SOURCE", digest), (v.portable, "PACKAGE", self.package),
                                     (v.portable, "__file__", str(self.root / "scripts/verify-portable-vault.py")),
                                     (v.owned, "__file__", str(self.root / "scripts/verify-webhost-link-mutations.py")),
                                     (v.tables, "__file__", str(self.root / "scripts/membership_spec.py")),
                                     (v.sys, "platform", "darwin")):
                stack.enter_context(mock.patch.object(obj, attr, value))
            stack.enter_context(mock.patch.object(v.owned, "run_owned", side_effect=self.run))
            stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
            stack.enter_context(mock.patch.object(v.sys, "argv", ["verify-membership.py"]))
            stack.enter_context(mock.patch("builtins.print"))
            yield

    def run(self, command, **kwargs):
        self.calls.append(command)
        if command[:3] == ["docker", "image", "inspect"]:
            return 0, json.dumps([self.image])
        if command[:2] == ["docker", "create"]:
            self.owner = command[command.index("--label") + 1].split("=", 1)[1]
            if self.change_source:
                (self.root / "scripts/verify-membership.py").write_text("changed source")
            return (9, "create failed") if self.fail_create else (0, "a" * 64)
        if command[:2] == ["docker", "inspect"]:
            return 0, json.dumps([{"Id": "a" * 64, "Image": self.image["Id"], "Config": {"Labels": {
                "dev.agentvault.verification-owner": "foreign" if self.wrong_owner else self.owner}}}])
        if command[:2] == ["docker", "rm"]:
            return (8, "remove failed") if self.fail_cleanup else (0, "a" * 64)
        if command[:2] == ["docker", "start"]:
            return 0, "a" * 64
        if command[0] == "/usr/bin/sw_vers":
            return 0, "ProductName: macOS\nProductVersion: 26.0"
        if command[-2:] == ["uname", "-m"] or command == ["/usr/bin/uname", "-m"]:
            return 0, "aarch64" if command[0] == "docker" else "arm64"
        if command[-2:] == ["cat", "/etc/os-release"]:
            return 0, 'NAME="Ubuntu"'
        if "swift" in command:
            swift = command[command.index("swift") + 1:]
            if swift == ["--version"]:
                return 0, "Swift version 6.2"
            if swift == ["-print-target-info"]:
                return 0, json.dumps({"target": {"triple": "aarch64-unknown-linux-gnu" if command[0] == "docker" else "arm64-apple-macosx15.0"}})
            if swift[0] == "build":
                return 0, "Building for debugging...\n[3/5] Compiling VaultCore RevisionCodec.swift\nBuild complete! (0.10s)\n"
            if swift[0] == "test":
                names = [v.TARGET] if "--filter" in swift else NAMES
                mounted = [c for c in self.calls if c[:2] == ["docker", "create"]][-1]
                mount = next(c for c in mounted if c.startswith("type=bind,src=") and "dst=/package," in c)
                copy = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
                mutant = controls.REMOVED not in (copy / controls.RELATIVE).read_bytes()
                if mutant and self.fail_mutant:
                    return None, "timeout"
                if mutant and command[0] == "docker":
                    return 1, n1_failure(v.n1_location(copy))
                return 0, passing(names)
        if command[-1].endswith("verify-boundaries.py"):
            return 0, "boundaries: PASS\n"
        raise AssertionError("unexpected mock command")

    def baseline(self):
        v.main()
        paths = list((self.root / "verification-logs/membership-u0-worker").glob("baseline-*/result.json"))
        if len(paths) != 1:
            raise AssertionError("one baseline report required")
        return paths[0]


class DriverTests(unittest.TestCase):
    def setUp(self):
        parent = Path(tempfile.gettempdir()) / "membership-verifier-tests"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent.chmod(0o700)
        self.temporary = tempfile.TemporaryDirectory(prefix="python-fixture-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name))

    def test_fixture_root_uses_canonical_path_through_directory_alias(self):
        parent = Path(self.temporary.name).resolve()
        canonical = parent / "canonical"
        canonical.mkdir()
        alias = parent / "alias"
        alias.symlink_to(canonical, target_is_directory=True)
        fixture = Fixture(alias / "fixture")
        self.assertEqual(fixture.root, canonical / "fixture")
        self.assertEqual(fixture.package, canonical / "fixture/Packages/VaultCore")
        with fixture.patched():
            path = fixture.baseline()
            self.assertEqual(v.verify_baseline(path, v.snapshot())["sha256"], v.sha(path.read_bytes()))

    def test_positive_baseline_binds_inputs_logs_commands_runtime_and_cleanup(self):
        f = self.fixture
        with f.patched():
            path = f.baseline()
            binding = v.verify_baseline(path, v.snapshot())
            self.assertEqual(binding["sha256"], v.sha(path.read_bytes()))
            self.assertEqual(v.verify_baseline(Path(os.path.relpath(path)), v.snapshot()), binding)
            report = json.loads(path.read_text())
            self.assertEqual(report["cleanup"], {"status": "removed"})
            self.assertEqual(len(report["suites"]["linux"]["tests"]), 21)
            self.assertEqual(len([c for c in f.calls if c[:2] == ["docker", "create"]]), 1)
            self.assertEqual([c for c in f.calls if c[:2] == ["docker", "rm"]], [["docker", "rm", "--force", "a" * 64]])
            for file in path.parent.glob("*.log"):
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_primary_cleanup_and_source_failures_survive_together(self):
        f = self.fixture
        f.fail_create = f.fail_cleanup = f.change_source = True
        with f.patched():
            with self.assertRaisesRegex(v.VerificationFailure, "failed_linux_create"):
                v.main()
            path = next((f.root / "verification-logs/membership-u0-worker").glob("baseline-*/result.json"))
            report = json.loads(path.read_text())
            self.assertEqual(report["failure"]["code"], "failed_linux_create")
            self.assertEqual(report["cleanup"]["error"]["code"], "failed_container_remove")
            self.assertEqual(report["source_check_error"]["code"], "source_changed_during_recording")
            self.assertEqual(report["status"], "fail")

    def test_cleanup_failure_alone_fails_recording(self):
        f = self.fixture
        f.fail_cleanup = True
        with f.patched():
            with self.assertRaisesRegex(v.VerificationFailure, "failed_container_remove"):
                v.main()
            path = next((f.root / "verification-logs/membership-u0-worker").glob("baseline-*/result.json"))
            report = json.loads(path.read_text())
            self.assertIsNone(report["failure"])
            self.assertEqual(report["status"], "fail")
            self.assertTrue(report["source_unchanged"])

    def test_foreign_container_is_never_started_or_removed(self):
        f = self.fixture
        f.wrong_owner = True
        with f.patched():
            with self.assertRaisesRegex(v.VerificationFailure, "linux_identity_unconfirmed"):
                v.main()
            self.assertFalse(any(c[:2] in (["docker", "rm"], ["docker", "start"]) for c in f.calls))

    def test_baseline_source_harness_lock_and_test_changes_fail(self):
        f = self.fixture
        with f.patched():
            path = f.baseline()
            original_snapshot = v.snapshot()
            for relative in ("scripts/verify-membership.py", "deploy/tests/test_membership_verifier.py",
                             "scripts/verify-webhost-link-mutations.py", "Package.resolved"):
                file = f.root / relative
                original = file.read_bytes()
                file.write_bytes(b"weaker input")
                with self.assertRaisesRegex(v.VerificationFailure, "matching_passed_baseline_required"):
                    v.verify_baseline(path, v.snapshot())
                file.write_bytes(original)
            file = f.package / "Package.resolved"
            file.write_bytes(b"different lock")
            with self.assertRaisesRegex(v.VerificationFailure, "frozen_codec_changed"):
                v.snapshot()
            self.assertNotEqual(v.package_snapshot(f.package), original_snapshot["package"])

    def test_changed_log_hash_is_rejected(self):
        # Required detector control: disabling verify_file must break this test.
        f = self.fixture
        with f.patched():
            path = f.baseline()
            log = path.parent / "native-baseline-test.log"
            log.write_bytes(log.read_bytes() + b"changed log\n")
            with self.assertRaisesRegex(v.VerificationFailure, "artifact_hash_mismatch"):
                v.verify_baseline(path, v.snapshot())

    def test_missing_oversized_symlink_artifacts_fail(self):
        file = self.fixture.root / "artifact"
        with self.assertRaisesRegex(v.VerificationFailure, "artifact_not_regular"):
            v.read_regular(file)
        file.write_bytes(b"12345")
        with self.assertRaisesRegex(v.VerificationFailure, "artifact_size_invalid"):
            v.read_regular(file, limit=4)
        alias = self.fixture.root / "alias"
        alias.symlink_to(file)
        with self.assertRaisesRegex(v.VerificationFailure, "artifact_not_regular"):
            v.read_regular(alias)

    def test_report_runtime_and_command_mismatch_fail(self):
        f = self.fixture
        with f.patched():
            path = f.baseline()
            original = json.loads(path.read_text())
            changed = json.loads(json.dumps(original))
            changed["runtime"]["linux_architecture"] = "x86_64"
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(v.VerificationFailure, "runtime_log_mismatch"):
                v.verify_baseline(path, v.snapshot())
            changed = json.loads(json.dumps(original))
            next(s for s in changed["steps"] if s["step"] == "native-baseline-test")["command"].append("--filter")
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(v.VerificationFailure, "baseline_command_mismatch"):
                v.verify_baseline(path, v.snapshot())

    def test_owned_control_restores_and_records_separate_platform_statuses(self):
        f = self.fixture
        with f.patched():
            baseline = f.baseline()
            initial = v.package_snapshot(f.package)
            with mock.patch.object(v.sys, "argv", ["verify-membership-controls.py", str(baseline)]):
                controls.main()
            path = next((f.root / "verification-logs/membership-u0-worker").glob("controls-*/result.json"))
            report = json.loads(path.read_text())
            self.assertEqual(report["status"], "pass")
            self.assertEqual([r["status"] for r in report["controls"]], ["backend_masked", "detected"])
            self.assertEqual(report["owned_copy_initial"], report["owned_copy_final"])
            self.assertEqual(initial, v.package_snapshot(f.package))
            for result in report["controls"]:
                self.assertEqual(result["baseline"]["status"], "pass")
                self.assertEqual(result["restored"]["status"], "pass")
            self.assertEqual(len([c for c in f.calls if c[:2] == ["docker", "create"]]), 2)

    def test_control_timeout_restores_and_reruns_passing_target(self):
        f = self.fixture
        with f.patched():
            baseline = f.baseline()
            f.fail_mutant = True
            with mock.patch.object(v.sys, "argv", ["verify-membership-controls.py", str(baseline)]):
                with self.assertRaisesRegex(v.VerificationFailure, "named_suite_not_passed"):
                    controls.main()
            path = next((f.root / "verification-logs/membership-u0-worker").glob("controls-*/result.json"))
            report = json.loads(path.read_text())
            result = report["controls"][0]
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["restored"]["status"], "pass")
            self.assertEqual(report["owned_copy_initial"], report["owned_copy_final"])
            self.assertEqual(report["cleanup"]["status"], "removed")

    def test_build_failure_never_runs_test_or_counts_as_detection(self):
        state = {"package": self.fixture.package, "evidence": self.fixture.root, "identifier": "a" * 64}
        steps = []
        run = v.make_run(self.fixture.root, steps)
        with mock.patch.object(v.owned, "run_owned", return_value=(1, "compiler error: unrelated")) as runner:
            with self.assertRaisesRegex(v.VerificationFailure, "failed_linux-mutant-build"):
                v.test_package(run, state, "linux", "mutant", [v.TARGET], mutant=True)
            self.assertEqual(runner.call_count, 1)
        with mock.patch.object(v.owned, "run_owned", return_value=(0, "no completed build")) as runner:
            with self.assertRaisesRegex(v.VerificationFailure, "build_completion_missing"):
                v.test_package(run, state, "linux", "missing", [v.TARGET], mutant=True)
            self.assertEqual(runner.call_count, 1)

    def test_primary_mutant_and_restore_failures_are_separate(self):
        f = self.fixture
        with f.patched():
            state, report, run = v.recording("controls")
            state["package"] = controls.copy_package(state["evidence"])
            path, original, mutated, _ = controls.mutation_bytes(state["package"], state["evidence"])
            def check(*args, **kwargs):
                if kwargs.get("mutant"):
                    raise v.VerificationFailure("primary_mutant_failure")
                return {"status": "pass"}
            @contextlib.contextmanager
            def broken_restore(path, original, mutated):
                path.write_bytes(mutated)
                yield
                raise OSError("private external diagnostic")
            with mock.patch.object(v, "test_package", side_effect=check), \
                 mock.patch.object(v.owned, "changed_source", side_effect=broken_restore):
                result, error = controls.platform_control(run, state, "linux", path, original, mutated)
            self.assertEqual(str(error), "primary_mutant_failure")
            self.assertEqual(result["failure"]["code"], "primary_mutant_failure")
            self.assertEqual(result["restore_error"], {"type": "OSError"})
            self.assertEqual(result["restored_test_error"]["code"], "owned_copy_not_restored")
            self.assertNotIn("private external diagnostic", json.dumps(result))

    def test_owned_runner_timeout_and_leak_are_recorded(self):
        f = self.fixture
        with f.patched():
            state, report, run = v.recording("baseline")
            with mock.patch.object(v.owned, "run_owned", return_value=(None, "timeout")):
                with self.assertRaisesRegex(v.VerificationFailure, "failed_timeout"):
                    run("timeout", ["synthetic-command"])
            with mock.patch.object(v.owned, "run_owned", return_value=(0, v.SENTINELS[0].decode())):
                with self.assertRaisesRegex(v.VerificationFailure, "synthetic_secret_output"):
                    run("leak", ["synthetic-command"])
            self.assertIsNone(report["steps"][0]["exit_code"])
            self.assertTrue(report["steps"][1]["secret_output_detected"])

    def test_cleanup_inspection_honors_disabled_scan_and_removes_owned_container(self):
        identifier, owner = "a" * 64, "synthetic-owner"
        inspection = json.dumps([{"Id": identifier, "Config": {
            "Labels": {"dev.agentvault.verification-owner": owner},
            "Env": [v.SENTINELS[0].decode()]}}])
        calls, steps = [], []
        def respond(command, **kwargs):
            calls.append(command)
            return (0, inspection) if command[:2] == ["docker", "inspect"] else (0, identifier)
        run = v.make_run(self.fixture.root, steps)
        with mock.patch.object(v.owned, "run_owned", side_effect=respond):
            v.cleanup_container(run, identifier, owner)
        self.assertEqual(calls, [["docker", "inspect", identifier],
                                 ["docker", "rm", "--force", identifier]])
        self.assertFalse(steps[0]["secret_output_detected"])
        self.assertEqual(steps[0]["exit_code"], 0)

    def test_recorded_scan_policy_is_explicit_and_checked(self):
        f = self.fixture
        with f.patched():
            path = f.baseline()
            report = json.loads(path.read_text())
            for step in report["steps"]:
                self.assertIs(step["secret_output_scanned"], step["step"] != "container_inspect")
            next(s for s in report["steps"] if s["step"] == "native-baseline-test")["secret_output_scanned"] = False
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(v.VerificationFailure, "baseline_scan_policy_mismatch"):
                v.verify_baseline(path, v.snapshot())

    def test_fixture_environment_refused(self):
        with mock.patch.dict(os.environ, {"AV_TEST_WRITE_FIXTURE": "/synthetic/path"}):
            with self.assertRaisesRegex(v.VerificationFailure, "fixture_environment_forbidden"):
                v.clean_env_required()

    def test_recorded_log_change_fails_before_pass(self):
        f = self.fixture
        with f.patched():
            state, report, run = v.recording("baseline")
            run("guard", [v.sys.executable, str(f.root / "scripts/verify-boundaries.py")])
            (state["evidence"] / "guard.log").write_text("changed")
            error = v.finish(report, state, run, report["snapshot"], None)
            self.assertEqual(str(error), "artifact_hash_mismatch")
            self.assertEqual(report["status"], "fail")


class DetectorTests(unittest.TestCase):
    def test_linux_n1_expected_failure_is_detected(self):
        self.assertTrue(v.n1_detected(1, n1_failure(), (2, 20)))

    def test_n1_wrong_missing_test_and_unrelated_failure_are_not_detected(self):
        # Required detector control: unconditional True must break this test.
        good = n1_failure()
        for code, output in ((0, good), (None, good), (-9, good), (2, good),
                             (1, good.replace(v.TARGET, "otherTest")),
                             (1, good.replace(f"◇ Test {v.TARGET}() started.\n", "")),
                             (1, good.replace("Expected fixed codec error", "Unexpected error type; details suppressed")),
                             (1, good.replace("LowOrderTests.swift:2:20", "LowOrderTests.swift:3:20")),
                             (1, "compiler: Expected fixed codec error"), (1, "unrelated failure"),
                             (1, good.replace("↳ Expected fixed codec error", "↳ Expected fixed codec error suffix", 1)),
                             (1, good + "✘ Test otherTest() recorded an issue\n"),
                             (1, good.replace("with 14 issues", "with 15 issues")),
                             (1, good + "error: Exited with unexpected signal code 6\n"),
                             (1, good + "[output capture ended without EOF after owned-group cleanup]\n")):
            with self.subTest(code=code, output=output[:70]):
                self.assertFalse(v.n1_detected(code, output, (2, 20)))

    def test_normal_suite_requires_exact_completed_tests_and_exit(self):
        good = passing(NAMES)
        self.assertTrue(v.passed_tests(0, good, NAMES))
        for code, output in ((1, good), (None, good), (0, passing(NAMES[:-1])), (0, "21 tests passed"),
                             (0, good.replace("codecCase0", "wrongTest")),
                             (0, good + "error: unexpected signal\n"),
                             (0, good.replace("◇ Test codecCase0() started.\n", ""))):
            self.assertFalse(v.passed_tests(code, output, NAMES))

    def test_finite_synthetic_output_forms(self):
        for value in v.SENTINELS:
            for form in (value, value.hex().encode(), value.hex().upper().encode(),
                         base64.b64encode(value), base64.urlsafe_b64encode(value)):
                self.assertTrue(v.portable.rejects_secret_output(form.decode("utf-8", "replace"), v.SENTINELS))
        self.assertFalse(v.portable.rejects_secret_output("ordinary test result", v.SENTINELS))

    def test_hash_binding_direct(self):
        parent = Path(tempfile.gettempdir()) / "membership-verifier-tests"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            path = Path(temporary) / "artifact"
            v.private_write(path, b"synthetic original")
            binding = v.file_record(path)
            path.write_bytes(b"synthetic changed!")
            with self.assertRaisesRegex(v.VerificationFailure, "artifact_hash_mismatch"):
                v.verify_file(path, binding)



class U1FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="membership-u1-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.package = self.root / "package"
        for name in v.ORIGINAL_FILES:
            path = self.package / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            v.private_write(path, v.read_regular(v.PACKAGE / name))
        self.corpus = self.root / "corpus"
        self.corpus.mkdir(mode=0o700)
        for name in v.EXCHANGE_LIMITS:
            data = self.membership() if name.endswith(".avm") else b"synthetic-revision"
            v.private_write(self.corpus / name, data)

    @staticmethod
    def membership(count=1, signature=0):
        prefix = b"AVMEMB01" + bytes([1, 1, 1]) + bytes(120) + count.to_bytes(4, "big")
        rows = b"".join(bytes([1, 1]) + bytes([index]) * 32 for index in range(count))
        # Structural synthetic bytes only. No signature validity claim.
        return prefix + rows + bytes([signature]) * 64

    def test_u1_inventory_preserves_original_subset(self):
        original = v.package_snapshot(self.package)
        self.assertEqual(original["sha256"], v.ORIGINAL_SOURCE)
        extra = self.package / "Tests/VaultCoreTests/SyntheticU1.swift"
        v.private_write(extra, b"@Test func syntheticU1Case() {}\n")
        frozen = v.package_snapshot(self.package)["files"]
        result = v.u1_package_snapshot(self.package, frozen)
        self.assertEqual(result["original"], original)
        self.assertNotEqual(result["combined"]["sha256"], original["sha256"])
        names = sorted((*v.ORIGINAL_NAMES, "syntheticU1Case"))
        self.assertEqual(v.u1_suite_names(self.package, names), names)
        self.assertTrue(v.passed_tests(0, passing(names), names))
        with self.assertRaisesRegex(v.VerificationFailure, "codec_test_inventory_changed"):
            v.suite_names(self.package)
        for changed in ({k: val for k, val in frozen.items() if k != extra.relative_to(self.package).as_posix()},
                        {**frozen, "Sources/VaultCore/Surprise.swift": {"size": 1, "sha256": "0" * 64}},
                        {**frozen, extra.relative_to(self.package).as_posix(): {"size": 1, "sha256": "0" * 64}}):
            with self.subTest(manifest=changed), self.assertRaisesRegex(
                    v.VerificationFailure, "u1_package_inventory_changed"):
                v.u1_package_snapshot(self.package, changed)
        alias = self.package / "Sources/VaultCore/Alias.swift"
        alias.symlink_to(extra)
        with self.assertRaisesRegex(v.VerificationFailure, "package_symlink"):
            v.u1_package_snapshot(self.package, frozen)

    def test_u1_original_bytes_cannot_be_replaced(self):
        for name in v.ORIGINAL_FILES:
            path = self.package / name
            original = path.read_bytes()
            with self.subTest(file=name), v.owned.changed_source(path, original, original + b"\n"):
                # Even a caller's replacement manifest cannot change the reviewed old bytes.
                changed = v.package_snapshot(self.package)["files"]
                with self.assertRaisesRegex(v.VerificationFailure, "u1_original_codec_changed"):
                    v.u1_package_snapshot(self.package, changed)

    def test_u1_original_files_cannot_be_missing_or_renamed(self):
        for name in ("Package.swift", "Sources/VaultCore/Binary.swift", "Tests/VaultCoreTests/Fixtures.swift"):
            path = self.package / name
            renamed = path.with_name("Renamed" + path.name)
            path.rename(renamed)
            try:
                with self.subTest(file=name), self.assertRaises(v.VerificationFailure):
                    v.u1_package_snapshot(self.package, {})
            finally:
                renamed.rename(path)

    def test_u1_original_names_cannot_be_replaced(self):
        tests = self.root / "inventory/Tests"
        tests.mkdir(parents=True, mode=0o700)
        path = tests / "Inventory.swift"
        for missing in v.ORIGINAL_NAMES:
            names = [name for name in v.ORIGINAL_NAMES if name != missing] + ["renamedOriginal"]
            path.write_text("\n".join("@Test func " + name + "() {}" for name in names))
            with self.subTest(missing=missing), self.assertRaisesRegex(
                    v.VerificationFailure, "u1_original_test_missing"):
                v.u1_suite_names(tests.parent, names)

    def test_u1_inventory_rejects_duplicate_missing_and_surprise_names(self):
        tests = self.root / "inventory/Tests"
        tests.mkdir(parents=True, mode=0o700)
        path = tests / "Inventory.swift"
        names = [*v.ORIGINAL_NAMES, "syntheticU1Case"]
        for actual, frozen, code in ((names + [names[0]], names, "u1_duplicate_test_name"),
                                     (names, names + [names[0]], "u1_duplicate_test_name"),
                                     (names[:-1], names, "u1_test_inventory_changed"),
                                     (names + ["surpriseCase"], names, "u1_test_inventory_changed")):
            path.write_text("\n".join("@Test func " + name + "() {}" for name in actual))
            with self.subTest(actual=actual, frozen=frozen), self.assertRaisesRegex(v.VerificationFailure, code):
                v.u1_suite_names(tests.parent, frozen)

    def test_exchange_file_set_is_exact(self):
        frozen = v.exchange_snapshot(self.root, "corpus")
        self.assertEqual(len(frozen), 13)
        path = self.corpus / "extra.avseal"
        v.private_write(path, b"synthetic-extra")
        with self.assertRaisesRegex(v.VerificationFailure, "exchange_file_set_invalid"):
            v.exchange_snapshot(self.root, "corpus")
        path.unlink()
        for name in v.EXCHANGE_LIMITS:
            path = self.corpus / name
            original = path.read_bytes()
            path.unlink()
            with self.subTest(missing=name), self.assertRaisesRegex(v.VerificationFailure, "exchange_file_set_invalid"):
                v.exchange_snapshot(self.root, "corpus")
            v.private_write(path, original)
        v.verify_exchange_snapshot(self.root, "corpus", frozen)

    def test_exchange_sizes_and_kinds_refused_before_open(self):
        for name, data in (("genesis.avm", b""), ("genesis.avm", bytes(232)),
                           ("genesis.avm", bytes(1288)), ("head0.avseal", b""),
                           ("head0.avseal", bytes(266500))):
            path = self.corpus / name
            original = path.read_bytes()
            with self.subTest(name=name, size=len(data)), v.owned.changed_source(path, original, data):
                with mock.patch.object(v.os, "open", side_effect=AssertionError("must refuse before open")):
                    with self.assertRaisesRegex(v.VerificationFailure, "artifact_size_invalid"):
                        v.exchange_snapshot(self.root, "corpus")
        path = self.corpus / "head0.avseal"
        original = path.read_bytes()
        for kind in ("directory", "fifo", "link"):
            path.unlink()
            if kind == "directory":
                path.mkdir(mode=0o700)
            elif kind == "fifo":
                os.mkfifo(path, 0o600)
            else:
                path.symlink_to(self.corpus / "head1.avseal")
            with self.subTest(kind=kind), self.assertRaisesRegex(v.VerificationFailure, "artifact_not_regular"):
                v.exchange_snapshot(self.root, "corpus")
            path.rmdir() if kind == "directory" else path.unlink()
            v.private_write(path, original)
        for name, (_, limit) in v.EXCHANGE_LIMITS.items():
            (self.corpus / name).write_bytes(self.membership(32) if name.endswith(".avm") else bytes(limit))
        full = v.exchange_snapshot(self.root, "corpus")
        self.assertEqual(sum(record["size"] for record in full.values()), 1873215)
        with mock.patch.object(v, "MAX_EXCHANGE", 1873214):
            with self.assertRaisesRegex(v.VerificationFailure, "exchange_size_invalid"):
                v.exchange_snapshot(self.root, "corpus")

    def test_exchange_paths_and_symlink_ancestors_refused(self):
        for relative in ("../corpus", "/corpus", "corpus/../corpus", "corpus//", "corpus/.", "corpus\\other", ""):
            with self.subTest(path=relative), self.assertRaisesRegex(v.VerificationFailure, "owned_path_invalid"):
                v.exchange_snapshot(self.root, relative)
        alias = self.root / "alias"
        alias.symlink_to(self.corpus, target_is_directory=True)
        for relative in ("alias", "alias/child"):
            with self.subTest(path=relative), self.assertRaisesRegex(v.VerificationFailure, "owned_path_invalid"):
                v.exchange_snapshot(self.root, relative)
        with self.assertRaisesRegex(v.VerificationFailure, "owned_path_invalid"):
            v.exchange_snapshot(alias, "child")

    def test_membership_body_identity_excludes_signature(self):
        first = self.membership(signature=1)
        second = self.membership(signature=2)
        self.assertNotEqual(v.sha(first), v.sha(second))
        self.assertEqual(v.membership_body_identity(first), v.membership_body_identity(second))
        self.assertEqual(v.membership_body_identity(first), {
            "size": 169, "member_count": 1, "sha256": v.sha(first[:169])})
        before = v.exchange_snapshot(self.root, "corpus")
        (self.corpus / "genesis.avm").write_bytes(second)
        after = v.exchange_snapshot(self.root, "corpus")
        self.assertEqual(before["genesis.avm"]["body"], after["genesis.avm"]["body"])
        self.assertNotEqual(before["genesis.avm"]["sha256"], after["genesis.avm"]["sha256"])
        with self.assertRaisesRegex(v.VerificationFailure, "exchange_changed"):
            v.verify_exchange_snapshot(self.root, "corpus", before)

    def test_membership_shape_is_bounded_and_canonical(self):
        good = self.membership(2)
        bad = [good[:index] for index in range(len(good))] + [good + b"x", bytes(1288)]
        for offset in (0, 8, 9, 10):
            bad.append(good[:offset] + bytes([good[offset] ^ 1]) + good[offset + 1:])
        for count in (0, 33, 4294967295):
            bad.append(good[:131] + count.to_bytes(4, "big") + good[135:])
        bad.extend([good[:135] + good[169:203] + good[135:169] + good[203:],
                    good[:169] + good[135:169] + good[203:]])
        for data in bad:
            with self.subTest(size=len(data)), self.assertRaisesRegex(v.VerificationFailure, "membership_shape_invalid"):
                v.membership_body_identity(data)
        self.assertEqual(v.membership_body_identity(self.membership(32))["size"], 1223)

    def test_exchange_rehash_refuses_changed_file(self):
        before = v.exchange_snapshot(self.root, "corpus")
        path = self.corpus / "head0.avseal"
        path.write_bytes(b"S" + path.read_bytes()[1:])
        with self.assertRaisesRegex(v.VerificationFailure, "exchange_changed"):
            v.verify_exchange_snapshot(self.root, "corpus", before)

    def test_owned_descriptor_checks_replacement_and_mid_read_change(self):
        path = self.corpus / "head0.avseal"
        original_open, original_read = os.open, os.read
        # Prepare replacement before intercepting the non-following descriptor open.
        replacement = self.root / "replacement"
        v.private_write(replacement, b"replacement")
        def replace_before_open(file, flags):
            replacement.replace(path)
            return original_open(file, flags)
        with mock.patch.object(v.os, "open", side_effect=replace_before_open):
            with self.assertRaisesRegex(v.VerificationFailure, "artifact_changed_during_read"):
                v._read_owned_regular(self.root, "corpus/head0.avseal", 1, 266499)
        changed = False
        def change_during_read(descriptor, size):
            nonlocal changed
            data = original_read(descriptor, size)
            if data and not changed:
                changed = True
                with path.open("ab") as stream:
                    stream.write(b"changed")
            return data
        with mock.patch.object(v.os, "read", side_effect=change_during_read):
            with self.assertRaisesRegex(v.VerificationFailure, "artifact_changed_during_read"):
                v._read_owned_regular(self.root, "corpus/head0.avseal", 1, 266499)
        path.unlink()
        v.private_write(path, b"synthetic")
        def link_before_open(file, flags):
            path.unlink()
            path.symlink_to(self.corpus / "head1.avseal")
            return original_open(file, flags)
        with mock.patch.object(v.os, "open", side_effect=link_before_open):
            with self.assertRaisesRegex(v.VerificationFailure, "owned_input_unavailable"):
                v._read_owned_regular(self.root, "corpus/head0.avseal", 1, 266499)

    def test_exchange_json_is_bounded_strict_and_has_no_status_oracle(self):
        data = b'{"status":"pass","unknown_future_version":77}'
        self.assertEqual(v.parse_exchange_json(data), json.loads(data))
        # Parsing alone deliberately makes no schema or U1 acceptance decision.
        at_limit = b'{"padding":"' + b"x" * (65536 - len(b'{"padding":""}')) + b'"}'
        self.assertEqual(len(at_limit), 65536)
        self.assertEqual(len(v.parse_exchange_json(at_limit)["padding"]), 65522)
        for data in (b"", at_limit + b" ", "{}"):
            with self.subTest(data_type=type(data).__name__), self.assertRaisesRegex(
                    v.VerificationFailure, "exchange_json_size_invalid"):
                v.parse_exchange_json(data)
        for data, code in ((b'{"a":1,"a":2}', "exchange_json_duplicate_key"),
                           (b'{"nested":{"x":1,"x":2}}', "exchange_json_duplicate_key"),
                           (b'{"a":1,"\\u0061":2}', "exchange_json_duplicate_key"),
                           (b"NaN", "exchange_json_invalid"), (b"Infinity", "exchange_json_invalid"),
                           (b"1e999", "exchange_json_invalid"), (b"{}{}", "exchange_json_invalid"),
                           (b"{", "exchange_json_invalid"), (b"\xff", "exchange_json_invalid"),
                           # Keep this unclosed. Balanced deep arrays are valid JSON;
                           # decoder recursion limits vary across Python builds.
                           (b"[" * 2000 + b"]" * 1999, "exchange_json_invalid")):
            with self.subTest(data=data[:50]), self.assertRaisesRegex(v.VerificationFailure, code):
                v.parse_exchange_json(data)
        with mock.patch.object(v.json, "loads", side_effect=RecursionError):
            with self.assertRaisesRegex(v.VerificationFailure, "exchange_json_invalid"):
                v.parse_exchange_json(b"{}")

    def test_evidence_reference_hash_is_required(self):
        path = self.root / "summary.json"
        v.private_write(path, b'{"status":"pass"}')
        record = {"path": path.name, **v.file_record(path)}
        self.assertEqual(v.read_evidence_reference(self.root, record), path.read_bytes())
        with self.assertRaisesRegex(v.VerificationFailure, "evidence_reference_mismatch"):
            v.read_evidence_reference(self.root, {**record, "sha256": "0" * 64})
        path.write_bytes(b'{"status":"fail"}')
        with self.assertRaisesRegex(v.VerificationFailure, "evidence_reference_mismatch"):
            v.read_evidence_reference(self.root, record)

    def test_evidence_reference_shape_size_and_path_are_bound(self):
        path = self.root / "artifact.json"
        v.private_write(path, b"{}")
        record = {"path": path.name, **v.file_record(path)}
        for value in ({}, {**record, "extra": True}, {**record, "size": True},
                      {**record, "size": 0}, {**record, "size": v.MAX_LOG + 1},
                      {**record, "sha256": "A" * 64}, {**record, "sha256": "0" * 63}):
            with self.subTest(reference=value), self.assertRaisesRegex(v.VerificationFailure, "evidence_reference_invalid"):
                v.read_evidence_reference(self.root, value)
        for size in (1, 3):
            with self.subTest(size=size), self.assertRaises(v.VerificationFailure):
                v.read_evidence_reference(self.root, {**record, "size": size})
        for relative in ("../artifact.json", str(path), "./artifact.json", "a/../artifact.json", "missing.json"):
            with self.subTest(path=relative), self.assertRaises(v.VerificationFailure):
                v.read_evidence_reference(self.root, {**record, "path": relative})
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(v.VerificationFailure, "owned_path_invalid"):
            v.read_evidence_reference(self.root, {**record, "path": "alias/artifact.json"})
        path.unlink()
        path.symlink_to(self.corpus / "head0.avseal")
        with self.assertRaisesRegex(v.VerificationFailure, "artifact_not_regular"):
            v.read_evidence_reference(self.root, record)

U1_PUBLIC_KEYS = {'controller': 'acdcc8494d458f44a7aaac1d6a84ec624daee88436db2ae26e67ba645a106228', 'writer': 'b7282fe472f97641c17097821a537874aaaa532645ad34dbd5987331a4e73f8d', 'writer-agreement': 'bfda3768f927db529fe9f0f6ee4ba469e432c93bb6fbb8ed5d04e87ed0a45d7b', 'reader-a': '7e698e6c04ff7ce65a05c6e5c1d0338782d223c6390db21ab9c72416c00eef6d', 'reader-b': '50bb406cf2cc8b70ffaf66973d06c7324549d29f77602828dadad475021b107a'}
# Exact pinned public Wycheproof JSON, zlib/base64 encoded for offline Python mocks.
U1_CORPUS_COMPRESSED = (
    'eNrsfVl3VEeT7Xv/Ci2/8mFyzsi7Vj+IWchMQozdvViRmZEgNKJZ3NX//e4osI1tCqOv6tplJGxjqYZz8kRG7tg7h4j/+x9LSz/w'
    '1pvd/Y3Dt9s/LP2fpR9u3bz5ZPmHf+kbB+2tbPPkVen9gF8fy/7GOHv98fUf3x3s7nz84BvZkX0+3N1/JvsHG3hVv2J+LPstfvzA'
    'ztF2lf2HY10ODg/0XRvN5I23wl329ZX/wq94QT+xdCwNFztY2h1Lh2d7snRL7/5scvMl3peljZ1D2enSl8bu/tIhvrGx8+YHfP9/'
    'Pt5sFy/pJf/vx0ve2N3e25eDA+lPNt7s8OHRvvz6Lt6vR2/WcZdJo28sP3j98Pbr5w/X7j+ZNH3yiS4HbX9j7/DnR1t/K5Pbfmro'
    'UtvdOeSNnYMlXjr4+RZLJ28Ff+8v8U5fwqPAdlu8t4RPf3zDLNUzXGPpRH9pR4dLY393e+kQV/7lEj8urb/dOPj8kozf9qRtjI3G'
    'W1tnS58ML/3HXxsrY6BVv7Tz468TU+I3POsSLnm007aE0RR0+67e+2gf72pbeevsYOPgx6WVQzzV0VZfqngGnrxZZQctmTzPuyM8'
    'PFqwe/JZ67bxgnDd2No4PEMXLR3sbuPJ+AAPiafe+PmCbze6wFDbu/jKgRzr448tPvnxh8kD/O/H5/hhZeeYtzb6rZ2227V3/4oO'
    'gzHwdGj65NZL8uneP9sOrx7JgXaK/HKdt9I2D/AuH/7hawcTV4UzLnFrsveNnfTxs3rXg6P29tfWHXzWbZ/1Dn7tS4e7U3rhX9p7'
    'H7vtX9oHE9Nrtxy+1Tt81gVftv7q4fFUwz99sPrg4fMH/5bNN3d2T36186/+/sVG/PmgXX66fvf19ZePlp/MxQWkv/not596/GNP'
    'YOgZtaF6wu4+QOtnt3izv3u0N1vX7u3vVq5bOmo6RrbCwsSlPvtIg2OiMwF4b4B7P49b9N3OxJp6VW3MNnCO0fyNwwPZGr8z6Ne6'
    '8/ryk5UbM3Tm17vylz68/5l3Tm3Lk5U7D5bXn67den1/+aefbi1fX/lpZf3l9Mbd6ghZnxvr48DbufppLGzJv5Y2xtLG9t6WbAti'
    'R0f79/fxJFtnGEtjMuh/fpP1skuDN7YOdGBNRvjEtPu8A8OiH5/orzsKaNt8pp2yt3twsIG76Oe3MfY1Sn3mVAqFEw8Cfp99wgr0'
    '7eHG1tbSJKJuKKo8EVlau31jiYx3/8JvbdKO+KP7MU8g9+dX6McwzbjP4RV3eL/CAeZm23MgZ+8b+jXemnwIpvxx6Xc9M+kYOUUE'
    '0z6Aterv+glm+LUXP42vk/1dOPeW7LzBTQ7e/hKU5N3kMrNYbn1jZ/MhumAgkE212ATmXl9/emdGI006vvEReIg6HE8olxxutAk3'
    '0CaopwAfNn/fyn3gvgb5vxIJJ61VvnH4892/DHHLU0Fta2NTAGnbwjt/Ame/e95nCiXzAipETdwKgL2xw/tn02DqPz7d/Qf96h0F'
    '9INfOekvzTj8uQ2f8dFfW7J3VLc22qr8Btd+8y1l1o9++dS/fv1IO9o/lk88+4T3+4GL0ZbPP7EpZ082Pkw+g/c+e2Nvc/K93EM3'
    'kkey0XMqNbnganSOaxVJFEfnEJwZRD5Ua6j52ll8KjJiKIN/+HTF//3j49z8yM9/8MaxNyaahHFWU8wG/7fGzHzrP97ykXzUIlf1'
    'z/Vbd1YeLD16ev2nlRtLq7deTl787537N3ZPrj9+eXPVPTtZPru1PJ6ah8PdXt+DLzzef7rxPuftt8NtPn5zZeXBT7dWTrI7erCX'
    '7ZOx+5//vTO5yK0HN/943S80597J5u/6dPNj9Prh4eqj3/Tj/vEn//hjB350aYiTHfn89dPJq9Mbf/X3jf9jTx3+LKr+65fL/tpU'
    'fb+tTO5t//X5q213W8Pd5PY//OYdsPE3v7veZ+Pys9f+5zdf2z5484WLYahNXu1h1A63qIOzSzWEbjMlpmbwg21ekmtMvhWJ8Jvk'
    'u5haXSA/aPTUmg2ucM340GjBco2Jh3ED77YWfC2lDgkts5RgRjLDk1Tm0r21LcBJf9sqQNDR1sdnP/7tU/3vv75uRPfXGDHTFDOS'
    'yT77SNIlBuJWbfYyshhfyiDvixtC1sXqmlDOXXLJsRMslzDeqpWckneOjIgnHtytw6cFQ7SWZOvA9y16pmFgki3dOEOp4BK1VbGm'
    'zMuM/q8xYwzAKZ/Dl42ZG7zEuDRcERuYazexsBmuV6qm9UzeBMBdYYJLUujVukGOXc45cDWZi40xWytt8MgDPYC3KnfTEksWX3oQ'
    'GSlrI7xPHFu0UtMoIVVv+ryMGf4aYwZKMTX8M75sTtss95JTw8ATX73tIgbuZxu8qhVHTZwplhESIsFWUdRy0ooZcDeS4vuw1KLx'
    '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'
    'VUeWYLnSQzL8f7OVX+SnP375G042NvE='
)


def u1_failure(identifier="M1"):
    spec = v.U1_DETECTORS[identifier]
    name = spec["test"]
    events = ["◇ Test run started.", "↳ Testing Library Version: 1501", "↳ Target Platform: arm64e-apple-macos14.0",
              f"◇ Test {name}() started.", f"✘ Test {name}() recorded an issue at {spec['location']}: {spec['message']}"]
    if spec["detail"] is not None:
        events.append("↳ " + spec["detail"])
    return "\n".join(events + [f"✘ Test {name}() failed after 0.001 seconds with 1 issue.",
                               "✘ Test run with 1 test in 0 suites failed after 0.001 seconds with 1 issue.", ""])


def negative_failure():
    name = v.READER_TEST
    prefix = ["◇ Test run started.", "↳ Testing Library Version: 1501", "↳ Target Platform: arm64e-apple-macos14.0",
              f"◇ Test {name}() started."]
    prefix += [v.CASE_PREFIX + json.dumps(case) for case in v.expected_cases("A")[:5]]
    return "\n".join(prefix + [f"✘ Test {name}() recorded an issue at MembershipReaderFixtures.swift:372:2: Caught error: badSignature",
                               f"✘ Test {name}() failed after 0.001 seconds with 1 issue.",
                               "↳ /// Separate reader process entry point. AV_MEMBERSHIP_READ_DIR names an exchange directory and",
                               "↳ /// AV_MEMBERSHIP_READER is exactly A or B. Without them this test performs no fixture I/O.",
                               "✘ Test run with 1 test in 0 suites failed after 0.001 seconds with 1 issue.", ""])


def corpus_log(value):
    name = "wycheproofEd25519ExpectedOutcomes"
    return passing([name]).replace(f"✔ Test {name}() passed", v.CORPUS_PREFIX + json.dumps(value) + f"\n✔ Test {name}() passed")


class U1HarnessFixture(Fixture):
    """Synthetic process boundary only. No Swift, signature operation or Docker executes."""
    def __init__(self, root):
        super().__init__(root)
        root = self.root
        for name in v.U1_FILES:
            path = self.package / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes((ROOT / "Packages/VaultCore" / name).read_bytes())
        for name in ("scripts/verify-portable-vault-controls.py", "AGENTS.md", "docs/design/multiplatform/MEMBERSHIP.md"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(("synthetic U1 root input " + name).encode())
        self.bodies = v.fixture_bodies({name: bytes.fromhex(key) for name, key in U1_PUBLIC_KEYS.items()})
        self.raw = zlib.decompress(base64.b64decode(U1_CORPUS_COMPRESSED))
        self.rows = v.extract_corpus(self.raw, (self.package / "Tests/VaultCoreTests/SignatureCorpus.swift").read_text())
        self.fail_build = self.incomplete_build = self.extra_mutant_file = self.bad_restore_run = False
        self.negative_wrong_error = False

    def result(self, directory, platform, role, reader=None):
        manifest = v.exchange_snapshot(self.evidence, directory)
        value = {"schema": "agent-vault-membership-exchange-v1", "role": role, "platform": platform,
                 "pin": {"vault": "6d" * 16, "genesisBody": v.HEADS[0]}, "status": "irrelevant_label",
                 "files": [{"name": n, "size": manifest[n]["size"], "sha256": manifest[n]["sha256"]} for n in v.EXCHANGE_ORDER],
                 "bodies": v.body_records(self.bodies)}
        if role == "producer":
            value["checkpoints"] = [{"sequence": i, "head": h} for i, h in enumerate(v.HEADS)]
        else:
            value.update(reader=reader, cases=v.expected_cases(reader))
        return value

    def run(self, command, **kwargs):
        if command[0] == v.OPENSSL:
            self.calls.append(command)
            if command[-1] == "version":
                return 0, "OpenSSL mock boundary"
            name = Path(command[command.index("-in") + 1]).stem
            index = list(v.ORACLE_KEYS).index(name)
            kind = v.ORACLE_SEEDS[index][0]
            prefix = "302a300506032b6570032100" if kind == "ed25519" else "302a300506032b656e032100"
            encoded = base64.b64encode(bytes.fromhex(prefix + U1_PUBLIC_KEYS[name])).decode()
            return 0, "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n"
        if "swift" not in command or command[command.index("swift") + 1] not in ("build", "test"):
            return super().run(command, **kwargs)
        self.calls.append(command)
        package = Path(command[command.index("--package-path") + 1])
        if str(package) == "/package":
            mounted = next(c for c in reversed(self.calls) if c[:2] == ["docker", "create"])
            mount = next(c for c in mounted if c.startswith("type=bind,src=") and "dst=/package," in c)
            package = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
        mounted = next(c for c in reversed(self.calls) if c[:2] == ["docker", "create"])
        mount = next(c for c in mounted if c.startswith("type=bind,src=") and "dst=/evidence" in c)
        self.evidence = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
        if "build" == command[command.index("swift") + 1]:
            if self.fail_build:
                return 1, "Build complete!\n" + u1_failure()
            if self.incomplete_build:
                return 0, u1_failure()
            corpus = self.evidence / "native-build/checkouts/swift-crypto/Tests/Test Vectors/ed25519_test.json"
            corpus.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            corpus.write_bytes(self.raw)
            return 0, "Building for debugging...\n[3/5] Compiling VaultCore RevisionCodec.swift\nBuild complete! (0.1s)\n"
        platform = "linux" if command[0] == "docker" else "macos"
        selected = command[command.index("--filter") + 1] if "--filter" in command else None
        if selected is None:
            value = {"schema": "agent-vault-wycheproof-ed25519-v1", "platform": platform, "sourceSHA256": v.CORPUS_SHA,
                     "tableSHA256": v.TABLE_SHA, "cases": [{"tcId": r[0], "expected": r[5], "constructed": True,
                                                          "verified": r[5] == "valid"} for r in self.rows]}
            output = passing(list(v.U1_NAMES))
            needle = "✔ Test wycheproofEd25519ExpectedOutcomes() passed"
            output = output.replace(needle, v.CORPUS_PREFIX + json.dumps(value) + "\n" + needle)
            return 0, output
        environment = dict(item.split("=", 1) for item in command if item.startswith("AV_MEMBERSHIP_"))
        if environment:
            path = environment.get("AV_MEMBERSHIP_WRITE_DIR", environment.get("AV_MEMBERSHIP_READ_DIR"))
            directory = Path(path).name
            target = self.evidence / directory
            role = "reader" if "AV_MEMBERSHIP_READER" in environment else "producer"
            if role == "producer":
                target.mkdir(mode=0o700)
                for name in v.EXCHANGE_ORDER:
                    data = self.bodies[name] + bytes([0x17]) * 64 if name in self.bodies else b"synthetic-ciphertext".ljust(674 if name == "head1.avseal" else 120, b"x")
                    v.private_write(target / name, data)
            elif directory.endswith("negative"):
                output = negative_failure()
                if self.negative_wrong_error:
                    output = output.replace("Caught error: badSignature", "Caught error: malformed")
                return 1, output
            reader = environment.get("AV_MEMBERSHIP_READER")
            value = self.result(directory, platform, role, reader)
            lines = [] if role == "producer" else [v.CASE_PREFIX + json.dumps(c) for c in value["cases"]]
            lines += [v.RESULT_PREFIX + json.dumps(value)]
            output = passing([selected]).replace(f"✔ Test {selected}() passed", "\n".join(lines) + f"\n✔ Test {selected}() passed")
            return 0, output
        if selected == v.TARGET:
            mutant = controls.REMOVED not in (package / controls.RELATIVE).read_bytes()
            return (1, n1_failure(v.n1_location(package))) if mutant and platform == "linux" else (0, passing([selected]))
        identifier = next(i for i, spec in v.U1_DETECTORS.items() if spec["test"] == selected)
        spec = v.U1_MUTATIONS[identifier]
        mutant = spec["old"] not in (package / spec["file"]).read_bytes() if identifier != "M10" else spec["new"] in (package / spec["file"]).read_bytes()
        if self.extra_mutant_file and mutant:
            (package / "Sources/VaultCore/Model.swift").write_bytes(b"second-file-defect")
        if mutant:
            return (0, passing([selected]) + v.SENTINELS[0].decode() + "\n") if identifier == "M10" else (1, u1_failure(identifier))
        if self.bad_restore_run:
            return 1, "unrelated runtime failure"
        return 0, passing([selected])


class U1IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def full_baseline(self):
        fixture = U1HarnessFixture(self.root / "fixture")
        with fixture.patched():
            with mock.patch.object(v.sys, "argv", ["verify-membership.py", "--unit", "u1"]):
                v.main()
            result = next((fixture.root / "verification-logs/membership-u1").glob("baseline-*/result.json"))
            report = json.loads(result.read_bytes())
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["cleanup"], {"status": "removed"})
            v.verify_u1_baseline(result, v.u1_snapshot())
        return fixture, result, report

    def test_u1_named_run_completion_is_exact(self):
        good = passing(list(v.U1_NAMES))
        self.assertTrue(v.passed_tests(0, good, list(v.U1_NAMES)))
        for text in (good + good, passing(list(v.U1_NAMES)[:-1]), good.replace("55 tests", "54 tests"),
                     good.replace("passed after", "skipped after", 1), good + "error: signal 6\n",
                     good + "[output capture ended without EOF after owned-group cleanup]\n"):
            self.assertFalse(v.passed_tests(0, text, list(v.U1_NAMES)))

    def test_exchange_failure_is_exact_runtime_case(self):
        good = negative_failure()
        self.assertTrue(v.exchange_failure(1, good))
        defects = [good.replace(" in 0 suites", ""), good.replace("badSignature", "badAuthentication"), good.replace(":372:2:", ":373:2:"),
                   good.replace("main.open.head0", "main.open.head1"), good.replace('"reader": "A"', '"reader": "B"'),
                   good.replace("with 1 issue.", "with 2 issues."), good.replace(v.READER_TEST, "anotherTest"),
                   good.replace("failed after 0.001 seconds with 1 issue.", "failed after 0.001 seconds.", 1),
                   good + v.RESULT_PREFIX + '{}\n', good + "error: signal 6\n", good + good,
                   "compiler warning: Caught error: badSignature", "Caught error: badSignature",
                   good.replace("Caught error: badSignature", "Issue recorded"),
                   good.replace("AV_MEMBERSHIP_CASE_V1", "compiler AV_MEMBERSHIP_CASE_V1", 1)]
        for code, text in [(code, good) for code in (0, 2, -9, None)] + [(1, text) for text in defects]:
            with self.subTest(code=code, text=text[:80]):
                self.assertFalse(v.exchange_failure(code, text))

    def test_control_failure_requires_pinned_assertion_for_every_row(self):
        for identifier, spec in v.U1_DETECTORS.items():
            if identifier == "M10":
                continue
            good = u1_failure(identifier)
            args = (spec["test"], spec["location"], spec["message"], spec["detail"])
            self.assertTrue(v.runtime_failure(1, good, *args))
            for code, output in ((0, good), (None, good), (-9, good), (1, good.replace(spec["location"], "wrong.swift:1:2")),
                                 (1, good.replace(spec["message"], "Caught error: unrelated", 1)),
                                 (1, good + good), (1, good + "error: compiler error\n"), (1, spec["message"])):
                self.assertFalse(v.runtime_failure(code, output, *args))

    def test_exchange_failure_requires_exact_framework_remarks(self):
        good = negative_failure()
        self.assertTrue(v.exchange_failure(1, good))
        first, second = v.READER_FAILURE_REMARKS
        for output in (good.replace(first + "\n", ""), good.replace(second + "\n", ""),
                       good.replace(first, "↳ /// unrelated note"),
                       good.replace(first, first + "\n" + first),
                       good.replace(first + "\n" + second, second + "\n" + first),
                       good + "↳ /// another note\n",
                       good.replace(first + "\n" + second + "\n", "").replace(
                           "◇ Test " + v.READER_TEST + "() started.",
                           "◇ Test " + v.READER_TEST + "() started.\n" + first + "\n" + second)):
            with self.subTest(output=output[-300:]):
                self.assertFalse(v.exchange_failure(1, output))

    def test_u1_build_gate_precedes_test_classification(self):
        state = {"package": v.PACKAGE, "evidence": self.root, "identifier": "a" * 64}
        for code, output in ((1, "Build complete!\n"), (0, u1_failure())):
            run = mock.Mock(return_value=(code, output))
            with self.assertRaises(v.VerificationFailure):
                v.test_package(run, state, "native", "m1-mutant", [v.U1_DETECTORS["M1"]["test"]], mutant=True, unit="u1", control_id="M1")
            self.assertEqual(run.call_count, 1)

    def test_backend_masking_requires_compiled_mutant_source(self):
        state = {"package": v.PACKAGE, "evidence": self.root, "identifier": "a" * 64}
        build = "Building for debugging...\nBuild complete! (0.1s)\n"
        run = mock.Mock(side_effect=[(0, build), (0, passing([v.TARGET]))])
        with self.assertRaisesRegex(v.VerificationFailure, "masked_mutant_compilation_unconfirmed"):
            v.test_package(run, state, "native", "n1-mutant", [v.TARGET], mutant=True, unit="u1")
        self.assertEqual(run.call_count, 1)
        run = mock.Mock(side_effect=[
            (0, "[3/5] Compiling VaultCore RevisionCodec.swift\n" + build),
            (0, passing([v.TARGET])),
        ])
        result = v.test_package(run, state, "native", "n1-mutant", [v.TARGET], mutant=True, unit="u1")
        self.assertEqual(result["status"], "backend_masked")

    def test_u1_snapshot_handles_directory_alias(self):
        canonical = self.root / "canonical"
        canonical.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(canonical, target_is_directory=True)
        fixture = U1HarnessFixture(alias / "fixture")
        with fixture.patched():
            result = v.u1_snapshot()
            self.assertEqual(result["package"]["combined"]["sha256"], v.U1_SOURCE)
            self.assertEqual(v.ROOT, (canonical / "fixture").resolve())

    def test_negative_exchange_is_required_even_when_live_and_replay_agree(self):
        fixture = U1HarnessFixture(self.root / "fixture")
        incomplete = tuple(step for step in v.EXCHANGE_STEPS if step[1] != "negative")
        with fixture.patched(), mock.patch.object(v, "EXCHANGE_STEPS", incomplete):
            with mock.patch.object(v.sys, "argv", ["verify-membership.py", "--unit", "u1"]):
                with self.assertRaisesRegex(v.VerificationFailure, "exchange_direction_incomplete"):
                    v.main()

    def test_reader_role_trace_and_pin_have_independent_oracle(self):
        for role in ("A", "B"):
            cases = v.expected_cases(role)
            self.assertEqual(len(cases), 29)
            self.assertEqual([c["index"] for c in cases], list(range(29)))
            self.assertEqual(cases[5]["id"], "main.open.head1")
            self.assertEqual([cases[i]["outcome"] for i in (1, 5, 10, 15)],
                             ["opened"] * 4 if role == "A" else ["unauthorizedRecipient", "opened", "badAuthentication", "unauthorizedRecipient"])
            for index in range(29):
                changed = json.loads(json.dumps(cases))
                changed[index]["outcome"] = "reported_success"
                with self.assertRaisesRegex(v.VerificationFailure, "reader_case_oracle_mismatch"):
                    v.validate_cases(changed, role)
        for role in ("a", "C", "", None):
            with self.assertRaises(v.VerificationFailure):
                v.expected_cases(role)
        keys = {n: bytes.fromhex(k) for n, k in U1_PUBLIC_KEYS.items()}
        bodies = v.fixture_bodies(keys)
        self.assertEqual(v.sha(bodies["genesis.avm"]), "a7b6578a9dc51eb7b3b2966b55c79db0daa6ced89851cd2a4d8714c797c16eaf")
        keys["reader-b"] = bytes(32)
        with self.assertRaisesRegex(v.VerificationFailure, "independent_body_pin_mismatch"):
            v.fixture_bodies(keys)

    def test_fixture_launcher_only_paths_roles_and_closed_test_selection(self):
        state = {"package": v.PACKAGE, "evidence": self.root, "identifier": "a" * 64}
        for platform in ("native", "linux"):
            for role in (None, "A", "B"):
                command = v.selected_fixture_command(state, platform, "native-corpus", role)
                variables = [c for c in command if c.startswith("AV_")]
                self.assertEqual(len(variables), 1 if role is None else 2)
                self.assertTrue(all(c.startswith(("AV_MEMBERSHIP_WRITE_DIR=", "AV_MEMBERSHIP_READ_DIR=", "AV_MEMBERSHIP_READER=")) for c in variables))
        for directory, role in (("../escape", "A"), ("native-corpus", "C"), ("native-corpus;echo bad", "A")):
            with self.assertRaises(v.VerificationFailure):
                v.selected_fixture_command(state, "native", directory, role)
        for key in ("AV_TEST_BYPASS", "AV_TEST", "AV_MEMBERSHIP_READER", "AV_MEMBERSHIP_UNKNOWN"):
            with mock.patch.dict(os.environ, {key: "A"}, clear=True), self.assertRaises(v.VerificationFailure):
                v.clean_env_required()

    def test_custody_rejects_foreign_helpers_initializers_and_extensions(self):
        fixture = U1HarnessFixture(self.root)
        reader = fixture.package / v.READER_SOURCE
        original = reader.read_text()
        v.reader_custody(fixture.package)
        for addition in ("\nfunc hostile() { _ = Fixture() }\n", "\nfunc hostile() { _ = membershipAgreementKey(0xD1) }\n",
                         "\nfunc hostile() { _ = Curve25519.Signing.PrivateKey() }\n"):
            reader.write_text(original + addition)
            with self.assertRaises(v.VerificationFailure):
                v.reader_custody(fixture.package)
        reader.write_text(original)
        source = fixture.package / "Sources/VaultCore/MembershipTypes.swift"
        old = source.read_text()
        for addition in ("\nextension Data { func shadow() {} }\n", "\nextension SealedRecord {}\n"):
            source.write_text(old + addition)
            with self.assertRaisesRegex(v.VerificationFailure, "prohibited_extension"):
                v.reader_custody(fixture.package)
        source.write_text(old)
        reader.write_text(original + "\nlet globalKey = Curve25519.KeyAgreement.PrivateKey()\n")
        with self.assertRaisesRegex(v.VerificationFailure, "global_key_initializer"):
            v.reader_custody(fixture.package)

    def test_signature_primary_table_compares_every_field(self):
        fixture = U1HarnessFixture(self.root)
        source = (fixture.package / "Tests/VaultCoreTests/SignatureCorpus.swift").read_text()
        rows = v.extract_corpus(fixture.raw, source)
        self.assertEqual(len(rows), 150)
        for field in range(7):
            old = "|".join(map(str, rows[0]))
            fields = list(map(str, rows[0]))
            fields[field] = "different"
            with self.assertRaisesRegex(v.VerificationFailure, "corpus_embedded_field_mismatch"):
                v.extract_corpus(fixture.raw, source.replace(old, "|".join(fields), 1))
        with self.assertRaisesRegex(v.VerificationFailure, "corpus_source_hash_mismatch"):
            v.extract_corpus(fixture.raw + b" ", source)

    def test_signature_case_binding_and_outcomes(self):
        fixture = U1HarnessFixture(self.root)
        rows = fixture.rows
        valid = {"schema": "agent-vault-wycheproof-ed25519-v1", "platform": "macos", "sourceSHA256": v.CORPUS_SHA,
                 "tableSHA256": v.TABLE_SHA, "cases": [{"tcId": r[0], "expected": r[5], "constructed": True, "verified": r[5] == "valid"} for r in rows]}
        self.assertEqual(v.signature_result(corpus_log(valid), "macos", rows), valid)
        for field, replacement in (("tcId", 151), ("expected", "invalid"), ("constructed", False), ("verified", False),
                                   ("constructed", 1), ("verified", 1)):
            value = json.loads(json.dumps(valid)); value["cases"][0][field] = replacement
            with self.assertRaises(v.VerificationFailure):
                v.signature_result(corpus_log(value), "macos", rows)
        for change in (lambda x: x["cases"].pop(), lambda x: x["cases"].append(x["cases"][0]),
                       lambda x: x.update(platform="linux"), lambda x: x.update(tableSHA256="f" * 64),
                       lambda x: next(c for c in x["cases"] if c["expected"] == "invalid").update(verified=True)):
            value = json.loads(json.dumps(valid)); change(value)
            with self.assertRaises(v.VerificationFailure):
                v.signature_result(corpus_log(value), "macos", rows)

    def test_u1_baseline_reopens_full_execution_and_summary(self):
        fixture, result, report = self.full_baseline()
        with fixture.patched():
            expected = v.u1_snapshot()
            for mutate in (lambda x: x["runtime"].update(linux_architecture="x86_64"),
                           lambda x: x["steps"][0]["command"].append("--invented"),
                           lambda x: x["steps"][0].update(secret_output_scanned=False),
                           lambda x: x["steps"][0].update(secret_output_detected=0),
                           lambda x: x["cleanup"].update(status=None),
                           lambda x: x["custody"].pop("native-read-a"),
                           lambda x: x["snapshot"]["inputs"].pop("scripts/verify-membership.py"),
                           lambda x: x["artifacts"].pop("corpus-primary.json")):
                altered = json.loads(json.dumps(report)); mutate(altered)
                result.write_text(json.dumps(altered))
                with self.assertRaises((v.VerificationFailure, KeyError)):
                    v.verify_u1_baseline(result, expected)
            result.write_text(json.dumps(report))
            summary_path = result.parent / "exchange-summary.json"
            summary_bytes = summary_path.read_bytes()
            summary = json.loads(summary_bytes)
            for mutate in (lambda x: x.update(schema="unknown"), lambda x: x["directions"].pop(),
                           lambda x: x["directions"][0]["readers"].pop("B"), lambda x: x.update(extra="dump")):
                altered = json.loads(json.dumps(summary)); mutate(altered)
                summary_path.write_bytes(v.compact(altered))
                changed = json.loads(json.dumps(report))
                changed["artifacts"]["exchange-summary.json"] = v.evidence_ref(result.parent, "exchange-summary.json")
                changed["summary"] = changed["artifacts"]["exchange-summary.json"]
                result.write_text(json.dumps(changed))
                with self.assertRaises(v.VerificationFailure):
                    v.verify_u1_baseline(result, expected)
            summary_path.write_bytes(summary_bytes)
            result.write_text(json.dumps(report))
            v.verify_u1_baseline(result, expected)

    def test_u1_current_harness_root_and_package_epoch_are_bound(self):
        fixture, result, report = self.full_baseline()
        with fixture.patched():
            for name in ("scripts/verify-membership.py", "scripts/verify-membership-controls.py", "scripts/membership_spec.py", "deploy/tests/test_membership_verifier.py",
                         "scripts/verify-portable-vault.py", "scripts/verify-webhost-link-mutations.py", "Package.resolved"):
                path = fixture.root / name; old = path.read_bytes(); path.write_bytes(old + b" changed")
                with self.assertRaisesRegex(v.VerificationFailure, "matching_passed_u1_baseline_required"):
                    v.verify_u1_baseline(result, v.u1_snapshot())
                path.write_bytes(old)
            path = fixture.package / "Sources/VaultCore/MembershipTypes.swift"
            path.write_bytes(path.read_bytes() + b" changed")
            with self.assertRaises(v.VerificationFailure):
                v.u1_snapshot()

    def test_u1_summary_overflow_fails_without_truncation(self):
        state = {"evidence": self.root}
        artifacts = {n: {"path": n, "size": 1, "sha256": "a" * 64} for n in
                     ("oracle-public.json", "corpus-primary.json", "corpus-native.json", "corpus-linux.json", "corpus-table.txt", "cofactor-matrix.json")}
        report = {"snapshot": {}, "artifacts": artifacts}
        with self.assertRaisesRegex(v.VerificationFailure, "exchange_summary_overflow"):
            v.write_summary(state, report, ["x" * 65536])
        self.assertFalse((self.root / "exchange-summary.json").exists())

    def test_u1_complete_control_matrix_and_separate_n1(self):
        fixture, baseline, _ = self.full_baseline()
        with fixture.patched(), mock.patch.object(v.sys, "argv", ["verify-membership-controls.py", "--unit", "u1", str(baseline)]):
            controls.main()
        result = next((fixture.root / "verification-logs/membership-u1").glob("controls-*/result.json"))
        report = json.loads(result.read_bytes())
        self.assertEqual(report["status"], "pass")
        self.assertEqual(len(report["controls"]), 20)
        self.assertTrue(all(row["status"] == "detected" for row in report["controls"]))
        self.assertEqual([row["status"] for row in report["n1"]], ["backend_masked", "detected"])
        self.assertEqual(report["owned_copy_initial"], report["owned_copy_final"])
        self.assertTrue(all(row["restored"]["status"] == "pass" for row in report["controls"]))
        self.assertEqual([row["mutant"]["scanner_error"]["code"] for row in report["controls"] if row["id"] == "M10"],
                         ["synthetic_secret_output"] * 2)
        with fixture.patched():
            state = {"evidence": result.parent, "package": result.parent / "owned-package"}
            v.validate_u1_controls(report, state)
            report["controls"].pop()
            with self.assertRaisesRegex(v.VerificationFailure, "u1_control_matrix_incomplete"):
                v.validate_u1_controls(report, state)

    def test_u1_lifecycle_restores_copy_and_reports_second_file_change(self):
        fixture, baseline, _ = self.full_baseline()
        fixture.extra_mutant_file = True
        with fixture.patched(), mock.patch.object(v.sys, "argv", ["controls", "--unit", "u1", str(baseline)]):
            with self.assertRaises(v.VerificationFailure):
                controls.main()
        result = next((fixture.root / "verification-logs/membership-u1").glob("controls-*/result.json"))
        report = json.loads(result.read_bytes())
        self.assertEqual(report["status"], "fail")
        self.assertIsNotNone(report["controls"][0]["restored_test_error"])
        self.assertIsNotNone(report["copy_check_error"])
        self.assertEqual(report["cleanup"], {"status": "removed"})
        self.assertTrue(any(row["status"] == "unexecuted" for row in report["controls"]))

    def test_u1_secondary_errors_preserve_primary(self):
        report = {"steps": [], "artifacts": {}, "kind": "baseline"}
        state = {"evidence": self.root, "container_attempted": True, "name": "owned", "owner": "a" * 32}
        primary = v.VerificationFailure("primary_build_failure")
        with mock.patch.object(v, "cleanup_container", side_effect=v.VerificationFailure("cleanup_failure")), \
             mock.patch.object(v, "u1_snapshot", side_effect=v.VerificationFailure("source_failure")):
            outcome = v.finish(report, state, mock.Mock(), {}, primary, unit="u1")
        self.assertIs(outcome, primary)
        self.assertEqual(report["failure"]["code"], "primary_build_failure")
        self.assertEqual(report["cleanup"]["error"]["code"], "cleanup_failure")
        self.assertEqual(report["source_check_error"]["code"], "source_failure")
        self.assertEqual(report["status"], "fail")

    def test_exchange_primary_survives_changed_artifact(self):
        report = {"custody": {}, "exchange_errors": {}}
        state = {"evidence": self.root}
        first = v.VerificationFailure("primary_runtime_failure")
        with mock.patch.object(v, "fixture_custody", side_effect=[None, v.VerificationFailure("exchange_changed")]), \
             mock.patch.object(v, "run_fixture", side_effect=first):
            with self.assertRaisesRegex(v.VerificationFailure, "primary_runtime_failure"):
                v.checked_reader(mock.Mock(), state, report, "native", "read", "linux-corpus", "A", {}, {})
        self.assertEqual(report["exchange_errors"]["read"]["failure"]["code"], "primary_runtime_failure")
        self.assertEqual(report["exchange_errors"]["read"]["artifact_check_error"]["code"], "exchange_changed")

    def test_machine_records_require_the_named_runtime_interval(self):
        fixture = U1HarnessFixture(self.root)
        value = {"schema": "agent-vault-wycheproof-ed25519-v1", "platform": "macos", "sourceSHA256": v.CORPUS_SHA,
                 "tableSHA256": v.TABLE_SHA, "cases": [{"tcId": r[0], "expected": r[5], "constructed": True,
                                                        "verified": r[5] == "valid"} for r in fixture.rows]}
        line = v.CORPUS_PREFIX + json.dumps(value)
        for output in (line, passing(["unrelated"]) + line, passing(["wycheproofEd25519ExpectedOutcomes"]) + line,
                       corpus_log(value) + "AV_UNREVIEWED_V1 {}\n"):
            with self.assertRaisesRegex(v.VerificationFailure, "trace_(named_interval_missing|interval_invalid)"):
                v.signature_result(output, "macos", fixture.rows)

    def test_each_u1_secondary_failure_alone_fails_the_run(self):
        for kind in ("cleanup", "artifact", "source", "validation"):
            with self.subTest(kind=kind):
                root = self.root / kind; root.mkdir(mode=0o700)
                v.private_write(root / "artifact", b"before")
                reference = v.evidence_ref(root, "artifact")
                report = {"steps": [], "artifacts": {"artifact": reference}, "kind": "baseline"}
                state = {"evidence": root, "container_attempted": kind == "cleanup", "name": "owned", "owner": "a" * 32}
                if kind == "artifact":
                    (root / "artifact").write_bytes(b"after!")
                with mock.patch.object(v, "cleanup_container", side_effect=v.VerificationFailure("cleanup_failure")), \
                     mock.patch.object(v, "u1_snapshot", side_effect=v.VerificationFailure("source_failure") if kind == "source" else None,
                                       return_value={}), \
                     mock.patch.object(v, "validate_u1_before_write", side_effect=v.VerificationFailure("validation_failure") if kind == "validation" else None):
                    error = v.finish(report, state, mock.Mock(), {}, None, unit="u1")
                self.assertIsInstance(error, v.VerificationFailure)
                self.assertEqual(report["status"], "fail")
                self.assertIsNone(report["failure"])
                field = {"artifact": "artifact_check_error", "source": "source_check_error", "validation": "validation_error"}.get(kind)
                self.assertIsNotNone(report["cleanup"].get("error") if kind == "cleanup" else report[field])

    def test_u1_scan_fields_and_artifact_rehash_fail_closed(self):
        fixture, result, original = self.full_baseline()
        with fixture.patched():
            expected = v.u1_snapshot()
            inspect = next(i for i, s in enumerate(original["steps"]) if s["step"] == "container_inspect")
            for index, field, value in ((0, "secret_output_scanned", None), (0, "secret_output_scanned", 1),
                                        (0, "secret_output_detected", False), (inspect, "secret_output_scanned", True)):
                report = json.loads(json.dumps(original))
                if index == 0 and field == "secret_output_detected":
                    del report["steps"][index][field]
                else:
                    report["steps"][index][field] = value
                result.write_text(json.dumps(report))
                with self.assertRaises(v.VerificationFailure):
                    v.verify_u1_baseline(result, expected)
            result.write_text(json.dumps(original))
            for name in ("native-baseline-test.log", "oracle-public.json", "corpus-primary.json", "native-corpus/head1.avseal"):
                path = result.parent / name; old = path.read_bytes(); path.write_bytes(old[:-1] + bytes([old[-1] ^ 1]))
                with self.assertRaises(v.VerificationFailure):
                    v.verify_u1_baseline(result, expected)
                path.write_bytes(old)

    def test_u1_timeout_restores_and_rebuilds_passing_target(self):
        fixture = U1HarnessFixture(self.root)
        with fixture.patched():
            state, report, run = v.recording("controls", unit="u1")
            state["package"] = controls.copy_package(state["evidence"])
            v.runtime_and_container(run, state)
            path, original, changed, _ = controls.mutation_bytes(state["package"], state["evidence"], "M1")
            real = fixture.run
            def timeout(command, **kwargs):
                if "test" in command and changed == path.read_bytes():
                    raise TimeoutError("external text must stay out")
                return real(command, **kwargs)
            with mock.patch.object(v.owned, "run_owned", side_effect=timeout):
                row, error = controls.platform_control(run, state, "native", path, original, changed, control_id="M1", unit="u1")
            self.assertIsInstance(error, TimeoutError)
            self.assertEqual(row["failure"], {"type": "TimeoutError"})
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(row["restored"]["status"], "pass")
            self.assertIsNone(row["restore_error"])
            self.assertIsNone(row["restored_test_error"])
            self.assertEqual(sum("build" in command and "swift" in command for command in fixture.calls), 3)
            self.assertEqual(sum("test" in command and "swift" in command for command in fixture.calls), 2)

    def test_frozen_membership_scanner_values_are_covered(self):
        values = [b"AV_MEMBERSHIP_U1_SYNTHETIC_CANARY_5E3B91A4", b"synthetic-member"]
        values += [bytes([n]) * 32 for n in (0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xD1, 0xD2, 0xD5, 0xD6, *range(0xE0, 0x100))]
        for value in values:
            for form in (value, value.hex().encode(), value.hex().upper().encode(), base64.b64encode(value), base64.urlsafe_b64encode(value)):
                self.assertTrue(v.portable.rejects_secret_output(form.decode("utf-8", "replace"), v.SENTINELS))

    def test_reader_rehash_rejects_changed_owned_corpus(self):
        fixture = U1HarnessFixture(self.root / "fixture")
        evidence = self.root / "evidence"; evidence.mkdir(mode=0o700)
        directory = evidence / "linux-corpus"; directory.mkdir(mode=0o700)
        for name in v.EXCHANGE_ORDER:
            data = fixture.bodies[name] + bytes([0x17]) * 64 if name in fixture.bodies else b"synthetic-ciphertext"
            v.private_write(directory / name, data)
        fixture.evidence = evidence
        initial = v.exchange_snapshot(evidence, "linux-corpus")
        value = fixture.result("linux-corpus", "macos", "reader", "A")
        text = "\n".join([v.CASE_PREFIX + json.dumps(c) for c in value["cases"]] + [v.RESULT_PREFIX + json.dumps(value)])
        output = passing([v.READER_TEST]).replace(f"✔ Test {v.READER_TEST}() passed", text + f"\n✔ Test {v.READER_TEST}() passed")
        def change(command, **kwargs):
            (directory / "head0.avseal").write_bytes(b"changed-ciphertext")
            return 0, output
        report = {"steps": [], "custody": {}, "exchange_errors": {}}
        state = {"evidence": evidence, "package": fixture.package, "identifier": "a" * 64}
        with mock.patch.object(v.owned, "run_owned", side_effect=change):
            with self.assertRaisesRegex(v.VerificationFailure, "exchange_changed"):
                v.checked_reader(v.make_run(evidence, report["steps"]), state, report, "native", "reader", "linux-corpus", "A", initial, fixture.bodies)
        self.assertIsNone(report["exchange_errors"]["reader"]["failure"])
        self.assertEqual(report["exchange_errors"]["reader"]["artifact_check_error"]["code"], "exchange_changed")


if __name__ == "__main__":
    unittest.main()
