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
                return 0, "Building for debugging...\nBuild complete! (0.10s)\n"
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
        parent = ROOT / "verification-logs/membership-u0-worker"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent.chmod(0o700)
        self.temporary = tempfile.TemporaryDirectory(prefix="python-fixture-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name))

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
        parent = ROOT / "verification-logs/membership-u0-worker"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            path = Path(temporary) / "artifact"
            v.private_write(path, b"synthetic original")
            binding = v.file_record(path)
            path.write_bytes(b"synthetic changed!")
            with self.assertRaisesRegex(v.VerificationFailure, "artifact_hash_mismatch"):
                v.verify_file(path, binding)


if __name__ == "__main__":
    unittest.main()
