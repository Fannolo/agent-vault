"""Verify fixture cleanup waits for unload and preserves diagnostics on failure.

launchctl, the clock and the mutated harness runs are mocked; no job is bootstrapped.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


xpc = load("verify_xpc", "scripts/verify-xpc.py")
mutations = load("verify_xpc_mutations", "scripts/verify-xpc-mutations.py")


def launchctl(*codes, stderr=""):
    return [subprocess.CompletedProcess([], code, "", stderr) for code in codes]


class FixtureCleanupTests(unittest.TestCase):
    def setUp(self):
        self.harness = xpc.Harness()
        self.addCleanup(lambda: shutil.rmtree(self.harness.work, ignore_errors=True))
        self.label = "dev.agentvault.ipcproof.cleanup-test"
        self.harness.labels = [self.label]
        (self.harness.work / "fixture.stderr").write_text("diagnostic")

    def cleanup(self, results, clock):
        with mock.patch.object(xpc.subprocess, "run", side_effect=results) as run, \
                mock.patch.object(xpc.time, "monotonic", side_effect=clock), \
                mock.patch.object(xpc.time, "sleep"):
            self.harness.cleanup()
        return run

    def test_waits_for_its_job_to_disappear_before_removing_files(self):
        run = self.cleanup(launchctl(0, 0, 0, 113), [10, 10.1, 10.2, 10.35])
        self.assertEqual(run.call_args_list[0].args[0], ["launchctl", "bootout", f"{xpc.DOMAIN}/{self.label}"])
        for call in run.call_args_list[1:]:
            self.assertEqual(call.args[0], ["launchctl", "print", f"{xpc.DOMAIN}/{self.label}"])
        self.assertEqual(self.harness.cleanup_record, {
            "labels": {self.label: {"status": "removed", "bootoutExitCode": 0, "bootoutStderr": "",
                                    "printExitCode": 113, "polls": 3, "seconds": 0.35}},
            "workDirRemoved": True, "workDirErrors": [], "clean": True})
        self.assertFalse(self.harness.work.exists())
        self.assertEqual(self.harness.labels, [])

    def test_retains_loaded_job_files_and_reports_cleanup_failure(self):
        self.cleanup(launchctl(5, 0, 0), [0, 1, 4])
        self.assertTrue((self.harness.work / "fixture.stderr").exists())
        self.assertEqual(self.harness.labels, [self.label])
        record = self.harness.cleanup_record
        self.assertEqual(record["labels"][self.label]["status"], "STILL LOADED")
        self.assertEqual(record["labels"][self.label]["bootoutExitCode"], 5)
        self.assertEqual(record["labels"][self.label]["seconds"], 4)
        self.assertEqual(record["retainedWorkDir"], str(self.harness.work))
        self.assertFalse(record["clean"])

    def test_a_failing_probe_is_not_taken_as_unloaded(self):
        self.cleanup(launchctl(0, 5, 5, stderr="probe error"), [0, 1, 3])
        self.assertTrue(self.harness.work.exists())
        self.assertEqual(self.harness.cleanup_record["labels"][self.label]["status"], "UNCONFIRMED")
        self.assertEqual(self.harness.cleanup_record["labels"][self.label]["printExitCode"], 5)
        self.assertEqual(self.harness.cleanup_record["labels"][self.label]["polls"], 2)
        self.assertFalse(self.harness.cleanup_record["clean"])

    def test_bootout_errors_and_removal_errors_are_reported(self):
        self.harness.work.chmod(0o500)
        self.addCleanup(self.harness.work.chmod, 0o700)
        self.cleanup(launchctl(3, 113, stderr="Boot-out failed: 3: No such process"), [0, 0.01])
        record = self.harness.cleanup_record
        self.assertEqual(record["labels"][self.label]["bootoutStderr"], "Boot-out failed: 3: No such process")
        self.assertTrue(record["workDirErrors"])
        self.assertTrue(any("fixture.stderr" in error for error in record["workDirErrors"]))
        self.assertFalse(record["workDirRemoved"])
        self.assertFalse(record["clean"])

    def test_a_repeated_cleanup_keeps_earlier_label_details(self):
        self.cleanup(launchctl(0, 113), [0, 0.2])
        self.cleanup([], [])
        self.assertEqual(self.harness.cleanup_record["labels"][self.label]["status"], "removed")
        self.assertTrue(self.harness.cleanup_record["clean"])


class MutationAssessmentTests(unittest.TestCase):
    CLEAN = {"labels": {}, "workDirRemoved": True, "workDirErrors": [], "clean": True}

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="av-xpc-assess-")
        self.addCleanup(directory.cleanup)
        self.evidence = Path(directory.name) / "evidence.json"

    def assess(self, expected, code, failed=(), cleanup=None, raw=None):
        results = [{"scenario": name, "passed": False} for name in failed] + [{"scenario": "other", "passed": True}]
        self.evidence.write_text(raw if raw is not None else
                                 json.dumps({"results": results, "cleanup": cleanup or self.CLEAN}))
        return mutations.assess("m", set(expected), code, self.evidence, "harness output")

    def test_expected_failures_need_a_failing_harness_exit(self):
        self.assertTrue(self.assess({"a"}, 1, {"a"})["ok"])
        self.assertFalse(self.assess({"a"}, 0, {"a"})["ok"])
        self.assertTrue(self.assess(set(), 0)["ok"])
        self.assertFalse(self.assess(set(), 1)["ok"])

    def test_exact_scenarios_and_confirmed_cleanup_are_required(self):
        self.assertFalse(self.assess({"a"}, 1, {"a", "b"})["ok"])
        unclean = {**self.CLEAN, "clean": False, "labels": {"x": {"status": "STILL LOADED"}}}
        report = self.assess({"a"}, 1, {"a"}, unclean)
        self.assertFalse(report["ok"])
        self.assertEqual(report["cleanup"], unclean)
        self.assertEqual(report["diagnostics"], "harness output")

    def test_missing_or_malformed_evidence_is_a_failure(self):
        self.assertFalse(self.assess({"a"}, 1, raw="{")["ok"])
        self.assertFalse(self.assess({"a"}, 1, raw='{"results": []}')["ok"])
        self.evidence.unlink()
        report = mutations.assess("m", {"a"}, 1, self.evidence, "out")
        self.assertFalse(report["ok"])
        self.assertIn("FileNotFoundError", report["failed"][0])

    def test_completed_results_are_written_when_a_later_run_raises(self):
        target = Path(self.evidence.parent) / "report.json"
        calls = []

        def fake_run(argv, **kwargs):
            if calls:
                raise OSError("harness could not start")
            calls.append(argv)
            Path(argv[-1]).write_text(json.dumps({"results": [], "cleanup": self.CLEAN}))
            return subprocess.CompletedProcess(argv, 0, "", "")

        def fake_copytree(source, tree, **kwargs):
            for _, relative, *_ in mutations.MUTATIONS:
                (tree / relative).parent.mkdir(parents=True, exist_ok=True)
                (tree / relative).write_text("x")

        with mock.patch.object(mutations, "MUTATIONS", [("one", "a.swift", "x", "y", set()),
                                                        ("two", "a.swift", "x", "y", set())]), \
                mock.patch.object(mutations.shutil, "copytree", side_effect=fake_copytree), \
                mock.patch.object(mutations.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(mutations.sys, "argv", ["verify-xpc-mutations", "--evidence", str(target)]), \
                mock.patch("builtins.print"), self.assertRaises(OSError):
            mutations.main()
        self.assertEqual([r["mutation"] for r in json.loads(target.read_text())], ["one"])


if __name__ == "__main__":
    unittest.main()
