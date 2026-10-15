"""Verify fixture cleanup waits for unload and preserves diagnostics on failure."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_xpc", ROOT / "scripts/verify-xpc.py")
xpc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(xpc)


class FixtureCleanupTests(unittest.TestCase):
    def setUp(self):
        self.harness = xpc.Harness()
        self.addCleanup(lambda: shutil.rmtree(self.harness.work, ignore_errors=True))
        self.label = "dev.agentvault.ipcproof.cleanup-test"
        self.harness.labels = [self.label]

    def test_waits_for_its_job_to_disappear_before_removing_files(self):
        results = [subprocess.CompletedProcess([], code) for code in (0, 0, 0, 113)]
        with mock.patch.object(xpc.subprocess, "run", side_effect=results) as run, \
                mock.patch.object(xpc.time, "sleep"):
            self.harness.cleanup()
        self.assertEqual(run.call_args_list[0].args[0], ["launchctl", "bootout", f"{xpc.DOMAIN}/{self.label}"])
        for call in run.call_args_list[1:]:
            self.assertEqual(call.args[0], ["launchctl", "print", f"{xpc.DOMAIN}/{self.label}"])
        self.assertEqual(self.harness.cleanup_record, {self.label: "removed", "work_dir_removed": True})
        self.assertEqual(self.harness.labels, [])

    def test_retains_loaded_job_files_and_reports_cleanup_failure(self):
        with mock.patch.object(xpc.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                mock.patch.object(xpc.time, "monotonic", side_effect=[0, 4]):
            self.harness.cleanup()
        self.assertTrue(self.harness.work.is_dir())
        self.assertEqual(self.harness.labels, [self.label])
        self.assertEqual(self.harness.cleanup_record, {self.label: "STILL LOADED", "work_dir_removed": False})


if __name__ == "__main__":
    unittest.main()
