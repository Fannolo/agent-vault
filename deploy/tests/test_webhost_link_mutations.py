"""Verify the web host link mutation harness ends only the processes it started.

Real child processes are used: an owned shell with a backgrounded descendant, and an
independent sentinel in its own session that the harness must never touch. `os.killpg`
is wrapped to record every group the harness signals.
"""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verify_webhost_link_mutations",
                                              ROOT / "scripts/verify-webhost-link-mutations.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


def gone(pid, within=3.0):
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


class OwnedProcessTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="webhost-mutations-test-"))
        self.addCleanup(shutil.rmtree, self.work, True)
        # Independent of the harness: its own session and group, same program as the owned descendant.
        self.sentinel = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
        self.addCleanup(self.stop_sentinel)
        self.signalled = []
        real = os.killpg

        def recording(pgid, sig):
            self.signalled.append((pgid, sig))
            return real(pgid, sig)
        patcher = mock.patch.object(harness.os, "killpg", side_effect=recording)
        patcher.start()
        self.addCleanup(patcher.stop)

    def stop_sentinel(self):
        # Ended through its own handle only.
        if self.sentinel.poll() is None:
            self.sentinel.kill()
        self.sentinel.wait()

    def owned_command(self, script):
        return ["/bin/sh", "-c", script.replace("WORK", str(self.work))]

    def pids(self, name):
        return int((self.work / name).read_text().strip())

    def test_timeout_ends_owned_child_and_descendant_and_spares_an_independent_process(self):
        code, _ = harness.run_owned(self.owned_command(
            "echo $$ > WORK/leader; /bin/sleep 60 & echo $! > WORK/descendant; wait"), timeout=0.5)
        self.assertIsNone(code)
        leader, descendant = self.pids("leader"), self.pids("descendant")
        self.assertTrue(gone(leader) and gone(descendant), "owned leader and descendant must end")
        self.assertIsNone(self.sentinel.poll(), "an independent process must survive the timeout")
        self.assertEqual({pgid for pgid, _ in self.signalled}, {leader}, "only the owned group is signalled")
        self.assertNotIn(self.sentinel.pid, {pgid for pgid, _ in self.signalled})

    def test_descendant_left_after_a_normal_exit_is_ended(self):
        code, _ = harness.run_owned(self.owned_command(
            "echo $$ > WORK/leader; /bin/sleep 60 & echo $! > WORK/descendant; exit 3"), timeout=10)
        self.assertEqual(code, 3)
        self.assertTrue(gone(self.pids("descendant")))
        self.assertIsNone(self.sentinel.poll())
        self.assertEqual({pgid for pgid, _ in self.signalled}, {self.pids("leader")})

    def test_clean_exit_signals_nothing(self):
        code, output = harness.run_owned(["/bin/echo", "synthetic"], timeout=10)
        self.assertEqual((code, output), (0, "synthetic\n"))
        self.assertEqual([sig for _, sig in self.signalled if sig != 0], [])
        self.assertIsNone(self.sentinel.poll())

    def test_refuses_groups_it_does_not_own(self):
        for pgid in (0, 1, os.getpgrp()):
            with self.assertRaises(ValueError):
                harness.terminate_group(pgid)
        self.assertEqual(self.signalled, [])

    def test_harness_never_finds_processes_by_name(self):
        source = (ROOT / "scripts/verify-webhost-link-mutations.py").read_text()
        for forbidden in ("pkill", "killall", "pgrep", "psutil", '"ps"'):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
