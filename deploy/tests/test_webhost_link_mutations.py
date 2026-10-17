"""Verify the web host link mutation harness ends only the processes it started.

Real child processes are used: an owned shell with a backgrounded descendant, and an
independent sentinel in its own session that the harness must never touch. `os.killpg`
is wrapped to record every group the harness signals.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
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

    def test_interrupted_wait_cleans_the_owned_group_before_returning(self):
        children = []
        spawn = subprocess.Popen

        def record(*args, **kwargs):
            child = spawn(*args, **kwargs)
            children.append(child)
            return child

        def interrupt(pid, timeout):
            deadline = time.monotonic() + 5
            while not (self.work / "descendant").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            raise KeyboardInterrupt

        try:
            with mock.patch.object(harness.subprocess, "Popen", side_effect=record), \
                    mock.patch.object(harness, "wait_for_exit_without_reaping", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    harness.run_owned(self.owned_command(
                        "echo $$ > WORK/leader; /bin/sleep 60 & echo $! > WORK/descendant; wait"), timeout=10)
            self.assertTrue(gone(self.pids("leader")) and gone(self.pids("descendant")))
            self.assertIsNone(self.sentinel.poll())
        finally:
            # Also cleans the intentionally broken implementation when this regression fails.
            for child in children:
                if child.returncode is None:
                    harness.terminate_group(child.pid)
                    child.wait()
                    child.stdout.close()

    def test_escaped_pipe_holder_cannot_block_output_cleanup(self):
        script = ("import pathlib,subprocess,sys; "
                  "child=subprocess.Popen(['/bin/sleep','5'],start_new_session=True); "
                  "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); print('synthetic',flush=True)")
        started = time.monotonic()
        code, output = harness.run_owned([sys.executable, "-I", "-c", script, str(self.work / "escaped")], 10)
        elapsed = time.monotonic() - started
        escaped = self.pids("escaped")
        # It exits naturally; neither the harness nor this test signals its escaped group.
        self.assertTrue(gone(escaped, within=6))
        self.assertLess(elapsed, 3, "an inherited output pipe cannot extend cleanup to the holder's lifetime")
        self.assertEqual(code, 0)
        self.assertIn("synthetic", output)
        self.assertNotIn(escaped, {pgid for pgid, _ in self.signalled})
        self.assertIsNone(self.sentinel.poll())

    def test_termination_handler_unwinds_and_restores_the_callers_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(KeyboardInterrupt):
            with harness.interrupt_on_termination():
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_sigterm_restores_source_after_cleaning_the_owned_worker(self):
        self.interrupt_fixture(repeated=False)

    def test_repeated_sigterm_cannot_interrupt_worker_cleanup_or_source_restoration(self):
        self.interrupt_fixture(repeated=True)

    def interrupt_fixture(self, repeated):
        source = self.work / "source"
        fifo = self.work / "finish"
        os.mkfifo(fifo)
        script = ("import importlib.util,pathlib,sys,time; "
                  "spec=importlib.util.spec_from_file_location('h',sys.argv[1]); "
                  "h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h); "
                  "source=pathlib.Path(sys.argv[2]); work=source.parent\n"
                  "if sys.argv[3]=='repeat':\n"
                  " original=h.terminate_group\n"
                  " def held_cleanup(pgid):\n"
                  "  (work/'cleaning').write_text('ready')\n"
                  "  while not (work/'go').exists(): time.sleep(.01)\n"
                  "  original(pgid)\n"
                  " h.terminate_group=held_cleanup\n"
                  "with h.changed_source(source,b'restored',b'in flight'):\n"
                  " received=[0]; handler=h.signal.getsignal(h.signal.SIGTERM)\n"
                  " def observed(signum,frame):\n"
                  "  handler(signum,frame); received[0]+=1\n"
                  "  (work/'signals').write_text(str(received[0]))\n"
                  " h.signal.signal(h.signal.SIGTERM,observed)\n"
                  " h.run_owned(sys.argv[4:],10)\n")
        command = self.owned_command(
            "echo $$ > WORK/leader; /bin/cat WORK/finish & echo $! > WORK/descendant; wait")
        with tempfile.TemporaryFile() as output:
            wrapper = subprocess.Popen([sys.executable, "-I", "-c", script,
                                        str(ROOT / "scripts/verify-webhost-link-mutations.py"), str(source),
                                        "repeat" if repeated else "once", *command],
                                       stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not (self.work / "descendant").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue((self.work / "descendant").exists())
                wrapper.terminate()  # exact Popen handle; no signal by name or search
                if repeated:
                    deadline = time.monotonic() + 5
                    while not (self.work / "cleaning").exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue((self.work / "cleaning").exists())
                    wrapper.terminate()
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if (self.work / "signals").exists() and (self.work / "signals").read_text() == "2":
                            break
                        time.sleep(0.01)
                    self.assertEqual((self.work / "signals").read_text(), "2",
                                     "both signals must be handled before cleanup is released")
                    self.assertIsNone(wrapper.poll(), "a second signal must not unwind cleanup")
                    (self.work / "go").write_text("release")
                wrapper.wait(timeout=10)
                self.assertEqual(source.read_text(), "restored")
                self.assertTrue(gone(self.pids("leader")) and gone(self.pids("descendant")))
                self.assertIsNone(self.sentinel.poll())
            finally:
                (self.work / "go").write_text("release")
                if wrapper.poll() is None:
                    wrapper.kill()
                wrapper.wait()
                # A broken variant's explicit fixture can exit cooperatively, with no signal.
                try:
                    descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                except OSError:
                    pass
                else:
                    os.write(descriptor, b"finish\n")
                    os.close(descriptor)
                for name in ("leader", "descendant"):
                    if (self.work / name).exists():
                        gone(self.pids(name), within=3)

    def test_interruption_during_the_mutation_write_restores_original_bytes(self):
        source = self.work / "source"
        original, mutated = b"guard safe\n", b"guard true\n"
        source.write_bytes(original)
        write = Path.write_bytes

        def interrupted(path, data):
            result = write(path, data)
            if path == source and data == mutated:
                raise KeyboardInterrupt
            return result

        with mock.patch.object(Path, "write_bytes", autospec=True, side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                with harness.changed_source(source, original, mutated):
                    self.fail("the interrupted write cannot start a command")
        self.assertEqual(source.read_bytes(), original)

    def test_failed_restore_build_cannot_report_successful_mutation_verification(self):
        source = self.work / "source"
        source.write_text("guard is_safe\n")
        detail = self.work / "details.log"
        mutation = ("guard", str(source), "is_safe", "true", "focused")
        with mock.patch.object(harness, "M", [mutation]), \
                mock.patch.object(harness, "LOG", detail), \
                mock.patch.object(harness.sys, "argv", ["harness"]), \
                mock.patch.object(harness, "run_owned", side_effect=[
                    (0, "build"), (0, "baseline"), (0, "mutant build"), (1, "detected"), (1, "restore failed")]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(harness.main(), 2)
            self.assertIn("FAIL: restored source build", output.getvalue())
        self.assertEqual(source.read_text(), "guard is_safe\n")
        self.assertIn("restored source build -> 1", detail.read_text())

    def test_refuses_groups_it_does_not_own(self):
        for pgid in (0, 1, os.getpgrp()):
            with self.assertRaises(ValueError):
                harness.terminate_group(pgid)
        self.assertEqual(self.signalled, [])

    def test_continuation_compile_failure_is_not_a_detected_mutation(self):
        spec = importlib.util.spec_from_file_location("continuation_mutations", ROOT / "scripts/verify-continuation-mutations.py")
        continuation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(continuation)
        source, detail = self.work / "source", self.work / "details.log"
        source.write_bytes(b"guard safe\n")
        with mock.patch.object(continuation, "MUTATIONS", [("guard", str(source), "safe", "true", "focused")]), \
                mock.patch.object(continuation, "LOG", detail), \
                mock.patch.object(continuation.sys, "argv", ["continuation"]), \
                mock.patch.object(continuation.harness, "run_owned", side_effect=[
                    (0, "build"), (0, "baseline"), (1, "compile failed"), (0, "restored")]):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(continuation.main(), 1)
        self.assertIn("BUILD_FAILED", output.getvalue())
        self.assertNotIn("KILLED", output.getvalue())
        self.assertEqual(source.read_bytes(), b"guard safe\n")

    def test_harness_never_finds_processes_by_name(self):
        source = (ROOT / "scripts/verify-webhost-link-mutations.py").read_text()
        for forbidden in ("pkill", "killall", "pgrep", "psutil", '"ps"'):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
