"""Exercise scripts/record-verification.py against a tiny temporary repository and fake checks."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("record_verification", ROOT / "scripts/record-verification.py")
recorder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recorder)


def check(code):
    return [sys.executable, "-I", "-c", code]


CHECKS = {
    "pass": check("print('Ran 1 test'); print('OK')"),
    "fail": check("import sys; print('FAILED'); sys.exit(3)"),
    "aux": check("import sys; open(sys.argv[2], 'w').write('{\"results\": [1]}'); print('PASS aux')"),
    "aux-malformed": check("import sys; open(sys.argv[2], 'w').write('{\"results\": ['); print('PASS aux')"),
    "aux-missing": check("print('PASS aux')"),
    "edit-tracked": check("open('source.txt', 'a').write('changed')"),
    "new-untracked": check("open('new.txt', 'w').write('x')"),
    "new-ignored": check("open('state.json', 'w').write('{}')"),
    "artifacts": check("import os; os.makedirs('.build/debug', exist_ok=True); os.makedirs('pkg/__pycache__');"
                       "open('pkg/__pycache__/m.pyc', 'w').write('x'); open('.build/debug/o', 'w').write('x')"),
    "unstartable": ["/nonexistent/agent-vault-check"],
    "race": check("open('../race.json', 'w').write('earlier evidence')"),
}


class RecorderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="av-recorder-")
        self.addCleanup(directory.cleanup)
        self.repo = Path(directory.name).resolve() / "repo"
        self.repo.mkdir()
        (self.repo / "source.txt").write_text("source\n")
        (self.repo / ".gitignore").write_text(".build/\n__pycache__/\nstate.json\n/verification-logs/\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "init")
        for name, value in (("ROOT", self.repo), ("CHECKS", CHECKS), ("EVIDENCE", {"aux", "aux-malformed", "aux-missing"})):
            original = getattr(recorder, name)
            setattr(recorder, name, value)
            self.addCleanup(setattr, recorder, name, original)

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def record(self, name, *checks):
        path = self.repo.parent / f"{name}.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = recorder.main(["--checks", *checks, "--record", str(path)])
        return code, json.loads(path.read_text()), path

    def test_logs_and_evidence_are_retained_by_relative_path_and_hash(self):
        code, record, _ = self.record("r", "pass", "aux")
        self.assertEqual(code, 0)
        self.assertTrue(record["sourceUnchanged"])
        self.assertTrue(record["logDirectory"].startswith("verification-logs/"))
        for entry in record["checks"]:
            log = self.repo / entry["log"]
            self.assertFalse(Path(entry["log"]).is_absolute())
            self.assertEqual(entry["logSha256"], hashlib.sha256(log.read_bytes()).hexdigest())
            self.assertTrue(entry["passed"])
        aux = record["checks"][1]
        self.assertEqual(aux["evidence"], {"results": [1]})
        evidence = self.repo / aux["evidenceFile"]["path"]
        self.assertEqual(aux["evidenceFile"]["sha256"], hashlib.sha256(evidence.read_bytes()).hexdigest())
        self.assertNotIn(str(self.repo), json.dumps(record["checks"]))
        self.assertEqual(record["checks"][0]["observedSummary"], ["Ran 1 test", "OK"])

    def test_malformed_or_missing_evidence_is_a_recorded_failure(self):
        for name in ("aux-malformed", "aux-missing"):
            with self.subTest(name=name):
                code, record, _ = self.record(name, name, "pass")
                self.assertEqual(code, 1)
                self.assertEqual([c["name"] for c in record["checks"]], [name])
                failed = record["checks"][0]
                self.assertEqual(failed["exitCode"], 0)
                self.assertFalse(failed["passed"])
                self.assertIn("evidence", failed["error"])
                self.assertTrue((self.repo / failed["log"]).exists())
        retained = self.repo / record["logDirectory"]
        self.assertTrue(any(self.repo.glob("verification-logs/*aux-malformed/aux-malformed.json")))
        self.assertTrue(retained.is_dir())

    def test_failing_and_unstartable_checks_stop_the_run_and_are_recorded(self):
        code, record, _ = self.record("f", "fail", "pass")
        self.assertEqual(code, 1)
        self.assertEqual([(c["name"], c["exitCode"], c["passed"]) for c in record["checks"]], [("fail", 3, False)])
        code, record, _ = self.record("u", "unstartable")
        self.assertEqual(code, 1)
        self.assertIsNone(record["checks"][0]["exitCode"])
        self.assertIn("could not start", record["checks"][0]["error"])

    def test_source_changes_during_the_run_are_detected(self):
        for name in ("edit-tracked", "new-untracked", "new-ignored"):
            with self.subTest(name=name):
                code, record, _ = self.record(name, name)
                self.assertEqual(code, 1)
                self.assertTrue(record["checks"][0]["passed"])
                self.assertFalse(record["sourceUnchanged"])
                self.git("checkout", "--", ".")
                for path in ("new.txt", "state.json"):
                    (self.repo / path).unlink(missing_ok=True)

    def test_only_designated_build_and_log_output_is_excluded(self):
        code, record, _ = self.record("a", "artifacts")
        self.assertEqual(code, 0)
        self.assertTrue(record["sourceUnchanged"])
        self.assertEqual(record["source"]["ignoredPaths"], [])
        (self.repo / "state.json").write_text("{}")
        code, record, _ = self.record("b", "pass")
        self.assertEqual(record["source"]["ignoredPaths"], ["state.json"])
        self.assertEqual(record["buildCache"]["buildDirectoryBefore"], "directory")
        self.assertIn("not a clean build", record["buildCache"]["note"])

    def test_dirty_source_and_reused_record_paths_are_refused(self):
        _, first, path = self.record("once", "pass")
        before = path.read_bytes()
        logs = sorted(p.relative_to(self.repo) for p in (self.repo / "verification-logs").rglob("*"))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            recorder.main(["--checks", "pass", "--record", str(path)])
        self.record("twice", "pass")
        self.assertEqual(path.read_bytes(), before)
        after = sorted(p.relative_to(self.repo) for p in (self.repo / "verification-logs").rglob("*"))
        self.assertTrue(set(logs) < set(after))
        self.assertEqual(first["buildCache"]["buildDirectoryBefore"], "absent")
        (self.repo / "source.txt").write_text("edited\n")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            recorder.main(["--checks", "pass", "--record", str(self.repo.parent / "dirty.json")])

    def test_a_record_created_during_the_run_is_not_overwritten(self):
        path = self.repo.parent / "race.json"
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(FileExistsError):
            recorder.main(["--checks", "race", "--record", str(path)])
        self.assertEqual(path.read_text(), "earlier evidence")

    def test_log_directory_must_be_ignored(self):
        (self.repo / ".gitignore").write_text(".build/\n")
        self.git("commit", "-qam", "unignore")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            recorder.main(["--checks", "pass", "--record", str(self.repo.parent / "x.json")])
        self.assertFalse((self.repo / "verification-logs").exists())


if __name__ == "__main__":
    unittest.main()
