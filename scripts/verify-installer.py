#!/usr/bin/env python3
"""Verify deploy/ipc/agentvault_installer.py without root and without touching the host.

1. Runs deploy/tests/test_installer.py with and without -O, in isolated mode.
2. Copies the installer to a private temporary directory, disables one guard at a time
   there and requires the named tests to fail. The working tree is never modified.
3. With --signed-payload DIR (for example dist/AgentVault-review), runs the installer CLI
   in a sandbox against a copy of the real signed programs: real codesign checks and
   cdhash pins, simulated accounts and launchd.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "deploy/ipc/agentvault_installer.py"
TESTS = ROOT / "deploy/tests/test_installer.py"
PYTHON = "/usr/bin/python3"

MUTATIONS = [
    ("ancestors not checked", [("    return meta.mode & 0o022 == 0", "    return True")],
     ["HostStateTests.test_unsafe_ancestors_are_refused"]),
    ("hard links accepted", [('require(kind != "file" or meta.nlink == 1,', "require(True,")],
     ["HostStateTests.test_existing_items_with_wrong_type_owner_mode_or_links_are_refused"]),
    ("source inspected instead of snapshot",
     [('self.inspect(program, self.staged_path("snapshot", program.source))',
       "self.inspect(program, os.path.join(args.payload, program.source))")],
     ["SignatureTests.test_payload_swapped_after_snapshot_is_not_installed"]),
    ("debugger entitlement accepted", [("require(not found.get_task_allow,", "require(True,")],
     ["SignatureTests.test_unsigned_or_misattributed_payloads_are_refused"]),
    ("unsafe code entitlements accepted", [("require(not found.unsafe_entitlements,", "require(True,")],
     ["SignatureTests.test_code_protection_exceptions_are_refused_before_install"]),
    ("unknown role entitlements accepted", [("require(role_entitlements_allowed(program.identifier, found.entitlements),", "require(True,")],
     ["SignatureTests.test_exact_role_entitlements_are_required"]),
    ("partial account adopted", [("require(complete or journal == uid,", "require(True,")],
     ["AccountTests.test_partial_account_is_completed_only_with_the_journal"]),
    ("approval key replaced silently", [("require(args.replace_approval_key == old_fingerprint,", "require(True,")],
     ["InstallTests.test_key_and_client_changes_need_the_current_values"]),
    ("no restart after interruption",
     [('interrupted = self.fs.lstat(self.staging, "restart.pending") is not None', "interrupted = False")],
     ["InstallTests.test_retry_converges_after_an_interruption_at_every_step"]),
    ("private directory built in place",
     [('                fd = self.stage_dir("data", 0o700, broker_uid, broker_uid)\n',
       '                self.fs.mkdir(db, DATA_NAME, 0o700)\n                fd = self.fs.open_dir(db, DATA_NAME)\n'
       '                self.fs.chmod(fd, 0o700)\n                self.fs.chown(fd, broker_uid, broker_uid)\n'),
      ('                self.fs.rename(self.staging, "data", db, DATA_NAME, RENAME_EXCL)\n', "")],
     ["InstallTests.test_retry_converges_after_an_interruption_at_every_step"]),
    ("sandbox allowed as root", [("if os.geteuid() == 0 or os.getuid() == 0:", "if False:")],
     ["StructureTests.test_sandbox_refuses_root_and_unmarked_directories"]),
    ("payload links followed",
     [("os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK", "os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK")],
     ["SignatureTests.test_payload_symlinks_and_special_files_are_refused"]),
]


def run_tests(installer, *names, optimize=True):
    env = {"PATH": "/usr/bin:/bin", "AGENTVAULT_INSTALLER": str(installer), "TMPDIR": tempfile.gettempdir()}
    return subprocess.run([PYTHON, "-I", *(["-O"] if optimize else []), str(TESTS), *names],
                          capture_output=True, text=True, env=env)


def suite():
    for optimize in (True, False):
        result = run_tests(INSTALLER, optimize=optimize)
        summary = [line for line in result.stderr.splitlines() if line.startswith(("Ran ", "OK", "FAILED", "optimize="))]
        print(f"tests {'-O' if optimize else 'default'}: {' | '.join(summary)}")
        if result.returncode != 0 or f"optimize={1 if optimize else 0}" not in result.stderr:
            print(result.stderr[-4000:])
            return False
    return True


def mutations():
    ok = True
    source = INSTALLER.read_text()
    with tempfile.TemporaryDirectory(prefix="av-installer-mutation-") as tmp:
        mutant = Path(tmp) / "agentvault_installer.py"
        for name, edits, tests in MUTATIONS:
            text = source
            for old, new in edits:
                if text.count(old) != 1:
                    break
                text = text.replace(old, new)
            else:
                mutant.write_text(text)
                result = run_tests(mutant, *tests)
                caught = result.returncode != 0
                print(f"mutation {name!r}: {'caught' if caught else 'NOT CAUGHT'}")
                ok = ok and caught
                continue
            print(f"mutation {name!r}: target text not found exactly once")
            ok = False
    return ok


def cli(sandbox, *args):
    result = subprocess.run([PYTHON, "-I", "-O", str(INSTALLER), "--sandbox", str(sandbox), *args],
                            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    print(f"  {args[0]}: exit {result.returncode}: {(result.stdout + result.stderr).strip()}")
    return result


def signed_dry_run(payload):
    with tempfile.TemporaryDirectory(prefix="av-installer-signed-") as tmp:
        tmp = Path(os.path.realpath(tmp))
        copy = tmp / "payload"
        copy.mkdir()
        for name in ("agent-vault-broker", "agent-vault-bridge"):
            shutil.copy2(payload / name, copy / name)
        shutil.copytree(payload / "AgentVault.app", copy / "AgentVault.app", symlinks=True)
        # A synthetic public key (the P-256 generator); its private half is not used anywhere.
        gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
        gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        key = b"\x04" + gx.to_bytes(32, "big") + gy.to_bytes(32, "big")
        (tmp / "key.json").write_text(json.dumps({
            "format": "agent-vault-approval-public-key-v1", "protection": "secure_enclave",
            "publicKeyX963Base64": base64.b64encode(key).decode()}))
        sandbox = tmp / "system"
        sandbox.mkdir()
        install = ["install", "--payload", str(copy), "--client-uid", "501", "--approval-key-file",
                   str(tmp / "key.json"), "--approval-key-sha256", hashlib.sha256(key).hexdigest()]
        steps = [cli(sandbox, "sandbox-init", "--client-uid", "501"), cli(sandbox, *install)]
        config = json.loads((sandbox / "Library/Application Support/AgentVault/config.json").read_text())
        pins = {k: config["ipc"][k].rsplit('H"', 1)[1].rstrip('"') for k in
                ("brokerRequirement", "readRequirement", "adminRequirement")}
        expected = {}
        for key_name, name in (("brokerRequirement", "agent-vault-broker"), ("readRequirement", "agent-vault-bridge"),
                               ("adminRequirement", "AgentVault.app")):
            details = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(payload / name)],
                                     capture_output=True, text=True).stderr
            expected[key_name] = next(l.split("=", 1)[1] for l in details.splitlines() if l.startswith("CDHash="))
        print(f"  pinned cdhashes match codesign of the source payload: {pins == expected} {pins}")
        steps += [cli(sandbox, "verify"), cli(sandbox, *install), cli(sandbox, "uninstall")]
        rerun_current = "already current" in steps[3].stdout
        print(f"  rerun reported no changes: {rerun_current}")
        return all(step.returncode == 0 for step in steps) and pins == expected and rerun_current


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--signed-payload", type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("verify-installer never runs as root")
    ok = suite()
    ok = mutations() and ok
    if args.signed_payload:
        print(f"signed dry run of {args.signed_payload}:")
        ok = signed_dry_run(args.signed_payload.resolve()) and ok
    print("verify-installer: " + ("passed" if ok else "FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
