#!/usr/bin/env python3
"""Exchange synthetic sealed revisions between native macOS and Linux.

No real vault, Keychain, cloud account or production credential is accessed. Builds and
tests use the repository's owned-process runner. Only the uniquely labelled container
created by this invocation may be removed. Raw output stays in private local evidence.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "Packages" / "VaultCore"
IMAGE = "swift@sha256:d6f8f6112e9a63da0a4a151d6b93acd16699d35c0b82531ac1a245f5af210197"
spec = importlib.util.spec_from_file_location("owned_processes", ROOT / "scripts/verify-webhost-link-mutations.py")
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)


class VerificationFailure(Exception):
    pass


def rejects_secret_output(output, sentinels):
    """Finite accidental-output checks; not a general information-flow guarantee."""
    raw = output.encode("utf-8")
    for secret in sentinels:
        for form in (secret, secret.hex().encode(), secret.hex().upper().encode(),
                     base64.b64encode(secret), base64.urlsafe_b64encode(secret)):
            if form and form in raw:
                return True
    return False


def source_digest():
    files = [PACKAGE / "Package.swift", PACKAGE / "Package.resolved"]
    for part in ("Sources", "Tests"):
        files.extend(sorted((PACKAGE / part).rglob("*.swift")))
    if any(not path.is_file() for path in files[:2]) or len(files) < 4:
        raise VerificationFailure("portable_package_missing")
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(PACKAGE)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def owned_container(inspect_output, owner):
    """Resolve a known unique name only when the daemon confirms our owner label."""
    try:
        values = json.loads(inspect_output)
        if len(values) != 1:
            return None
        value = values[0]
        identifier = value["Id"]
        label = value["Config"]["Labels"]["dev.agentvault.verification-owner"]
        if label == owner and re.fullmatch(r"[0-9a-f]{64}", identifier):
            return identifier
    except (ValueError, KeyError, TypeError):
        pass
    return None


def error_record(error):
    # Only verifier-owned codes enter the report; external exception text may contain data.
    value = {"type": type(error).__name__}
    if isinstance(error, VerificationFailure):
        value["code"] = str(error)
    return value


def cleanup_container(run, name, owner):
    code, inspection = run("container_inspect", ["docker", "inspect", name], timeout=30,
                           required=False, scan=False)
    identifier = owned_container(inspection, owner) if code == 0 else None
    if identifier is None:
        raise VerificationFailure("owned_container_cleanup_unconfirmed")
    run("container_remove", ["docker", "rm", "--force", identifier], timeout=30)


def main():
    if sys.platform != "darwin":
        raise VerificationFailure("run_controller_on_macos")
    initial = source_digest()
    token = uuid.uuid4().hex
    evidence = ROOT / "verification-logs" / "portable-vault" / token
    evidence.mkdir(parents=True, mode=0o700)
    name = "agent-vault-codec-" + token
    results = []
    # These are test fixtures, never read from an existing vault or user account.
    sentinels = [b"AV_UNIT1_SYNTHETIC_CANARY_7F92C6D0", b"synthetic-user"]
    sentinels.extend(bytes([value]) * 32 for value in (0x11, 0x21, 0x31, 0x41, 0x51))

    def run(label, command, timeout=900, required=True, scan=True):
        code, output = owned.run_owned(command, timeout=timeout, cwd=ROOT)
        private_write(evidence / (label + ".log"), output.encode())
        leak = scan and rejects_secret_output(output, sentinels)
        results.append({"step": label, "exit_code": code, "secret_output_detected": bool(leak),
                        "output_sha256": hashlib.sha256(output.encode()).hexdigest()})
        if leak:
            raise VerificationFailure("synthetic_secret_in_" + label)
        if required and code != 0:
            raise VerificationFailure("failed_" + label)
        return code, output

    command = ["swift", "test", "--package-path", str(PACKAGE), "--scratch-path",
               str(evidence / "mac-build"), "--force-resolved-versions", "--jobs", "4"]
    container_attempted = False
    failure = None
    runtime = {}
    try:
        _, swift_version = run("native_swift", ["swift", "--version"], timeout=30)
        _, os_version = run("native_os", ["/usr/bin/sw_vers"], timeout=30)
        _, architecture = run("native_architecture", ["/usr/bin/uname", "-m"], timeout=30)
        _, image_metadata = run("linux_image_metadata", ["docker", "image", "inspect", IMAGE],
                                timeout=30, scan=False)
        images = json.loads(image_metadata)
        if len(images) != 1:
            raise VerificationFailure("linux_image_metadata_unconfirmed")
        runtime = {"native": {"swift": swift_version.strip(), "os": os_version.strip(),
                              "architecture": architecture.strip()},
                   "linux_image": {key: images[0].get(key) for key in ("Id", "Os", "Architecture", "RepoDigests")}}
        run("native_write", ["/usr/bin/env", "AV_TEST_WRITE_FIXTURE=" + str(evidence / "mac.seal"), *command])
        if not (evidence / "mac.seal").is_file():
            raise VerificationFailure("native_fixture_not_observed")
        (evidence / "mac.seal").chmod(0o600)
        container_attempted = True
        run("linux_create", ["docker", "create", "--name", name,
            "--label", "dev.agentvault.verification-owner=" + token,
            "--cpus", "4", "--memory", "6g", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--mount",
            "type=bind,src=" + str(PACKAGE) + ",dst=/package,readonly", "--mount",
            "type=bind,src=" + str(evidence) + ",dst=/evidence",
            "--env", "AV_TEST_READ_FIXTURE=/evidence/mac.seal",
            "--env", "AV_TEST_WRITE_FIXTURE=/evidence/linux.seal", IMAGE,
            "swift", "test", "--package-path", "/package", "--scratch-path", "/evidence/linux-build",
            "--force-resolved-versions", "--jobs", "4"], timeout=90)
        run("linux_exchange", ["docker", "start", "--attach", name], timeout=1500)
        _, inspection = run("linux_exit", ["docker", "inspect", name], timeout=30, scan=False)
        inspected = json.loads(inspection)
        if len(inspected) != 1 or inspected[0]["State"]["ExitCode"] != 0:
            raise VerificationFailure("linux_test_exit_not_success")
        if not (evidence / "linux.seal").is_file():
            raise VerificationFailure("linux_fixture_not_observed")
        (evidence / "linux.seal").chmod(0o600)
        run("native_read", ["/usr/bin/env", "AV_TEST_READ_FIXTURE=" + str(evidence / "linux.seal"), *command])
        altered = bytearray((evidence / "linux.seal").read_bytes())
        if not altered:
            raise VerificationFailure("empty_linux_fixture")
        altered[-1] ^= 1
        private_write(evidence / "corrupt.seal", bytes(altered))
        code, output = run("native_reject_corrupt_exchange", ["/usr/bin/env",
            "AV_TEST_READ_FIXTURE=" + str(evidence / "corrupt.seal"), *command,
            "--filter", "fixtureExchange"], required=False)
        if code == 0 or code is None or "badSignature" not in output or "fixtureExchange" not in output:
            raise VerificationFailure("corrupt_exchange_not_rejected")
    except BaseException as error:
        failure = error
    finally:
        cleanup = {"status": "not_needed"}
        if container_attempted:
            try:
                cleanup_container(run, name, token)
                cleanup = {"status": "removed"}
            except BaseException as error:
                cleanup = {"status": "unconfirmed", "error": error_record(error)}
                if failure is None:
                    failure = error
        unchanged = None
        source_error = None
        try:
            unchanged = source_digest() == initial
            if not unchanged:
                raise VerificationFailure("source_changed_during_recording")
        except BaseException as error:
            source_error = error_record(error)
            if failure is None:
                failure = error
        report = {"status": "pass" if failure is None else "fail", "source_sha256": initial,
                  "source_unchanged": unchanged, "linux_image": IMAGE, "steps": results,
                  "failure": error_record(failure) if failure is not None else None,
                  "cleanup": cleanup, "source_check_error": source_error,
                  "runtime": runtime,
                  "evidence_directory": str(evidence), "scope": "synthetic_codec_only"}
        private_write(evidence / "result.json", (json.dumps(report, indent=2) + "\n").encode())
    if failure is not None:
        raise failure
    print("portable vault: Mac/Linux tests and bidirectional fixture exchange pass")
    print("evidence: " + str(evidence / "result.json"))


if __name__ == "__main__":
    try:
        main()
    except VerificationFailure as error:
        print("portable vault: " + str(error), file=sys.stderr)
        raise SystemExit(1)
