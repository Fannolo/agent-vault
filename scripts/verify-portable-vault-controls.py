#!/usr/bin/env python3
"""Prove the codec's output and signature tests catch planted defects.

Each defect is compiled in an invocation-owned package copy. Main source is never
modified. Run only after a passing verify-portable-vault.py recording of identical source.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import uuid
import hashlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("portable_verifier", ROOT / "scripts/verify-portable-vault.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

MUTATIONS = [
    ("plaintext_log", "Sources/VaultCore/RevisionCodec.swift",
     "    return try LoginItem.decode(plaintext)",
     "    print(String(decoding: try LoginItem.decode(plaintext).password, as: UTF8.self))\n    return try LoginItem.decode(plaintext)",
     "fixtureExchange"),
    ("signature_bypass", "Sources/VaultCore/Record.swift",
     "        guard trustedAuthor.isValidSignature(signature, for: signedMessage) else {\n            throw VaultError.badSignature\n        }",
     "        // Verification deliberately omitted in this owned negative-control copy.",
     "signatureCheckedBeforeIdentityAndDecryption"),
    ("context_bypass", "Sources/VaultCore/RevisionCodec.swift",
     "    guard record.context == expected else { throw VaultError.unexpectedIdentity }",
     "    // Context verification deliberately omitted in this owned copy.",
     "contextComparisonsAndTransplantBinding"),
    ("role_binding_bypass", "Sources/VaultCore/Record.swift",
     "payloadAAD + Data(SHA256.hash(data: payloadSection)) + Data([role.rawValue]) + publicKey",
     "payloadAAD + Data(SHA256.hash(data: payloadSection)) + publicKey",
     "resignedPayloadAndEnvelopeTampering"),
    ("recipient_order_bypass", "Sources/VaultCore/Record.swift",
     "        guard strictlySorted(envelopes.map(\\.sortKey)) else { throw VaultError.malformed }",
     "        // Recipient order check deliberately omitted in this owned copy.",
     "signedNoncanonicalParentsAndRecipientsAreMalformed"),
    ("low_order_recipient_bypass", "Sources/VaultCore/Model.swift",
     "        try validateX25519PublicKey(publicKey)",
     "        // Typed recipient validation deliberately omitted in this owned copy.",
     "lowOrderRecipientValidationPreventsPublicRecovery"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="Passing result.json from the cross-platform runner")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise verifier.VerificationFailure("run_controller_on_macos")
    source = verifier.source_digest()
    baseline = json.loads(args.baseline.read_text())
    if baseline.get("status") != "pass" or baseline.get("source_sha256") != source:
        raise verifier.VerificationFailure("matching_passed_baseline_required")
    token = uuid.uuid4().hex
    evidence = ROOT / "verification-logs" / "portable-vault-controls" / token
    evidence.mkdir(parents=True, mode=0o700)
    results = []

    def run(label, command, timeout):
        code, output = verifier.owned.run_owned(command, timeout=timeout, cwd=ROOT)
        verifier.private_write(evidence / (label + ".log"), output.encode())
        return code, output

    def test_package(platform, label, package, test):
        scratch = str(evidence / (platform + "-build")) if platform == "native" else "/evidence/linux-build"
        location = str(package) if platform == "native" else "/package"
        build = ["swift", "build", "--package-path", location, "--scratch-path", scratch,
                 "--force-resolved-versions", "--build-tests", "--jobs", "4"]
        check = ["swift", "test", "--package-path", location, "--scratch-path", scratch,
                 "--skip-build", "--filter", test]
        prefix = platform + "-" + label
        name = "agent-vault-controls-" + uuid.uuid4().hex
        owner = uuid.uuid4().hex
        attempted = False
        failure = None
        answer = None
        cleanup = {"status": "not_needed"}
        try:
            if platform == "linux":
                attempted = True
                create, _ = run(prefix + "-create", ["docker", "create", "--name", name,
                    "--label", "dev.agentvault.verification-owner=" + owner,
                    "--cpus", "4", "--memory", "6g", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--mount",
                    "type=bind,src=" + str(package) + ",dst=/package,readonly", "--mount",
                    "type=bind,src=" + str(evidence) + ",dst=/evidence",
                    verifier.IMAGE, "/bin/sleep", "1800"], 90)
                if create != 0:
                    raise verifier.VerificationFailure("linux_control_create_failed")
                code, inspection = run(prefix + "-identity", ["docker", "inspect", name], 30)
                identifier = verifier.owned_container(inspection, owner) if code == 0 else None
                if identifier is None:
                    raise verifier.VerificationFailure("linux_control_identity_unconfirmed")
                start, _ = run(prefix + "-start", ["docker", "start", identifier], 30)
                if start != 0:
                    raise verifier.VerificationFailure("linux_control_start_failed")
                build = ["docker", "exec", identifier, *build]
                check = ["docker", "exec", identifier, *check]
            build_code, _ = run(prefix + "-build", build, 900)
            if build_code != 0:
                raise verifier.VerificationFailure("control_build_failed_" + prefix)
            code, output = run(prefix + "-test", check, 90)
            answer = code, output
        except BaseException as error:
            failure = error
        finally:
            if attempted:
                try:
                    def clean(label, command, timeout, required=True, scan=True):
                        code, output = run(prefix + "-" + label, command, timeout)
                        if required and code != 0:
                            raise verifier.VerificationFailure("failed_" + label)
                        return code, output
                    verifier.cleanup_container(clean, name, owner)
                    cleanup = {"status": "removed"}
                except BaseException as error:
                    cleanup = {"status": "unconfirmed", "error": verifier.error_record(error)}
                    if failure is None:
                        failure = error
            verifier.private_write(evidence / (prefix + "-lifecycle.json"),
                (json.dumps({"cleanup": cleanup, "failure": verifier.error_record(failure) if failure else None},
                            indent=2) + "\n").encode())
        if failure is not None:
            raise failure
        return answer

    for label, relative, old, new, test in MUTATIONS:
        package = evidence / label
        package.mkdir(mode=0o700)
        for name in ("Package.swift", "Package.resolved"):
            shutil.copyfile(verifier.PACKAGE / name, package / name)
        for name in ("Sources", "Tests"):
            shutil.copytree(verifier.PACKAGE / name, package / name)
        path = package / relative
        original = path.read_text()
        if original.count(old) != 1:
            raise verifier.VerificationFailure("mutation_anchor_changed_" + label)
        mutated = original.replace(old, new)
        for platform in ("native", "linux"):
            code, output = test_package(platform, label + "-baseline", package, test)
            if code != 0 or test not in output or verifier.rejects_secret_output(output, [b"AV_UNIT1_SYNTHETIC_CANARY_7F92C6D0"]):
                raise verifier.VerificationFailure("control_baseline_failed_" + platform + "_" + label)
            with verifier.owned.changed_source(path, original.encode(), mutated.encode()):
                code, output = test_package(platform, label + "-mutant", package, test)
                leaked = verifier.rejects_secret_output(output, [b"AV_UNIT1_SYNTHETIC_CANARY_7F92C6D0"])
                if label == "plaintext_log":
                    detected = code == 0 and leaked
                else:
                    detected = code is not None and code != 0 and test in output and "failed" in output
            if path.read_text() != original:
                raise verifier.VerificationFailure("owned_copy_not_restored_" + label)
            results.append({"defect": label, "platform": platform, "detected": bool(detected),
                            "build_exit_code": 0, "test_exit_code": code, "owned_copy_restored": True,
                            "test_output_sha256": hashlib.sha256(output.encode()).hexdigest()})
            if not detected:
                raise verifier.VerificationFailure("control_not_detected_" + platform + "_" + label)
            print(platform + ": detected " + label, flush=True)
    unchanged = verifier.source_digest() == source
    report = {"status": "pass" if unchanged else "fail", "source_sha256": source,
              "main_source_unchanged": unchanged, "baseline": str(args.baseline.resolve()),
              "controls": results, "scope": "finite_codec_detector_controls"}
    verifier.private_write(evidence / "result.json", (json.dumps(report, indent=2) + "\n").encode())
    if not unchanged:
        raise verifier.VerificationFailure("main_source_changed")
    print("portable vault: all planted defects detected on Mac and Linux; main source unchanged")
    print("evidence: " + str(evidence / "result.json"))


if __name__ == "__main__":
    try:
        main()
    except verifier.VerificationFailure as error:
        print("portable vault controls: " + str(error), file=sys.stderr)
        raise SystemExit(1)
