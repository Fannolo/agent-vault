#!/usr/bin/env python3
"""U0 raw N1 only, in an owned copy, after a matching passing U0 baseline.

Native CryptoKit is expected to mask this removal. Linux must detect all 14 zero-DH
cases at the frozen badAuthentication assertion. Neither result augments the 12 legacy
controls. No membership policy, ciphertext exchange, actual credentials or external vault.
"""
import argparse
import difflib
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("membership_verifier", ROOT / "scripts/verify-membership.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
RELATIVE = "Sources/VaultCore/RevisionCodec.swift"
REMOVED = b"        try validateX25519PublicKey(encapsulatedKey)\n"


def copy_package(evidence):
    package = evidence / "owned-package"
    package.mkdir(mode=0o700)
    original = verifier.package_snapshot(verifier.PACKAGE)
    for name in original["files"]:
        target = package / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        verifier.private_write(target, verifier.read_regular(verifier.PACKAGE / name))
    verifier.require(verifier.package_snapshot(package) == original, "owned_copy_mismatch")
    return package


def mutation_bytes(package, evidence):
    path = package / RELATIVE
    original = verifier.read_regular(path)
    verifier.require(original.count(REMOVED) == 1, "n1_mutation_anchor_changed")
    mutated = original.replace(REMOVED, b"")
    patch = "".join(difflib.unified_diff(original.decode().splitlines(True), mutated.decode().splitlines(True),
                                       fromfile=RELATIVE, tofile=RELATIVE)).encode()
    verifier.private_write(evidence / "n1.patch", patch)
    return path, original, mutated, {"target": RELATIVE, "removed_sites": 1,
        "original_sha256": verifier.sha(original), "mutated_sha256": verifier.sha(mutated),
        "patch": "n1.patch", "patch_record": {"sha256": verifier.sha(patch), "size": len(patch)},
        "test": verifier.TARGET, "expected_error": "Expected fixed codec error",
        "assertion": "badAuthentication", "source_location": verifier.n1_location(package)}


def platform_control(run, state, platform, path, original, mutated):
    record = {"platform": platform, "status": "failed", "failure": None, "restore_error": None,
              "restored_test_error": None}
    first = None
    initial = verifier.package_snapshot(state["package"])
    try:
        record["baseline"] = verifier.test_package(run, state, platform, "n1-before", [verifier.TARGET])
        try:
            with verifier.owned.changed_source(path, original, mutated):
                try:
                    record["mutant_source"] = verifier.package_snapshot(state["package"])
                    record["mutant"] = verifier.test_package(run, state, platform, "n1-mutant", [verifier.TARGET], mutant=True)
                    verifier.require(verifier.package_snapshot(state["package"]) == record["mutant_source"],
                                     "mutant_source_changed")
                except BaseException as error:
                    first = error
                    record["failure"] = verifier.error_record(error)
        except BaseException as error:
            record["restore_error"] = verifier.error_record(error)
            first = first if first is not None else error
    except BaseException as error:
        first = error
        record["failure"] = verifier.error_record(error)
    finally:
        try:
            record["restored_source"] = verifier.package_snapshot(state["package"])
            verifier.require(record["restored_source"] == initial, "owned_copy_not_restored")
            record["restored"] = verifier.test_package(run, state, platform, "n1-restored", [verifier.TARGET])
            verifier.require(verifier.package_snapshot(state["package"]) == initial, "restored_source_changed")
        except BaseException as error:
            record["restored_test_error"] = verifier.error_record(error)
            first = first if first is not None else error
    if first is None:
        record["status"] = record["mutant"]["status"]
    return record, first


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="Matching passing verify-membership.py result.json")
    args = parser.parse_args()
    state, report, run = verifier.recording("controls")
    failure = None
    copy_initial = None
    try:
        report["baseline"] = verifier.verify_baseline(args.baseline, report["snapshot"])
        state["package"] = copy_package(state["evidence"])
        copy_initial = verifier.package_snapshot(state["package"])
        report["owned_copy_initial"] = copy_initial
        path, original, mutated, report["mutation"] = mutation_bytes(state["package"], state["evidence"])
        verifier.runtime_and_container(run, state)
        report["controls"] = []
        for platform in ("native", "linux"):
            result, error = platform_control(run, state, platform, path, original, mutated)
            report["controls"].append(result)
            if error is not None:
                raise error
        verifier.require(verifier.verify_baseline(args.baseline, report["snapshot"]) == report["baseline"],
                         "baseline_changed_during_controls")
    except BaseException as error:
        failure = error
    finally:
        report["copy_check_error"] = None
        if copy_initial is not None:
            try:
                report["owned_copy_final"] = verifier.package_snapshot(state["package"])
                verifier.require(report["owned_copy_final"] == copy_initial, "owned_copy_not_restored")
                verifier.verify_file(state["evidence"] / "n1.patch", report["mutation"]["patch_record"])
            except BaseException as error:
                report["copy_check_error"] = verifier.error_record(error)
                failure = failure if failure is not None else error
        failure = verifier.finish(report, state, run, report["snapshot"], failure)
    if failure is not None:
        raise failure
    print(state["evidence"] / "result.json")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        with verifier.owned.interrupt_on_termination():
            main()
    except verifier.VerificationFailure as error:
        print("membership U0 controls: " + str(error), file=sys.stderr)
        raise SystemExit(1)
