#!/usr/bin/env python3
"""U0 raw N1 or U1 policy controls in an owned copy after a matching baseline.

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


def platform_control(run, state, platform, path, original, mutated, *, control_id=None, unit="u0"):
    record = {"platform": platform, "status": "failed", "failure": None, "restore_error": None,
              "restored_test_error": None}
    first = None
    label = control_id.lower() if control_id else "n1"
    names = [verifier.U1_DETECTORS[control_id]["test"]] if control_id else [verifier.TARGET]
    selection = {"unit": unit, "control_id": control_id} if unit == "u1" else {}
    initial = verifier.package_snapshot(state["package"])
    try:
        record["baseline"] = verifier.test_package(run, state, platform, label + "-before", names, **selection)
        try:
            with verifier.owned.changed_source(path, original, mutated):
                try:
                    record["mutant_source"] = verifier.package_snapshot(state["package"])
                    record["mutant"] = verifier.test_package(run, state, platform, label + "-mutant", names, mutant=True, **selection)
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
            record["restored"] = verifier.test_package(run, state, platform, label + "-restored", names, **selection)
            verifier.require(verifier.package_snapshot(state["package"]) == initial, "restored_source_changed")
        except BaseException as error:
            record["restored_test_error"] = verifier.error_record(error)
            first = first if first is not None else error
    if first is None:
        record["status"] = record["mutant"]["status"]
    return record, first


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", choices=("u0", "u1"), default="u0")
    parser.add_argument("baseline", type=Path, help="Matching passing verify-membership.py result.json")
    args = parser.parse_args()
    if args.unit == "u1":
        return u1_main(args)
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


def u1_mutation_bytes(package, evidence, identifier):
    spec = verifier.U1_MUTATIONS[identifier]
    path = package / spec["file"]
    original = verifier.read_regular(path)
    verifier.require(original.count(spec["old"]) == 1, "u1_mutation_anchor_changed")
    mutated = original.replace(spec["old"], spec["new"])
    patch = "".join(difflib.unified_diff(original.decode().splitlines(True), mutated.decode().splitlines(True),
                                      fromfile=spec["file"], tofile=spec["file"])).encode()
    name = identifier.lower() + ".patch"
    verifier.private_write(evidence / name, patch)
    return path, original, mutated, {"id": identifier, "target": spec["file"], "changed_sites": 1,
        "original_sha256": verifier.sha(original), "mutated_sha256": verifier.sha(mutated),
        "patch": name, "patch_record": {"sha256": verifier.sha(patch), "size": len(patch)},
        "detector": verifier.U1_DETECTORS[identifier]}


def u1_main(args):
    state, report, run = verifier.recording("controls", unit="u1")
    failure, copy_initial = None, None
    report["controls"] = [{"id": identifier, "platform": platform, "status": "unexecuted"}
                          for identifier in verifier.U1_MUTATIONS for platform in ("native", "linux")]
    report["n1"] = [{"platform": platform, "status": "unexecuted"} for platform in ("native", "linux")]
    report["mutations"] = {}
    try:
        report["baseline"] = verifier.verify_u1_baseline(args.baseline, report["snapshot"])
        state["package"] = copy_package(state["evidence"])
        copy_initial = verifier.package_snapshot(state["package"])
        report["owned_copy_initial"] = copy_initial
        verifier.runtime_and_container(run, state)
        report["identifier"] = state["identifier"]
        baseline_runtime = verifier.strict_document(verifier.read_regular(args.baseline, 4 * 1024 * 1024))["runtime"]
        verifier.require(state["runtime"] == baseline_runtime, "controls_baseline_runtime_changed")
        for identifier in verifier.U1_MUTATIONS:
            path, original, mutated, record = u1_mutation_bytes(state["package"], state["evidence"], identifier)
            report["mutations"][identifier] = record
            name = record["patch"]
            report["artifacts"][name] = verifier.evidence_ref(state["evidence"], name)
            for platform in ("native", "linux"):
                result, error = platform_control(run, state, platform, path, original, mutated, control_id=identifier, unit="u1")
                result["id"] = identifier
                index = next(i for i, row in enumerate(report["controls"]) if row["id"] == identifier and row["platform"] == platform)
                report["controls"][index] = result
                if error is not None:
                    raise error
        path, original, mutated, record = mutation_bytes(state["package"], state["evidence"])
        report["mutations"]["N1"] = record
        report["artifacts"]["n1.patch"] = verifier.evidence_ref(state["evidence"], "n1.patch")
        for index, platform in enumerate(("native", "linux")):
            result, error = platform_control(run, state, platform, path, original, mutated, unit="u1")
            report["n1"][index] = result
            if error is not None:
                raise error
    except BaseException as error:
        failure = error
    finally:
        report["baseline_check_error"] = None
        if "baseline" in report:
            try:
                verifier.require(verifier.verify_u1_baseline(args.baseline, report["snapshot"]) == report["baseline"],
                                 "baseline_changed_during_controls")
            except BaseException as error:
                report["baseline_check_error"] = verifier.error_record(error)
                failure = failure if failure is not None else error
        report["copy_check_error"] = None
        if copy_initial is not None:
            try:
                report["owned_copy_final"] = verifier.package_snapshot(state["package"])
                verifier.require(report["owned_copy_final"] == copy_initial, "owned_copy_not_restored")
            except BaseException as error:
                report["copy_check_error"] = verifier.error_record(error)
                failure = failure if failure is not None else error
        failure = verifier.finish(report, state, run, report["snapshot"], failure, unit="u1")
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
