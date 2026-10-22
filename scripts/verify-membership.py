#!/usr/bin/env python3
"""U0 only: boundary guard and unchanged 21-test codec suites on Mac/Linux.

No exchange or fixture environment variables. Network dependency downloads are permitted;
this is not a hermetic build. Output hashes bind the owned runner's UTF-8 replacement
text, not the original byte stream. Finite ASCII/hex/base64 synthetic-canary scans cannot
prove arbitrary secret noninterference. Run only after all source workers have stopped.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "Packages/VaultCore"
EXPECTED_SOURCE = "8d2470defaadd67e255535186c35d876fc80f932a647e4eb83a449f8cf29f076"
IMAGE = "swift@sha256:d6f8f6112e9a63da0a4a151d6b93acd16699d35c0b82531ac1a245f5af210197"
TARGET = "lowOrderEncapsulationRejectedAfterSignatureAndContext"
SCHEMA = "membership-u0-v1"
MAX_LOG = 32 * 1024 * 1024
spec = importlib.util.spec_from_file_location("membership_portable_primitives", ROOT / "scripts/verify-portable-vault.py")
portable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portable)
owned = portable.owned
VerificationFailure = portable.VerificationFailure
private_write = portable.private_write
source_digest = portable.source_digest
cleanup_container = portable.cleanup_container
error_record = portable.error_record
SENTINELS = [b"AV_UNIT1_SYNTHETIC_CANARY_7F92C6D0", b"synthetic-user"] + [
    bytes([value]) * 32 for value in (0x11, 0x21, 0x31, 0x41, 0x51)]
HARNESS = (
    "scripts/verify-membership.py", "scripts/verify-membership-controls.py",
    "deploy/tests/test_membership_verifier.py", "scripts/verify-portable-vault.py",
    "scripts/verify-webhost-link-mutations.py", "scripts/verify-boundaries.py",
    "deploy/tests/test_vault_fixture_boundary.py", ".github/workflows/ci.yml",
)


def require(condition, code):
    if not condition:
        raise VerificationFailure(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, limit=MAX_LOG):
    require(not path.is_symlink() and path.is_file(), "artifact_not_regular")
    require(0 < path.stat().st_size <= limit, "artifact_size_invalid")
    data = path.read_bytes()
    require(0 < len(data) <= limit, "artifact_size_invalid")
    return data


def file_record(path):
    data = read_regular(path)
    return {"sha256": sha(data), "size": len(data)}


def verify_file(path, expected):
    require(file_record(path) == expected, "artifact_hash_mismatch")


def package_snapshot(package):
    files = [package / "Package.swift", package / "Package.resolved"]
    for part in ("Sources", "Tests"):
        tree = package / part
        require(tree.is_dir() and not tree.is_symlink(), "package_tree_missing")
        for entry in tree.rglob("*"):
            require(not entry.is_symlink(), "package_symlink")
        files.extend(sorted(tree.rglob("*.swift")))
    require(len(files) >= 4, "package_files_missing")
    digest = hashlib.sha256()
    manifest = {}
    for path in files:
        data = read_regular(path)
        relative = path.relative_to(package).as_posix()
        manifest[relative] = {"sha256": sha(data), "size": len(data)}
        digest.update(relative.encode() + b"\0" + data + b"\0")
    return {"sha256": digest.hexdigest(), "files": manifest}


def snapshot():
    package = package_snapshot(PACKAGE)
    require(package["sha256"] == EXPECTED_SOURCE == source_digest(), "frozen_codec_changed")
    paths = list(HARNESS) + ["Package.swift", "Package.resolved"]
    for part in ("Sources", "Tests"):
        paths.extend(path.relative_to(ROOT).as_posix() for path in sorted((ROOT / part).rglob("*.swift")))
    inputs = {name: file_record(ROOT / name) for name in paths}
    # Imported implementations must be the exact files captured above, even in test copies.
    require(Path(portable.__file__).resolve() == (ROOT / "scripts/verify-portable-vault.py").resolve(),
            "imported_helper_path_mismatch")
    require(Path(owned.__file__).resolve() == (ROOT / "scripts/verify-webhost-link-mutations.py").resolve(),
            "imported_helper_path_mismatch")
    return {"package": package, "inputs": inputs}


def suite_names(package):
    names = []
    for path in sorted((package / "Tests").rglob("*.swift")):
        names.extend(re.findall(r"^@Test func ([A-Za-z0-9_]+)\(\)", path.read_text(), re.M))
    require(len(names) == 21 and len(set(names)) == 21 and TARGET in names, "codec_test_inventory_changed")
    return sorted(names)


def passed_tests(code, output, names):
    """Pinned Swift Testing text shape; require actual starts, completions and run exit."""
    starts = re.findall(r"^◇ Test (\w+)\(\) started\.$", output, re.M)
    passes = re.findall(r"^✔ Test (\w+)\(\) passed after [0-9.]+ seconds\.$", output, re.M)
    count = len(names)
    summary = rf"^✔ Test run with {count} test{'s' if count != 1 else ''} (?:in 0 suites )?passed after [0-9.]+ seconds\.$"
    return (code == 0 and output.splitlines().count("◇ Test run started.") == 1 and sorted(starts) == sorted(names) and sorted(passes) == sorted(names)
            and len(re.findall(summary, output, re.M)) == 1 and "✘" not in output
            and "recorded an issue" not in output and "error:" not in output
            and "[output capture ended" not in output)


def n1_location(package):
    lines = (package / "Tests/VaultCoreTests/LowOrderTests.swift").read_text().splitlines()
    matches = [(i + 1, line.index("(") + 1) for i, line in enumerate(lines)
               if line.strip() == "expectError(.badAuthentication) { _ = try fixture.open(bytes) }"]
    require(len(matches) == 1, "n1_assertion_anchor_changed")
    return matches[0]


def n1_detected(code, output, location):
    """Only 14 zero-DH cases at the frozen badAuthentication assertion count as N1."""
    line, column = location
    start = f"◇ Test {TARGET}() started."
    issue = f"✘ Test {TARGET}() recorded an issue at LowOrderTests.swift:{line}:{column}: Issue recorded"
    lines = output.splitlines()
    starts = [value for value in lines if re.match(r"◇ Test \w+\(\) started\.$", value)]
    issues = [i for i, value in enumerate(lines) if "recorded an issue" in value]
    failure = rf"✘ Test {TARGET}\(\) failed after [0-9.]+ seconds with 14 issues\."
    summary = r"✘ Test run with 1 test (?:in 0 suites )?failed after [0-9.]+ seconds with 14 issues\."
    if code != 1 or starts != [start] or len(issues) != 14 or lines.count("◇ Test run started.") != 1:
        return False
    if any(lines[i] != issue or i + 1 >= len(lines) or lines[i + 1] != "↳ Expected fixed codec error"
           for i in issues):
        return False
    events = [value for value in lines if value.startswith(("◇ Test ", "✔ Test ", "✘ Test ", "↳"))
              and value != "◇ Test run started."
              and not value.startswith(("↳ Testing Library Version: ", "↳ Target Platform: "))]
    expected_prefix = [start] + [value for _ in range(14) for value in (issue, "↳ Expected fixed codec error")]
    return (events[:-2] == expected_prefix and len(events) == len(expected_prefix) + 2
            and re.fullmatch(failure, events[-2]) is not None
            and re.fullmatch(summary, events[-1]) is not None
            and "error:" not in output and "[output capture ended" not in output)


def new_evidence(kind):
    parent = ROOT / "verification-logs/membership-u0-worker"
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    evidence = parent / (kind + "-" + uuid.uuid4().hex)
    evidence.mkdir(mode=0o700)
    return evidence


def make_run(evidence, steps):
    def run(label, command, timeout=900, required=True, scan=True):
        require(re.fullmatch(r"[a-z0-9_-]+", label) is not None, "invalid_step_label")
        step = {"step": label, "command": list(command), "cwd": str(ROOT), "timeout_seconds": timeout,
                "exit_code": None, "runner_error": None}
        steps.append(step)
        try:
            code, output = owned.run_owned(command, timeout=timeout, cwd=ROOT)
        except BaseException as error:
            step["runner_error"] = error_record(error)
            raise
        data = output.encode("utf-8")
        private_write(evidence / (label + ".log"), data)
        leak = scan and portable.rejects_secret_output(output, SENTINELS)
        step.update(exit_code=code, log=label + ".log", log_record={"sha256": sha(data), "size": len(data)},
                    secret_output_scanned=bool(scan), secret_output_detected=bool(leak))
        require(len(data) <= MAX_LOG, "log_size_invalid")
        require(not leak, "synthetic_secret_output")
        if required:
            require(code == 0, "failed_" + label)
        return code, output
    return run


def clean_env_required():
    require(not any(key.startswith("AV_TEST_") for key in os.environ), "fixture_environment_forbidden")


def runtime_and_container(run, state):
    runtime = state["runtime"]
    for label, command in (("native_swift", ["swift", "--version"]),
                           ("native_os", ["/usr/bin/sw_vers"]),
                           ("native_architecture", ["/usr/bin/uname", "-m"]),
                           ("native_target", ["swift", "-print-target-info"])):
        _, value = run(label, command, timeout=30)
        runtime[label] = value.strip()
    require("apple-macosx" in json.loads(runtime["native_target"])["target"]["triple"], "native_target_mismatch")
    _, image_text = run("linux_image", ["docker", "image", "inspect", IMAGE], timeout=30)
    images = json.loads(image_text)
    require(len(images) == 1 and images[0]["Os"] == "linux" and images[0]["Architecture"] == "arm64"
            and IMAGE in images[0]["RepoDigests"], "linux_image_mismatch")
    image = images[0]
    runtime["linux_image"] = {key: image[key] for key in ("Id", "Os", "Architecture", "RepoDigests")}
    state["container_attempted"] = True
    run("linux_create", ["docker", "create", "--name", state["name"], "--platform", "linux/arm64",
        "--label", "dev.agentvault.verification-owner=" + state["owner"],
        "--cpus", "4", "--memory", "6g", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--mount", "type=bind,src=" + str(state["package"]) + ",dst=/package,readonly",
        "--mount", "type=bind,src=" + str(state["evidence"]) + ",dst=/evidence",
        IMAGE, "/bin/sleep", "7200"], timeout=90)
    _, text = run("linux_identity", ["docker", "inspect", state["name"]], timeout=30)
    identifier = portable.owned_container(text, state["owner"])
    require(identifier is not None, "linux_identity_unconfirmed")
    require(json.loads(text)[0]["Image"] == image["Id"], "container_image_mismatch")
    state["identifier"] = identifier
    run("linux_start", ["docker", "start", identifier], timeout=30)
    for label, command in (("linux_swift", ["swift", "--version"]),
                           ("linux_architecture", ["uname", "-m"]),
                           ("linux_os", ["cat", "/etc/os-release"]),
                           ("linux_target", ["swift", "-print-target-info"])):
        _, value = run(label, ["docker", "exec", identifier, *command], timeout=30)
        runtime[label] = value.strip()
    require(runtime["linux_architecture"] == "aarch64", "linux_architecture_mismatch")
    triple = json.loads(runtime["linux_target"])["target"]["triple"]
    require(triple.startswith("aarch64-") and "linux" in triple, "linux_target_mismatch")


def suite_commands(state, platform, names):
    require(platform in ("native", "linux"), "unsupported_platform")
    package = str(state["package"]) if platform == "native" else "/package"
    scratch = str(state["evidence"] / "native-build") if platform == "native" else "/evidence/linux-build"
    prefix = [] if platform == "native" else ["docker", "exec", state["identifier"],
              "/bin/sh", "-c", 'umask 077; exec "$@"', "sh"]
    options = ["--package-path", package, "--scratch-path", scratch]
    selection = ["--filter", TARGET] if names == [TARGET] else []
    return ([*prefix, "swift", "build", *options, "--force-resolved-versions", "--build-tests", "--jobs", "4"],
            [*prefix, "swift", "test", *options, "--skip-build", *selection])


def test_package(run, state, platform, label, names, *, mutant=False):
    """Shared baseline/control build-test seam; no new process/container ownership logic."""
    build, test = suite_commands(state, platform, names)
    build_label, test_label = platform + "-" + label + "-build", platform + "-" + label + "-test"
    _, build_output = run(build_label, build, timeout=1500)
    require(re.search(r"^Build complete!", build_output, re.M) is not None, "build_completion_missing")
    code, output = run(test_label, test, timeout=180, required=False)
    if mutant and platform == "linux":
        require(n1_detected(code, output, n1_location(state["package"])), "n1_linux_not_detected")
        status = "detected"
    else:
        require(passed_tests(code, output, names), "named_suite_not_passed")
        status = "backend_masked" if mutant else "pass"
    return {"status": status, "tests": names, "build_step": build_label, "test_step": test_label,
            "build_exit_code": 0, "test_exit_code": code}


def finish(report, state, run, initial, failure):
    """Always preserve primary, cleanup and final source errors in separate fields."""
    report["failure"] = error_record(failure) if failure is not None else None
    report["cleanup"] = {"status": "not_needed"}
    if state["container_attempted"]:
        try:
            cleanup_container(run, state.get("identifier", state["name"]), state["owner"])
            report["cleanup"] = {"status": "removed"}
        except BaseException as error:
            report["cleanup"] = {"status": "unconfirmed", "error": error_record(error)}
            failure = failure if failure is not None else error
    report["artifact_check_error"] = None
    try:
        for step in report["steps"]:
            if "log" in step:
                verify_file(state["evidence"] / step["log"], step["log_record"])
    except BaseException as error:
        report["artifact_check_error"] = error_record(error)
        failure = failure if failure is not None else error
    report["source_check_error"] = None
    try:
        report["final_snapshot"] = snapshot()
        require(report["final_snapshot"] == initial, "source_changed_during_recording")
        report["source_unchanged"] = True
    except BaseException as error:
        report["source_unchanged"] = False
        report["source_check_error"] = error_record(error)
        failure = failure if failure is not None else error
    report["status"] = "pass" if failure is None else "fail"
    private_write(state["evidence"] / "result.json", (json.dumps(report, indent=2) + "\n").encode())
    return failure


def recording(kind):
    require(sys.platform == "darwin", "run_controller_on_macos")
    clean_env_required()
    initial = snapshot()
    evidence = new_evidence(kind)
    token = uuid.uuid4().hex
    state = {"evidence": evidence, "package": PACKAGE, "owner": token,
             "name": "agent-vault-membership-" + token, "container_attempted": False, "runtime": {}}
    report = {"schema": SCHEMA, "kind": kind, "snapshot": initial, "steps": [],
              "runtime": state["runtime"], "image": IMAGE, "scope": "synthetic_U0_no_exchange",
              "network": "dependency_downloads_permitted_not_hermetic",
              "python": {"executable": sys.executable, "version": sys.version, "optimized": not __debug__},
              "log_encoding": "owned_runner_utf8_replacement_text",
              "leak_scan": "finite_known_synthetic_ASCII_hex_base64_only", "fixture_environment": "none"}
    return state, report, make_run(evidence, report["steps"])


def verify_baseline(path, expected):
    """Revalidate exact inputs and captured logs, not merely a caller's PASS label."""
    data = read_regular(path, 4 * 1024 * 1024)
    path = path.resolve()
    report = json.loads(data)
    require(report.get("schema") == SCHEMA and report.get("kind") == "baseline"
            and report.get("status") == "pass" and report.get("snapshot") == expected
            and report.get("final_snapshot") == expected and report.get("source_unchanged") is True
            and report.get("failure") is None and report.get("source_check_error") is None
            and report.get("artifact_check_error") is None
            and report.get("cleanup") == {"status": "removed"}
            and report.get("image") == IMAGE, "matching_passed_baseline_required")
    steps = report["steps"]
    require(len({s["step"] for s in steps}) == len(steps), "duplicate_step")
    by_name = {s["step"]: s for s in steps}
    for step in steps:
        require(step.get("secret_output_scanned") is (step["step"] != "container_inspect"),
                "baseline_scan_policy_mismatch")
        require(step.get("runner_error") is None and step.get("exit_code") == 0
                and step.get("secret_output_detected") is False, "baseline_step_failed")
        require(step["log"] == step["step"] + ".log" and re.fullmatch(r"[a-z0-9_-]+", step["step"]), "invalid_log_path")
        verify_file(path.parent / step["log"], step["log_record"])
    require(by_name["guard"]["command"] == [sys.executable, str(ROOT / "scripts/verify-boundaries.py")], "guard_command_mismatch")
    runtime = report["runtime"]
    for label in ("native_swift", "native_os", "native_architecture", "native_target",
                  "linux_swift", "linux_os", "linux_architecture", "linux_target"):
        require(runtime[label] == (path.parent / by_name[label]["log"]).read_text().strip(), "runtime_log_mismatch")
    image = json.loads((path.parent / by_name["linux_image"]["log"]).read_text())[0]
    require(runtime["linux_image"] == {key: image[key] for key in ("Id", "Os", "Architecture", "RepoDigests")}
            and image["Os"] == "linux" and image["Architecture"] == "arm64", "baseline_runtime_mismatch")
    inspection = json.loads((path.parent / by_name["linux_identity"]["log"]).read_text())[0]
    identifier = inspection["Id"]
    require(re.fullmatch(r"[0-9a-f]{64}", identifier) and inspection["Image"] == image["Id"], "baseline_identity_mismatch")
    names = suite_names(PACKAGE)
    state = {"package": PACKAGE, "evidence": path.parent, "identifier": identifier}
    for platform in ("native", "linux"):
        result = report["suites"][platform]
        require(result["status"] == "pass" and result["tests"] == names, "baseline_suite_missing")
        build, test = by_name[result["build_step"]], by_name[result["test_step"]]
        expected_build, expected_test = suite_commands(state, platform, names)
        require(build["command"] == expected_build and test["command"] == expected_test,
                "baseline_command_mismatch")
        require(re.search(r"^Build complete!", (path.parent / build["log"]).read_text(), re.M), "build_completion_missing")
        require(passed_tests(test["exit_code"], (path.parent / test["log"]).read_text(), names), "baseline_suite_missing")
    require(report["runtime"]["linux_architecture"] == "aarch64"
            and IMAGE in report["runtime"]["linux_image"]["RepoDigests"], "baseline_runtime_mismatch")
    return {"path": str(path.resolve()), "sha256": sha(data), "size": len(data)}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    state, report, run = recording("baseline")
    failure = None
    try:
        run("guard", [sys.executable, str(ROOT / "scripts/verify-boundaries.py")])
        runtime_and_container(run, state)
        names = suite_names(PACKAGE)
        report["suites"] = {}
        for platform in ("native", "linux"):
            report["suites"][platform] = test_package(run, state, platform, "baseline", names)
    except BaseException as error:
        failure = error
    failure = finish(report, state, run, report["snapshot"], failure)
    if failure is not None:
        raise failure
    print(state["evidence"] / "result.json")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        with owned.interrupt_on_termination():
            main()
    except VerificationFailure as error:
        print("membership U0: " + str(error), file=sys.stderr)
        raise SystemExit(1)
