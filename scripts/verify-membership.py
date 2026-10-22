#!/usr/bin/env python3
"""Frozen U0 codec or U1 membership evidence on Mac/Linux.

U1 uses only fixed fixture paths and A/B roles. Network dependency downloads are permitted;
this is not a hermetic build. Output hashes bind the owned runner's UTF-8 replacement
text, not the original byte stream. Finite ASCII/hex/base64 synthetic-canary scans cannot
prove arbitrary secret noninterference. Run only after all source workers have stopped.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "Packages/VaultCore"

table_spec = importlib.util.spec_from_file_location("membership_spec", ROOT / "scripts/membership_spec.py")
tables = importlib.util.module_from_spec(table_spec)
table_spec.loader.exec_module(tables)
ORIGINAL_SOURCE = tables.ORIGINAL_SOURCE
ORIGINAL_FILES = tables.ORIGINAL_FILES
ORIGINAL_NAMES = tables.ORIGINAL_NAMES
EXCHANGE_LIMITS = tables.EXCHANGE_LIMITS
MAX_EXCHANGE = tables.MAX_EXCHANGE
MAX_EXCHANGE_JSON = tables.MAX_EXCHANGE_JSON
U1_SCHEMA = tables.U1_SCHEMA
U1_SOURCE = tables.U1_SOURCE
U1_FILES = tables.U1_FILES
U1_NAMES = tables.U1_NAMES
CORPUS_SHA = tables.CORPUS_SHA
TABLE_SHA = tables.TABLE_SHA
CRYPTO_REVISION = tables.CRYPTO_REVISION
READER_SOURCE = tables.READER_SOURCE
PRODUCER_TEST = tables.PRODUCER_TEST
READER_TEST = tables.READER_TEST
CASE_PREFIX = tables.CASE_PREFIX
RESULT_PREFIX = tables.RESULT_PREFIX
CORPUS_PREFIX = tables.CORPUS_PREFIX
OPENSSL = tables.OPENSSL
EXCHANGE_ORDER = tables.EXCHANGE_ORDER
BODY_PINS = tables.BODY_PINS
HEADS = tables.HEADS
CASE_TABLE = tables.CASE_TABLE
ORACLE_KEYS = tables.ORACLE_KEYS
ORACLE_SEEDS = tables.ORACLE_SEEDS
READER_FAILURE_REMARKS = tables.READER_FAILURE_REMARKS
U1_DETECTORS = tables.U1_DETECTORS
U1_MUTATIONS = tables.U1_MUTATIONS
EXCHANGE_STEPS = tables.EXCHANGE_STEPS
MUTATIONS = tables.MUTATIONS
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
SENTINELS += [b"AV_MEMBERSHIP_U1_SYNTHETIC_CANARY_5E3B91A4", b"synthetic-member"] + [
    bytes([value]) * 32 for value in (0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xD1, 0xD2, 0xD5, 0xD6, *range(0xE0, 0x100))]
SENTINELS += [bytes([0xC1]).decode("utf-8", "replace").encode("utf-8") * 32]
HARNESS = (
    "scripts/verify-membership.py", "scripts/verify-membership-controls.py", "scripts/membership_spec.py",
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


# Frozen U0 appendix. Harness DESIGN SHA256
# f2fa763b62318be50ea1f06c3efabae7713eca05385960a10bae361fb5074e19.
# Accepted U0 baseline SHA256
# 5218bc766b05c099141fd7e8fd9317634f1c58620c30dcb35e0d37ffe1efcd2e.
# Never regenerate these pins from a combined package or transferred artifacts.


def u1_package_snapshot(package, frozen_files):
    """Internal seam: root supplies the complete reviewed handoff manifest, never a CLI input."""
    combined = package_snapshot(package)
    original, digest = {}, hashlib.sha256()
    for name in ORIGINAL_FILES:
        data = read_regular(package / name)
        original[name] = {"size": len(data), "sha256": sha(data)}
        digest.update(name.encode() + b"\0" + data + b"\0")
    require(original == ORIGINAL_FILES and digest.hexdigest() == ORIGINAL_SOURCE, "u1_original_codec_changed")
    require(combined["files"] == frozen_files, "u1_package_inventory_changed")
    require(all(combined["files"].get(name) == record for name, record in original.items()),
            "u1_original_snapshot_changed")
    return {"original": {"sha256": digest.hexdigest(), "files": original}, "combined": combined}


def u1_suite_names(package, frozen_names):
    """Exact complete inventory is frozen by root only after the fixture worker stops."""
    names = []
    for path in sorted((package / "Tests").rglob("*.swift")):
        names.extend(re.findall(r"^@Test func ([A-Za-z0-9_]+)\(\)", path.read_text(), re.M))
    require(len(frozen_names) == len(set(frozen_names)) and len(names) == len(set(names)),
            "u1_duplicate_test_name")
    require(set(ORIGINAL_NAMES) <= set(frozen_names), "u1_original_test_missing")
    require(sorted(names) == sorted(frozen_names), "u1_test_inventory_changed")
    return sorted(names)


def _owned_path(owned_root, relative, *, directory=False):
    """No links within the declared root. Trusted callers own its ancestors and writers."""
    root = Path(owned_root)
    require(root.is_absolute() and ".." not in root.parts, "owned_path_invalid")
    require(isinstance(relative, str) and re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*", relative) is not None,
        "owned_path_invalid")
    try:
        require(stat.S_ISDIR(root.lstat().st_mode), "owned_path_invalid")
        path = root
        parts = relative.split("/")
        for index, part in enumerate(parts):
            path = path / part
            info = path.lstat()
            if index < len(parts) - 1 or directory:
                require(stat.S_ISDIR(info.st_mode), "owned_path_invalid")
            else:
                require(stat.S_ISREG(info.st_mode), "artifact_not_regular")
        return path, info
    except OSError:
        raise VerificationFailure("owned_input_unavailable") from None


def _file_identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _regular_bounds(info, minimum, limit):
    require(stat.S_ISREG(info.st_mode), "artifact_not_regular")
    require(minimum <= info.st_size <= limit, "artifact_size_invalid")


def _read_owned_regular(owned_root, relative, minimum, limit, *, expected=None):
    """Bound reads and compare path/descriptor observations; not a same-UID sandbox."""
    path, before = _owned_path(owned_root, relative)
    _regular_bounds(before, minimum, limit)
    if expected is not None:
        require(_file_identity(before) == _file_identity(expected), "artifact_changed_during_read")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(descriptor)
            _regular_bounds(opened, minimum, limit)
            require(_file_identity(opened) == _file_identity(before), "artifact_changed_during_read")
            data = bytearray()
            while len(data) <= limit:
                part = os.read(descriptor, min(65536, limit + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            after = os.fstat(descriptor)
            require(_file_identity(opened) == _file_identity(after), "artifact_changed_during_read")
        finally:
            os.close(descriptor)
    except OSError:
        raise VerificationFailure("owned_input_unavailable") from None
    _, final = _owned_path(owned_root, relative)
    require(_file_identity(final) == _file_identity(before), "artifact_changed_during_read")
    require(minimum <= len(data) <= limit and len(data) == before.st_size, "artifact_size_invalid")
    return bytes(data)


def membership_body_identity(data):
    """Structural AVMEMB01 identity only. Swift owns signature and semantic policy."""
    require(233 <= len(data) <= 1287, "membership_shape_invalid")
    require(data[:11] == b"AVMEMB01\x01\x01\x01", "membership_shape_invalid")
    count = int.from_bytes(data[131:135], "big")
    require(1 <= count <= 32 and len(data) == 199 + 34 * count, "membership_shape_invalid")
    previous = None
    for offset in range(135, 135 + 34 * count, 34):
        identity = data[offset:offset + 1] + data[offset + 2:offset + 34]
        require(previous is None or previous < identity, "membership_shape_invalid")
        previous = identity
    size = 135 + 34 * count
    return {"size": size, "sha256": sha(data[:size]), "member_count": count}


def exchange_snapshot(owned_root, relative):
    """Freeze exact public corpus metadata before a reader; rehash after every reader."""
    path, _ = _owned_path(owned_root, relative, directory=True)
    try:
        with os.scandir(path) as entries:
            files = {entry.name: entry.stat(follow_symlinks=False) for entry in entries}
    except OSError:
        raise VerificationFailure("owned_input_unavailable") from None
    require(set(files) == set(EXCHANGE_LIMITS), "exchange_file_set_invalid")
    for name, (minimum, limit) in EXCHANGE_LIMITS.items():
        _regular_bounds(files[name], minimum, limit)
    require(sum(info.st_size for info in files.values()) <= MAX_EXCHANGE, "exchange_size_invalid")
    records = {}
    for name, (minimum, limit) in sorted(EXCHANGE_LIMITS.items()):
        data = _read_owned_regular(owned_root, relative + "/" + name, minimum, limit, expected=files[name])
        record = {"size": len(data), "sha256": sha(data)}
        if name.endswith(".avm"):
            record["body"] = membership_body_identity(data)
        records[name] = record
    return records


def verify_exchange_snapshot(owned_root, relative, expected):
    require(exchange_snapshot(owned_root, relative) == expected, "exchange_changed")


def parse_exchange_json(data):
    """Bounded strict JSON only. No trace/summary schema or success decision exists yet."""
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_EXCHANGE_JSON, "exchange_json_size_invalid")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "exchange_json_duplicate_key")
            result[key] = value
        return result
    def constant(value):
        raise VerificationFailure("exchange_json_invalid")
    def number(value):
        result = float(value)
        require(math.isfinite(result), "exchange_json_invalid")
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=number)
    except (ValueError, UnicodeError, RecursionError):
        raise VerificationFailure("exchange_json_invalid") from None


def read_evidence_reference(owned_root, reference, *, limit=MAX_LOG):
    """References bind regular owned evidence bytes, not a reported status field."""
    require(isinstance(reference, dict) and set(reference) == {"path", "size", "sha256"},
            "evidence_reference_invalid")
    require(type(reference["size"]) is int and 0 < reference["size"] <= limit
            and isinstance(reference["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is not None,
            "evidence_reference_invalid")
    data = _read_owned_regular(owned_root, reference["path"], 1, reference["size"])
    require(len(data) == reference["size"] and sha(data) == reference["sha256"], "evidence_reference_mismatch")
    return data


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
    require(Path(tables.__file__).resolve() == (ROOT / "scripts/membership_spec.py").resolve(),
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


def new_evidence(kind, unit="u0"):
    require(unit in ("u0", "u1"), "unsupported_unit")
    parent = ROOT / ("verification-logs/membership-u1" if unit == "u1" else "verification-logs/membership-u0-worker")
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
    require(not any(key.startswith(("AV_TEST", "AV_MEMBERSHIP")) for key in os.environ), "fixture_environment_forbidden")


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


def suite_commands(state, platform, names, unit="u0"):
    require(platform in ("native", "linux"), "unsupported_platform")
    package = str(state["package"]) if platform == "native" else "/package"
    scratch = str(state["evidence"] / "native-build") if platform == "native" else "/evidence/linux-build"
    prefix = [] if platform == "native" else ["docker", "exec", state["identifier"],
              "/bin/sh", "-c", 'umask 077; exec "$@"', "sh"]
    options = ["--package-path", package, "--scratch-path", scratch]
    selection = ["--filter", TARGET] if names == [TARGET] else []
    if unit == "u1":
        require(names == list(U1_NAMES) or (len(names) == 1 and names[0] in U1_NAMES), "u1_selection_invalid")
        selection = ["--filter", names[0]] if len(names) == 1 else []
    else:
        require(unit == "u0", "unsupported_unit")
    return ([*prefix, "swift", "build", *options, "--force-resolved-versions", "--build-tests", "--jobs", "4"],
            [*prefix, "swift", "test", *options, "--skip-build", *(["--no-parallel"] if unit == "u1" else []), *selection])


def test_package(run, state, platform, label, names, *, mutant=False, unit="u0", control_id=None):
    """Shared baseline/control build-test seam; no new process/container ownership logic."""
    build, test = suite_commands(state, platform, names, unit=unit)
    build_label, test_label = platform + "-" + label + "-build", platform + "-" + label + "-test"
    build_code, build_output = run(build_label, build, timeout=1500)
    require(build_code == 0, "build_exit_failed")
    require(re.search(r"^Build complete!", build_output, re.M) is not None, "build_completion_missing")
    if mutant and platform == "native" and control_id is None:
        require(re.search(r"^\[\d+/\d+\] Compiling VaultCore RevisionCodec\.swift$", build_output, re.M)
                is not None, "masked_mutant_compilation_unconfirmed")
    scanner_error = None
    try:
        code, output = run(test_label, test, timeout=180, required=False)
    except VerificationFailure as error:
        if unit != "u1" or control_id != "M10" or not mutant or str(error) != "synthetic_secret_output":
            raise
        scanner_error = error_record(error)
        step = state["report_steps"][-1]
        require(step["step"] == test_label and step["secret_output_scanned"] is True
                and step["secret_output_detected"] is True and step["runner_error"] is None,
                "m10_scan_evidence_invalid")
        code = step["exit_code"]
        output = read_regular(state["evidence"] / (test_label + ".log")).decode()
        require(step["log_record"] == file_record(state["evidence"] / (test_label + ".log")), "m10_log_changed")
    if unit == "u1" and control_id is not None and mutant:
        spec = U1_DETECTORS[control_id]
        require(names == [spec["test"]], "u1_control_selection_invalid")
        if control_id == "M10":
            require(scanner_error is not None and passed_tests(code, output, names)
                    and portable.rejects_secret_output(output, SENTINELS), "m10_not_detected")
        else:
            require(runtime_failure(code, output, spec["test"], spec["location"], spec["message"], spec["detail"]),
                    "u1_control_not_detected")
        return {"status": "detected", "tests": names, "build_step": build_label, "test_step": test_label,
                "build_exit_code": 0, "test_exit_code": code, "scanner_error": scanner_error}
    if mutant and platform == "linux":
        require(n1_detected(code, output, n1_location(state["package"])), "n1_linux_not_detected")
        status = "detected"
    else:
        require(passed_tests(code, output, names), "named_suite_not_passed")
        status = "backend_masked" if mutant else "pass"
    return {"status": status, "tests": names, "build_step": build_label, "test_step": test_label,
            "build_exit_code": 0, "test_exit_code": code}


def finish(report, state, run, initial, failure, unit="u0"):
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
        if unit == "u1":
            for reference in report["artifacts"].values():
                read_evidence_reference(state["evidence"], reference)
            for directory, manifest in report.get("exchange_snapshots", {}).items():
                verify_exchange_snapshot(state["evidence"], directory, manifest)
    except BaseException as error:
        report["artifact_check_error"] = error_record(error)
        failure = failure if failure is not None else error
    report["source_check_error"] = None
    try:
        report["final_snapshot"] = u1_snapshot() if unit == "u1" else snapshot()
        require(report["final_snapshot"] == initial, "source_changed_during_recording")
        report["source_unchanged"] = True
    except BaseException as error:
        report["source_unchanged"] = False
        report["source_check_error"] = error_record(error)
        failure = failure if failure is not None else error
    if unit == "u1":
        report["validation_error"] = None
        if failure is None:
            try:
                report["status"] = "pass"
                if report["kind"] == "baseline":
                    validate_u1_before_write(report, state)
                else:
                    validate_u1_controls(report, state)
            except BaseException as error:
                report["validation_error"] = error_record(error)
                failure = error
    report["status"] = "pass" if failure is None else "fail"
    private_write(state["evidence"] / "result.json", (json.dumps(report, indent=2) + "\n").encode())
    return failure


def recording(kind, unit="u0"):
    require(sys.platform == "darwin", "run_controller_on_macos")
    clean_env_required()
    require(unit in ("u0", "u1"), "unsupported_unit")
    initial = u1_snapshot() if unit == "u1" else snapshot()
    evidence = new_evidence(kind, unit=unit)
    token = uuid.uuid4().hex
    state = {"evidence": evidence, "package": PACKAGE, "owner": token,
             "name": "agent-vault-membership-" + token, "container_attempted": False, "runtime": {}}
    report = {"schema": SCHEMA, "kind": kind, "snapshot": initial, "steps": [],
              "runtime": state["runtime"], "image": IMAGE, "scope": "synthetic_U0_no_exchange",
              "network": "dependency_downloads_permitted_not_hermetic",
              "python": {"executable": sys.executable, "version": sys.version, "optimized": not __debug__},
              "log_encoding": "owned_runner_utf8_replacement_text",
              "leak_scan": "finite_known_synthetic_ASCII_hex_base64_only", "fixture_environment": "none"}
    if unit == "u1":
        report.update(schema=U1_SCHEMA, scope="synthetic_U1_stateless_membership", fixture_environment="closed_paths_and_A_B_roles",
                      artifacts={}, owner=state["owner"], container_name=state["name"])
        state["report_steps"] = report["steps"]
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


def closed(value, keys, code):
    require(isinstance(value, dict) and set(value) == set(keys), code)


def strict_document(data, limit=4 * 1024 * 1024):
    require(isinstance(data, bytes) and 0 < len(data) <= limit, "document_size_invalid")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "document_duplicate_key")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, "document_nonfinite"))
    except (ValueError, UnicodeError, RecursionError):
        raise VerificationFailure("document_invalid") from None


def compact(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def evidence_ref(root, relative):
    data = _read_owned_regular(root, relative, 1, MAX_LOG)
    return {"path": relative, "size": len(data), "sha256": sha(data)}


def save_evidence(state, report, name, data):
    require(name not in report["artifacts"], "duplicate_artifact")
    private_write(state["evidence"] / name, data)
    reference = evidence_ref(state["evidence"], name)
    report["artifacts"][name] = reference
    return reference


def reader_custody(package):
    files = {p.relative_to(package).as_posix(): p.read_text() for part in ("Sources", "Tests")
             for p in sorted((package / part).rglob("*.swift"))}
    stripped = {name: re.sub(r"//[^\n]*", "", text) for name, text in files.items()}
    reader = stripped[READER_SOURCE]
    forbidden = (r"\bSigning\b", r"\bFixture\b", r"\bFixtureController\b", r"\bMembershipAuthority\b",
                 r"\bMembershipExchangeProducer\b", r"Seed\b", r"\bsignature\(for", r"\bsealRevision\b",
                 r"\bresign\b", r"\bsigned\(",
                 r"(?i)\b0x(?:11|21|31|41|51|61|c[1-5]|e[0-9a-f]|f[0-9a-f]|d5|d6)\b")
    require(not any(re.search(pattern, reader) for pattern in forbidden), "reader_authority_reachable")
    declaration = r"^(?:public |internal )?(?:final )?(?:func|struct|enum|class|let|var|typealias|actor)\s+(\w+)"
    foreign = {symbol for name, body in stripped.items() if name.startswith("Tests/") and name != READER_SOURCE
               for symbol in re.findall(declaration, body, re.M)}
    require(not any(re.search(r"\b" + re.escape(symbol) + r"\b", reader) for symbol in foreign),
            "reader_foreign_test_helper")
    for name, body in stripped.items():
        require(not (name.startswith("Sources/") and re.search(r"Signing\.PrivateKey\s*\(", body)),
                "library_signing_key_construction")
        for line in body.splitlines():
            require(not (name.startswith("Tests/") and re.match(r"(?:let|var|\s+static (?:let|var))\s", line)
                         and "PrivateKey(" in line), "global_key_initializer")
        if name not in ORIGINAL_FILES:
            extensions = re.findall(r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public |internal |private |fileprivate )?extension\s+([\w.]+)", body, re.M)
            require(all(target == "FixtureMembershipSession" for target in extensions), "prohibited_extension")
    return {"reader": READER_SOURCE, "reader_record": file_record(package / READER_SOURCE),
            "scope": "frozen_reviewed_call_path_lexical_check_not_same_uid_sandbox"}


def u1_snapshot():
    package = u1_package_snapshot(PACKAGE, U1_FILES)
    for part in ("Sources", "Tests"):
        for path in (PACKAGE / part).rglob("*"):
            require(path.is_dir() or path.relative_to(PACKAGE).as_posix() in U1_FILES, "u1_unexpected_source_file")
    require(package["combined"]["sha256"] == U1_SOURCE == source_digest(), "u1_package_digest_changed")
    names = u1_suite_names(PACKAGE, U1_NAMES)
    paths = list(HARNESS) + ["scripts/verify-portable-vault-controls.py", "AGENTS.md", "Package.swift", "Package.resolved",
                            "docs/design/multiplatform/MEMBERSHIP.md"]
    for part in ("Sources", "Tests"):
        paths.extend(p.relative_to(ROOT).as_posix() for p in sorted((ROOT / part).rglob("*.swift")))
    require(Path(portable.__file__).resolve() == ROOT / "scripts/verify-portable-vault.py"
            and Path(owned.__file__).resolve() == ROOT / "scripts/verify-webhost-link-mutations.py", "imported_helper_path_mismatch")
    require(Path(tables.__file__).resolve() == ROOT / "scripts/membership_spec.py", "imported_helper_path_mismatch")
    return {"package": package, "names": names, "inputs": {name: file_record(ROOT / name) for name in paths},
            "reader_custody": reader_custody(PACKAGE), "corpus_source": CORPUS_SHA, "corpus_table": TABLE_SHA,
            "recorder": {"path": "scripts/verify-membership.py", **file_record(Path(__file__))},
            "python_binary": file_record(Path(sys.executable).resolve())}


def fixture_bodies(keys):
    """Rebuild canonical bodies from independently derived public keys, never fixture reports."""
    closed(keys, ORACLE_KEYS, "oracle_keys_invalid")
    require(all(isinstance(value, bytes) and len(value) == 32 for value in keys.values()), "oracle_keys_invalid")
    w, a, b = (1, 3, keys["writer-agreement"]), (1, 1, keys["reader-a"]), (1, 1, keys["reader-b"])
    def body(sequence, parent, rows):
        ordered = sorted(rows, key=lambda row: bytes([row[0]]) + row[2])
        return (b"AVMEMB01\x01\x01\x01" + bytes([0x6D]) * 16 + sequence.to_bytes(8, "big") + parent
                + keys["controller"] + keys["writer"] + len(rows).to_bytes(4, "big")
                + b"".join(bytes([role, capability]) + key for role, capability, key in ordered))
    bodies = {}
    bodies["genesis.avm"] = body(0, bytes(32), [w, a])
    h0 = bytes.fromhex(sha(bodies["genesis.avm"]))
    bodies["add-reader.avm"] = body(1, h0, [w, a, b])
    h1 = bytes.fromhex(sha(bodies["add-reader.avm"]))
    bodies["remove-reader.avm"] = body(2, h1, [w, a])
    h2 = bytes.fromhex(sha(bodies["remove-reader.avm"]))
    bodies["gap-at-3.avm"] = body(3, h2, [w, a])
    bodies["fork-at-1.avm"] = body(1, h0, [w, a])
    bodies["contradiction-at-2.avm"] = body(2, bytes.fromhex(sha(b"agent-vault membership exchange nonexistent parent")), [w, a])
    require({name: sha(value) for name, value in bodies.items()} == BODY_PINS, "independent_body_pin_mismatch")
    return bodies


def public_key_from_pem(text, kind):
    lines = text.splitlines()
    require(len(lines) == 3 and lines[0] == "-----BEGIN PUBLIC KEY-----" and lines[-1] == "-----END PUBLIC KEY-----",
            "oracle_public_key_invalid")
    try:
        value = base64.b64decode(lines[1], validate=True)
    except ValueError:
        raise VerificationFailure("oracle_public_key_invalid") from None
    prefix = bytes.fromhex("302a300506032b6570032100" if kind == "ed25519" else "302a300506032b656e032100")
    require(len(value) == 44 and value[:12] == prefix, "oracle_public_key_invalid")
    return value[12:]


def prepare_oracle(run, state, report):
    temporary = state["evidence"] / "oracle-temporary"
    temporary.mkdir(mode=0o700)
    keys = {}
    run("oracle_version", [OPENSSL, "version"], timeout=30)
    try:
        for name, (kind, seed) in zip(ORACLE_KEYS, ORACLE_SEEDS):
            path = temporary / (name + ".der")
            prefix = "302e020100300506032b657004220420" if kind == "ed25519" else "302e020100300506032b656e04220420"
            private_write(path, bytes.fromhex(prefix) + bytes([seed]) * 32)
            _, output = run("oracle_" + name.replace("-", "_"),
                            [OPENSSL, "pkey", "-inform", "DER", "-in", str(path), "-pubout"], timeout=30)
            keys[name] = public_key_from_pem(output, kind)
    finally:
        for path in temporary.iterdir():
            path.unlink()
        temporary.rmdir()
    bodies = fixture_bodies(keys)
    save_evidence(state, report, "oracle-public.json", compact({name: key.hex() for name, key in keys.items()}))
    return bodies


def extract_corpus(raw, swift_source):
    require(sha(raw) == CORPUS_SHA, "corpus_source_hash_mismatch")
    corpus = strict_document(raw)
    require((corpus.get("algorithm"), corpus.get("generatorVersion"), corpus.get("numberOfTests"))
            == ("EDDSA", "0.9rc5", 150), "corpus_header_mismatch")
    rows, seen, counts = [], set(), {"valid": 0, "invalid": 0, "malleability": 0}
    groups = corpus["testGroups"]
    require(len(groups) == 77, "corpus_group_mismatch")
    for index, group in enumerate(groups):
        require(group.get("type") == "EddsaVerify" and group["publicKey"].get("curve") == "edwards25519",
                "corpus_group_mismatch")
        public_key = group["publicKey"]["pk"]
        require(isinstance(public_key, str) and re.fullmatch(r"[0-9a-f]{64}", public_key), "corpus_key_invalid")
        for case in group["tests"]:
            tcid, label, flags = case["tcId"], case["result"], case["flags"]
            require(type(tcid) is int and tcid not in seen and label in ("valid", "invalid"), "corpus_case_invalid")
            require(isinstance(flags, list) and all(isinstance(f, str) and re.fullmatch(r"[A-Za-z]+", f) for f in flags),
                    "corpus_case_invalid")
            require(all(isinstance(case[k], str) and re.fullmatch(r"(?:[0-9a-f]{2})*", case[k]) for k in ("msg", "sig")),
                    "corpus_case_invalid")
            seen.add(tcid)
            counts[label] += 1
            counts["malleability"] += "SignatureMalleability" in flags
            rows.append([tcid, index, public_key, case["msg"], case["sig"], label, ",".join(flags)])
    require(seen == set(range(1, 151)) and counts == {"valid": 88, "invalid": 62, "malleability": 8}, "corpus_count_mismatch")
    rows.sort(key=lambda row: row[0])
    table = "\n".join("|".join(map(str, row)) for row in rows)
    require(sha(table.encode()) == TABLE_SHA, "corpus_table_hash_mismatch")
    embedded = re.findall(r'    static let table = """\n(.*?)\n"""', swift_source, re.S)
    require(embedded == [table], "corpus_embedded_field_mismatch")
    for name, value in (("sourceSHA256", CORPUS_SHA), ("tableSHA256", TABLE_SHA), ("revision", CRYPTO_REVISION)):
        require(re.findall(r'    static let ' + name + r' = "([^"]+)"', swift_source) == [value], "corpus_provenance_mismatch")
    return rows


def prefixed_json(output, prefix):
    values = []
    for line in output.splitlines():
        if prefix.strip() in line:
            require(line.startswith(prefix) and len((line + "\n").encode()) <= MAX_EXCHANGE_JSON, "trace_line_invalid")
            values.append(parse_exchange_json(line[len(prefix):].encode()))
    return values


def machine_interval(output, name, prefixes):
    lines = output.splitlines()
    starts = [i for i, line in enumerate(lines) if line == f"◇ Test {name}() started."]
    ends = [i for i, line in enumerate(lines) if re.fullmatch(rf"✔ Test {name}\(\) passed after [0-9.]+ seconds\.", line)]
    require(len(starts) == len(ends) == 1 and starts[0] < ends[0], "trace_named_interval_missing")
    values = []
    for index, line in enumerate(lines):
        if line.startswith("AV_"):
            require(any(line.startswith(prefix) for prefix in prefixes) and starts[0] < index < ends[0], "trace_interval_invalid")
            values.append(line)
    return values


def signature_result(output, platform, rows):
    machine_interval(output, "wycheproofEd25519ExpectedOutcomes", (CORPUS_PREFIX,))
    values = prefixed_json(output, CORPUS_PREFIX)
    require(len(values) == 1, "signature_report_missing")
    value = values[0]
    closed(value, ("schema", "platform", "sourceSHA256", "tableSHA256", "cases"), "signature_report_invalid")
    expected = [{"tcId": row[0], "expected": row[5], "constructed": True, "verified": row[5] == "valid"} for row in rows]
    require(value["schema"] == "agent-vault-wycheproof-ed25519-v1" and value["platform"] == platform
            and value["sourceSHA256"] == CORPUS_SHA and value["tableSHA256"] == TABLE_SHA, "signature_provenance_mismatch")
    require(value["cases"] == expected and all(type(c["constructed"]) is bool and type(c["verified"]) is bool
                                             and type(c["tcId"]) is int for c in value["cases"]), "signature_cases_mismatch")
    return value


def expected_cases(reader):
    require(reader in ("A", "B"), "reader_role_invalid")
    result = []
    for index, (identifier, outcome, sequence) in enumerate(CASE_TABLE):
        if reader == "B" and index in (1, 15):
            outcome = "unauthorizedRecipient"
        if reader == "B" and index == 10:
            outcome = "badAuthentication"
        case = {"reader": reader, "index": index, "id": identifier, "outcome": outcome, "sequence": sequence, "head": HEADS[sequence]}
        if 20 <= index <= 23:
            case["evidence"] = "observedSequence"
        if 26 <= index <= 28:
            case["evidence"] = "signedLineageContradiction"
        result.append(case)
    return result


def validate_cases(cases, reader, *, negative=False):
    expected = expected_cases(reader)[:5] if negative else expected_cases(reader)
    require(cases == expected, "reader_case_oracle_mismatch")
    for case in cases:
        require(type(case["index"]) is int and type(case["sequence"]) is int, "reader_case_oracle_mismatch")


def body_records(bodies):
    return [{"name": name, "body": sha(bodies[name]), "sequence": int.from_bytes(bodies[name][27:35], "big"),
             "parent": bodies[name][35:67].hex()} for name in EXCHANGE_ORDER if name in bodies]


def validate_fixture_files(root, relative, bodies):
    manifest = exchange_snapshot(root, relative)
    path, info = _owned_path(root, relative, directory=True)
    require(stat.S_IMODE(info.st_mode) == 0o700, "exchange_permissions_invalid")
    for name in EXCHANGE_ORDER:
        file, info = _owned_path(root, relative + "/" + name)
        require(stat.S_IMODE(info.st_mode) == 0o600, "exchange_permissions_invalid")
        if name in bodies:
            data = _read_owned_regular(root, relative + "/" + name, *EXCHANGE_LIMITS[name])
            require(data[:-64] == bodies[name], "exchange_body_oracle_mismatch")
    return manifest


def exchange_result(code, output, platform, role, manifest, bodies, reader=None):
    test = PRODUCER_TEST if role == "producer" else READER_TEST
    require(role in ("producer", "reader") and platform in ("macos", "linux"), "exchange_role_invalid")
    require(passed_tests(code, output, [test]), "exchange_named_test_missing")
    machine = machine_interval(output, test, (CASE_PREFIX, RESULT_PREFIX))
    require(machine and machine[-1].startswith(RESULT_PREFIX)
            and all(line.startswith(CASE_PREFIX) for line in machine[:-1]), "trace_order_invalid")
    values = prefixed_json(output, RESULT_PREFIX)
    cases = prefixed_json(output, CASE_PREFIX)
    require(not prefixed_json(output, CORPUS_PREFIX) and len(values) == 1, "exchange_result_missing")
    value = values[0]
    keys = {"schema", "role", "platform", "pin", "files", "bodies", "status"}
    keys.update(("reader", "cases") if role == "reader" else ("checkpoints",))
    closed(value, keys, "exchange_result_invalid")
    require(value["schema"] == "agent-vault-membership-exchange-v1" and value["role"] == role
            and value["platform"] == platform, "exchange_role_invalid")
    require(value["pin"] == {"vault": "6d" * 16, "genesisBody": HEADS[0]}, "exchange_pin_mismatch")
    files = [{"name": name, "size": manifest[name]["size"], "sha256": manifest[name]["sha256"]} for name in EXCHANGE_ORDER]
    require(value["files"] == files and all(type(f["size"]) is int for f in value["files"]), "exchange_file_binding_mismatch")
    require(value["bodies"] == body_records(bodies) and all(type(b["sequence"]) is int for b in value["bodies"]),
            "exchange_body_binding_mismatch")
    if role == "reader":
        require(value["reader"] == reader and value["cases"] == cases, "reader_role_invalid")
        validate_cases(cases, reader)
    else:
        require(reader is None and not cases and value["checkpoints"] == [{"sequence": i, "head": h} for i, h in enumerate(HEADS)]
                and all(type(c["sequence"]) is int for c in value["checkpoints"]),
                "producer_checkpoint_mismatch")
    # status is a schema field, never an acceptance oracle.
    require(isinstance(value["status"], str), "exchange_result_invalid")
    return value


def runtime_failure(code, output, name, location, message, detail=None, *, remarks=()):
    """Pinned native grammar. Linux must match exactly or block, with no fallback."""
    if type(code) is not int or code != 1 or "[output capture ended" in output:
        return False
    lines = output.splitlines()
    issue_line = f"✘ Test {name}() recorded an issue at {location}: {message}"
    if any("error:" in line and line != issue_line for line in lines):
        return False
    if lines.count("◇ Test run started.") != 1:
        return False
    events = [line for line in lines if line.startswith(("◇ Test ", "✔ Test ", "✘ Test ", "↳"))
              and line != "◇ Test run started."
              and not line.startswith(("↳ Testing Library Version: ", "↳ Target Platform: "))]
    expected = [f"◇ Test {name}() started.", f"✘ Test {name}() recorded an issue at {location}: {message}"]
    if detail is not None:
        expected.append("↳ " + detail)
    return (len(events) == len(expected) + 2 + len(remarks) and events[:len(expected)] == expected
            and re.fullmatch(rf"✘ Test {name}\(\) failed after [0-9.]+ seconds with 1 issue\.", events[len(expected)]) is not None
            and tuple(events[len(expected) + 1:-1]) == remarks
            and re.fullmatch(r"✘ Test run with 1 test in 0 suites failed after [0-9.]+ seconds with 1 issue\.", events[-1]) is not None
            and sum("recorded an issue" in line for line in lines) == 1)


def exchange_failure(code, output):
    if not runtime_failure(code, output, READER_TEST, "MembershipReaderFixtures.swift:372:2", "Caught error: badSignature",
                           remarks=READER_FAILURE_REMARKS):
        return False
    try:
        require(not prefixed_json(output, RESULT_PREFIX) and not prefixed_json(output, CORPUS_PREFIX), "negative_result_forbidden")
        cases = prefixed_json(output, CASE_PREFIX)
        validate_cases(cases, "A", negative=True)
        lines = output.splitlines()
        start = lines.index(f"◇ Test {READER_TEST}() started.")
        issue = next(i for i, line in enumerate(lines) if "recorded an issue" in line)
        indexes = [i for i, line in enumerate(lines) if line.startswith(CASE_PREFIX)]
        require(len(indexes) == 5 and all(start < i < issue for i in indexes), "negative_case_order_invalid")
        return True
    except (VerificationFailure, ValueError, StopIteration):
        return False


def selected_fixture_command(state, platform, directory, reader=None):
    require(platform in ("native", "linux") and reader in (None, "A", "B"), "fixture_launcher_invalid")
    require(directory in ("native-corpus", "linux-corpus", "native-negative", "linux-negative"), "fixture_launcher_invalid")
    _, test = suite_commands(state, platform, [PRODUCER_TEST if reader is None else READER_TEST], unit="u1")
    index = test.index("swift")
    path = str(state["evidence"] / directory) if platform == "native" else "/evidence/" + directory
    variables = ["AV_MEMBERSHIP_WRITE_DIR=" + path] if reader is None else ["AV_MEMBERSHIP_READ_DIR=" + path, "AV_MEMBERSHIP_READER=" + reader]
    return test[:index] + ["/usr/bin/env", *variables] + test[index:]


def run_fixture(run, state, platform, label, directory, reader=None, *, negative=False):
    code, output = run(label, selected_fixture_command(state, platform, directory, reader), timeout=180, required=False)
    if negative:
        require(exchange_failure(code, output), "negative_transfer_not_detected")
    else:
        require(passed_tests(code, output, [PRODUCER_TEST if reader is None else READER_TEST]), "exchange_named_test_missing")
    return code, output


def negative_corpus(root, original, negative, bodies):
    before = validate_fixture_files(root, original, bodies)
    (root / negative).mkdir(mode=0o700)
    for name in EXCHANGE_ORDER:
        data = _read_owned_regular(root, original + "/" + name, *EXCHANGE_LIMITS[name])
        if name == "head1.avseal":
            require(len(data) == 674, "negative_signature_offset_changed")
            data = data[:-1] + bytes([data[-1] ^ 1])
        private_write(root / negative / name, data)
    after = validate_fixture_files(root, negative, bodies)
    require(before.keys() == after.keys() and [n for n in before if before[n] != after[n]] == ["head1.avseal"], "negative_delta_invalid")
    return after


def validate_negative_delta(root, original, negative, bodies):
    before = validate_fixture_files(root, original, bodies)
    after = validate_fixture_files(root, negative, bodies)
    for name in EXCHANGE_ORDER:
        a = _read_owned_regular(root, original + "/" + name, *EXCHANGE_LIMITS[name])
        b = _read_owned_regular(root, negative + "/" + name, *EXCHANGE_LIMITS[name])
        if name == "head1.avseal":
            require(len(a) == 674 and b == a[:-1] + bytes([a[-1] ^ 1]), "negative_delta_invalid")
        else:
            require(a == b, "negative_delta_invalid")
    return {"file": "head1.avseal", "offset": 673, "xor": 1, "before": before["head1.avseal"]["sha256"],
            "after": after["head1.avseal"]["sha256"]}


def validate_no_fixture_output(output):
    require(not prefixed_json(output, CASE_PREFIX) and not prefixed_json(output, RESULT_PREFIX), "normal_suite_fixture_io")


def fixture_custody(report, root, label, directory, expected, *, before):
    observed = exchange_snapshot(root, directory)
    require(observed == expected, "exchange_changed")
    entry = report["custody"].setdefault(label, {})
    entry["before" if before else "after"] = observed


def checked_reader(run, state, report, platform, label, directory, reader, manifest, bodies, *, negative=False,
                   original_directory=None, original_manifest=None):
    root = state["evidence"]
    errors = {"failure": None, "artifact_check_error": None}
    report["exchange_errors"][label] = errors
    first, result = None, None
    try:
        fixture_custody(report, root, label, directory, manifest, before=True)
        code, output = run_fixture(run, state, platform, label, directory, reader, negative=negative)
        if not negative:
            result = exchange_result(code, output, "macos" if platform == "native" else "linux", "reader", manifest, bodies, reader)
    except BaseException as error:
        errors["failure"] = error_record(error)
        first = error
    finally:
        try:
            fixture_custody(report, root, label, directory, manifest, before=False)
            if original_directory is not None:
                verify_exchange_snapshot(root, original_directory, original_manifest)
        except BaseException as error:
            errors["artifact_check_error"] = error_record(error)
            first = first if first is not None else error
    if first is not None:
        raise first
    return result


def exchange_direction(run, state, report, producer, bodies, *, replay=False):
    """Run or replay the identical fixed exchange; replay never creates corpus files."""
    root = state["evidence"]
    consumer = "linux" if producer == "native" else "native"
    directory, negative = producer + "-corpus", producer + "-negative"
    readers, manifest, negative_record = {}, None, None
    for suffix, kind, role in EXCHANGE_STEPS:
        label = producer + "-" + suffix
        if kind == "producer":
            code, output = run_fixture(run, state, producer, label, directory)
            manifest = validate_fixture_files(root, directory, bodies)
            report["exchange_snapshots"][directory] = manifest
            exchange_result(code, output, "macos" if producer == "native" else "linux",
                            "producer", manifest, bodies)
            continue
        if kind == "negative":
            if replay:
                validate_negative_delta(root, directory, negative, bodies)
                altered = validate_fixture_files(root, negative, bodies)
            else:
                altered = negative_corpus(root, directory, negative, bodies)
            report["exchange_snapshots"][negative] = altered
            checked_reader(run, state, report, consumer, label, negative, role, altered, bodies,
                           negative=True, original_directory=directory, original_manifest=manifest)
            negative_record = {
                "classification": "badSignature_at_main.open.head1",
                "log": evidence_ref(root, label + ".log"),
                "patch": validate_negative_delta(root, directory, negative, bodies), "files": altered,
            }
            continue
        value = checked_reader(run, state, report, consumer, label, directory, role, manifest, bodies)
        if kind == "reader":
            readers[role] = {"log": evidence_ref(root, label + ".log"), "cases": value["cases"]}
    return direction_summary(root, producer, manifest, readers, negative_record, bodies)


def direction_summary(root, producer, manifest, readers, negative_record, bodies):
    require(set(readers) == {"A", "B"} and negative_record is not None, "exchange_direction_incomplete")
    directory = producer + "-corpus"
    pairs = []
    for kind, second in (("observedSequence", "fork-at-1.avm"), ("signedLineageContradiction", "contradiction-at-2.avm")):
        pairs.append({"kind": kind, "first": evidence_ref(root, directory + "/add-reader.avm"),
                      "second": evidence_ref(root, directory + "/" + second)})
    return {"producer": producer, "consumer": "linux" if producer == "native" else "native", "files": manifest,
            "bodies": body_records(bodies), "producer_log": evidence_ref(root, producer + "-produce.log"),
            "readers": readers, "evidence_pairs": pairs, "negative": negative_record,
            "restored_reader_a": evidence_ref(root, producer + "-read-a-restored.log"), "inputs_unchanged": True}


def summary_document(snapshot, artifacts, directions):
    return {"schema": "membership-u1-exchange-summary-v1", "source_epoch": sha(compact(snapshot)),
            "oracle": artifacts["oracle-public.json"], "pin": {"vault": "6d" * 16, "genesisBody": HEADS[0]},
            "directions": directions,
            "signature": {"primary": artifacts["corpus-primary.json"], "native": artifacts["corpus-native.json"],
                          "linux": artifacts["corpus-linux.json"], "table": artifacts["corpus-table.txt"]},
            "cofactor": {"status": "unmeasured", "evidence": artifacts["cofactor-matrix.json"]}}


def write_summary(state, report, directions):
    summary = summary_document(report["snapshot"], report["artifacts"], directions)
    data = compact(summary)
    require(len(data) <= MAX_EXCHANGE_JSON, "exchange_summary_overflow")
    require(not portable.rejects_secret_output(data.decode(), SENTINELS), "synthetic_secret_output")
    report["summary"] = save_evidence(state, report, "exchange-summary.json", data)


def u1_baseline(run, state, report):
    run("guard", [sys.executable, str(ROOT / "scripts/verify-boundaries.py")])
    runtime_and_container(run, state)
    report["owner"] = state["owner"]
    report["container_name"] = state["name"]
    report["identifier"] = state["identifier"]
    report["suites"] = {}
    for platform in ("native", "linux"):
        report["suites"][platform] = test_package(run, state, platform, "baseline", list(U1_NAMES), unit="u1")
    primary = state["evidence"] / "native-build/checkouts/swift-crypto/Tests/Test Vectors/ed25519_test.json"
    # SwiftPM checkout content is verified by the primary digest, independent of its path name.
    raw = read_regular(primary, 1024 * 1024)
    source = read_regular(PACKAGE / "Tests/VaultCoreTests/SignatureCorpus.swift").decode()
    rows = extract_corpus(raw, source)
    save_evidence(state, report, "corpus-primary.json", raw)
    table = "\n".join("|".join(map(str, row)) for row in rows).encode()
    save_evidence(state, report, "corpus-table.txt", table)
    for platform in ("native", "linux"):
        output = read_regular(state["evidence"] / (platform + "-baseline-test.log")).decode()
        validate_no_fixture_output(output)
        value = signature_result(output, "macos" if platform == "native" else "linux", rows)
        save_evidence(state, report, "corpus-" + platform + ".json", compact(value))
    save_evidence(state, report, "cofactor-matrix.json", compact({"schema": "membership-cofactor-v1", "status": "unmeasured",
                  "gate": "future_independent_multiwriter_authority"}))
    bodies = prepare_oracle(run, state, report)
    report["custody"], report["exchange_errors"], report["exchange_snapshots"] = {}, {}, {}
    directions = [exchange_direction(run, state, report, platform, bodies) for platform in ("native", "linux")]
    write_summary(state, report, directions)


def replay_steps(root, report):
    """One sequential replay of captured commands. No subprocess or lifecycle is copied."""
    steps, position = report["steps"], [0]
    require(isinstance(steps, list) and len({s["step"] for s in steps}) == len(steps), "duplicate_step")
    def run(label, command, timeout=900, required=True, scan=True):
        require(position[0] < len(steps), "baseline_step_missing")
        step = steps[position[0]]
        position[0] += 1
        run.steps.append(step)
        closed(step, ("step", "command", "cwd", "timeout_seconds", "exit_code", "runner_error", "log", "log_record",
                      "secret_output_scanned", "secret_output_detected"), "baseline_step_invalid")
        require(step["step"] == label and step["command"] == list(command) and step["cwd"] == str(ROOT)
                and type(step["timeout_seconds"]) is int and step["timeout_seconds"] == timeout, "baseline_command_mismatch")
        require(step["runner_error"] is None and type(step["exit_code"]) is int, "baseline_runner_failed")
        require(step["log"] == label + ".log" and re.fullmatch(r"[a-z0-9_-]+", label), "invalid_log_path")
        data = read_evidence_reference(root, {"path": step["log"], **step["log_record"]})
        text = data.decode("utf-8")
        leak = bool(scan and portable.rejects_secret_output(text, SENTINELS))
        require(type(step["secret_output_scanned"]) is bool and step["secret_output_scanned"] == scan
                and type(step["secret_output_detected"]) is bool and step["secret_output_detected"] == leak, "baseline_scan_policy_mismatch")
        require(not leak, "synthetic_secret_output")
        if required:
            require(step["exit_code"] == 0, "baseline_step_failed")
        return step["exit_code"], text
    run.steps = []
    return run, position


def validate_u1_before_write(report, state):
    validate_u1_baseline_report(state["evidence"], report, report["snapshot"])


def verify_u1_baseline(path, expected):
    data = read_regular(path, 4 * 1024 * 1024)
    require(not path.parent.is_symlink(), "baseline_path_invalid")
    validate_u1_baseline_report(path.parent.absolute(), strict_document(data), expected)
    return {"path": str(path.absolute()), "sha256": sha(data), "size": len(data)}


def validate_u1_baseline_report(root, report, expected):
    closed(report, ("schema", "kind", "snapshot", "steps", "runtime", "image", "scope", "network", "python", "log_encoding",
                    "leak_scan", "fixture_environment", "artifacts", "owner", "container_name", "suites", "identifier", "custody",
                    "exchange_errors", "exchange_snapshots", "summary", "failure", "cleanup", "artifact_check_error",
                    "source_check_error", "final_snapshot", "source_unchanged", "validation_error", "status"), "baseline_record_invalid")
    require(report.get("schema") == U1_SCHEMA and report.get("kind") == "baseline" and report.get("status") == "pass"
            and report.get("snapshot") == expected and report.get("final_snapshot") == expected
            and report.get("source_unchanged") is True and report.get("image") == IMAGE
            and all(report.get(k) is None for k in ("failure", "source_check_error", "artifact_check_error", "validation_error"))
            and report.get("cleanup") == {"status": "removed"}, "matching_passed_u1_baseline_required")
    require(report.get("python") == {"executable": sys.executable, "version": sys.version, "optimized": not __debug__},
            "baseline_python_mismatch")
    require(re.fullmatch(r"[0-9a-f]{32}", report["owner"]) and report["container_name"] == "agent-vault-membership-" + report["owner"],
            "baseline_owner_invalid")
    artifact_names = {"oracle-public.json", "corpus-primary.json", "corpus-table.txt", "corpus-native.json", "corpus-linux.json",
                      "cofactor-matrix.json", "exchange-summary.json"}
    artifacts = report["artifacts"]
    require(set(artifacts) == artifact_names and all(artifacts[n]["path"] == n for n in artifact_names), "baseline_artifact_set_invalid")
    reopened = {n: read_evidence_reference(root, reference) for n, reference in artifacts.items()}
    require(reopened["cofactor-matrix.json"] == compact({"schema": "membership-cofactor-v1", "status": "unmeasured",
            "gate": "future_independent_multiwriter_authority"}), "cofactor_status_invalid")
    rows = extract_corpus(reopened["corpus-primary.json"], read_regular(PACKAGE / "Tests/VaultCoreTests/SignatureCorpus.swift").decode())
    require(reopened["corpus-table.txt"] == "\n".join("|".join(map(str, row)) for row in rows).encode(), "corpus_table_mismatch")
    run, position = replay_steps(root, report)
    state = {"evidence": root, "package": PACKAGE, "owner": report["owner"], "name": report["container_name"],
             "container_attempted": False, "runtime": {}}
    run("guard", [sys.executable, str(ROOT / "scripts/verify-boundaries.py")])
    runtime_and_container(run, state)
    require(state["runtime"] == report["runtime"] and state["identifier"] == report["identifier"], "baseline_runtime_mismatch")
    for platform in ("native", "linux"):
        result = test_package(run, state, platform, "baseline", list(U1_NAMES), unit="u1")
        require(report["suites"][platform] == result, "baseline_suite_mismatch")
        output = read_regular(root / (result["test_step"] + ".log")).decode()
        validate_no_fixture_output(output)
        value = signature_result(output, "macos" if platform == "native" else "linux", rows)
        require(reopened["corpus-" + platform + ".json"] == compact(value), "signature_artifact_mismatch")
    run("oracle_version", [OPENSSL, "version"], timeout=30)
    keys = {}
    for name, (kind, _) in zip(ORACLE_KEYS, ORACLE_SEEDS):
        _, output = run("oracle_" + name.replace("-", "_"), [OPENSSL, "pkey", "-inform", "DER", "-in",
                        str(root / "oracle-temporary" / (name + ".der")), "-pubout"], timeout=30)
        keys[name] = public_key_from_pem(output, kind)
    require(reopened["oracle-public.json"] == compact({name: key.hex() for name, key in keys.items()}), "oracle_artifact_mismatch")
    require(not (root / "oracle-temporary").exists(), "oracle_temporary_not_removed")
    bodies = fixture_bodies(keys)
    exchange = {"custody": {}, "exchange_errors": {}, "exchange_snapshots": {}}
    directions = [exchange_direction(run, state, exchange, producer, bodies, replay=True)
                  for producer in ("native", "linux")]
    require(report["custody"] == exchange["custody"], "baseline_custody_mismatch")
    require(report["exchange_errors"] == exchange["exchange_errors"], "baseline_exchange_error")
    require(report["exchange_snapshots"] == exchange["exchange_snapshots"], "baseline_exchange_snapshot_mismatch")
    cleanup_container(run, state["identifier"], state["owner"])
    require(position[0] == len(report["steps"]), "baseline_extra_steps")
    summary = parse_exchange_json(reopened["exchange-summary.json"])
    require(summary == summary_document(expected, artifacts, directions), "exchange_summary_mismatch")
    require(report["summary"] == artifacts["exchange-summary.json"], "exchange_summary_reference_mismatch")
    return summary


def mutation_source(identifier, package):
    """One specification and source/patch construction for recording and replay."""
    import difflib
    spec = MUTATIONS[identifier]
    path = package / spec["file"]
    original = read_regular(path)
    require(original.count(spec["old"]) == 1,
            "n1_mutation_anchor_changed" if identifier == "N1" else "u1_mutation_anchor_changed")
    changed = original.replace(spec["old"], spec["new"])
    patch = "".join(difflib.unified_diff(original.decode().splitlines(True), changed.decode().splitlines(True),
                                      fromfile=spec["file"], tofile=spec["file"])).encode()
    manifest, digest = {}, hashlib.sha256()
    for name in package_snapshot(package)["files"]:
        data = changed if name == spec["file"] else read_regular(package / name)
        manifest[name] = {"size": len(data), "sha256": sha(data)}
        digest.update(name.encode() + b"\0" + data + b"\0")
    record = {"target": spec["file"], "original_sha256": sha(original), "mutated_sha256": sha(changed),
              "patch": identifier.lower() + ".patch", "patch_record": {"sha256": sha(patch), "size": len(patch)}}
    if identifier == "N1":
        record.update(removed_sites=1, test=TARGET, expected_error="Expected fixed codec error",
                      assertion="badAuthentication", source_location=list(n1_location(package)))
    else:
        record.update(id=identifier, changed_sites=1, detector=U1_DETECTORS[identifier])
    return path, original, changed, record, patch, {"files": manifest, "sha256": digest.hexdigest()}


def expected_mutation(identifier):
    _, _, _, record, patch, snapshot = mutation_source(identifier, PACKAGE)
    return record, patch, snapshot


def validate_u1_controls(report, state):
    expected = report["snapshot"]
    closed(report, ("schema", "kind", "snapshot", "steps", "runtime", "image", "scope", "network", "python", "log_encoding",
                    "leak_scan", "fixture_environment", "artifacts", "owner", "container_name", "identifier", "controls", "n1",
                    "mutations", "baseline", "owned_copy_initial", "owned_copy_final", "baseline_check_error", "copy_check_error",
                    "failure", "cleanup", "artifact_check_error", "source_check_error", "final_snapshot", "source_unchanged",
                    "validation_error", "status"), "controls_record_invalid")
    require(report["schema"] == U1_SCHEMA and report["kind"] == "controls" and report["status"] == "pass"
            and report["final_snapshot"] == expected and report["source_unchanged"] is True
            and all(report.get(k) is None for k in ("failure", "source_check_error", "artifact_check_error", "validation_error",
                                                   "baseline_check_error", "copy_check_error"))
            and report["cleanup"] == {"status": "removed"}, "u1_controls_not_complete")
    require(verify_u1_baseline(Path(report["baseline"]["path"]), expected) == report["baseline"], "controls_baseline_changed")
    baseline = strict_document(read_regular(Path(report["baseline"]["path"]), 4 * 1024 * 1024))
    require(report["runtime"] == baseline["runtime"] and report["python"] == baseline["python"], "controls_baseline_runtime_changed")
    initial = expected["package"]["combined"]
    require(report["owned_copy_initial"] == initial and report["owned_copy_final"] == initial
            and package_snapshot(state["package"]) == initial, "owned_copy_not_restored")
    identifiers = [*U1_MUTATIONS, "N1"]
    require(set(report["mutations"]) == set(identifiers) and set(report["artifacts"]) == {i.lower() + ".patch" for i in identifiers},
            "u1_control_matrix_incomplete")
    root = state["evidence"]
    run, position = replay_steps(root, report)
    replay_state = {"evidence": root, "package": state["package"], "owner": report["owner"], "name": report["container_name"],
                    "runtime": {}, "container_attempted": False, "report_steps": run.steps}
    runtime_and_container(run, replay_state)
    require(report["runtime"] == replay_state["runtime"] and report["identifier"] == replay_state["identifier"], "controls_runtime_mismatch")
    require([(row["id"], row["platform"]) for row in report["controls"]] == [(i, p) for i in U1_MUTATIONS for p in ("native", "linux")]
            and [row["platform"] for row in report["n1"]] == ["native", "linux"], "u1_control_matrix_incomplete")
    for identifier in identifiers:
        mutation, patch, mutant_snapshot = expected_mutation(identifier)
        require(compact(report["mutations"][identifier]) == compact(mutation), "u1_mutation_evidence_mismatch")
        require(read_evidence_reference(root, report["artifacts"][identifier.lower() + ".patch"]) == patch, "u1_patch_mismatch")
        for platform in ("native", "linux"):
            row = next(r for r in (report["n1"] if identifier == "N1" else report["controls"])
                       if r["platform"] == platform and (identifier == "N1" or r["id"] == identifier))
            require(all(row[k] is None for k in ("failure", "restore_error", "restored_test_error")), "u1_control_error")
            require(row["mutant_source"] == mutant_snapshot and row["restored_source"] == initial, "u1_control_restore_mismatch")
            names = [TARGET] if identifier == "N1" else [U1_DETECTORS[identifier]["test"]]
            control_id = None if identifier == "N1" else identifier
            for phase in ("before", "mutant", "restored"):
                result = test_package(run, replay_state, platform, identifier.lower() + "-" + phase, names,
                                      mutant=phase == "mutant", unit="u1", control_id=control_id)
                require(row[{"before": "baseline", "mutant": "mutant", "restored": "restored"}[phase]] == result,
                        "u1_control_runtime_mismatch")
            require(row["status"] == row["mutant"]["status"], "u1_control_status_mismatch")
    cleanup_container(run, replay_state["identifier"], replay_state["owner"])
    require(position[0] == len(report["steps"]), "controls_extra_steps")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", choices=("u0", "u1"), default="u0")
    args = parser.parse_args()
    state, report, run = recording("baseline", unit=args.unit)
    failure = None
    try:
        if args.unit == "u1":
            u1_baseline(run, state, report)
        else:
            run("guard", [sys.executable, str(ROOT / "scripts/verify-boundaries.py")])
            runtime_and_container(run, state)
            names = suite_names(PACKAGE)
            report["suites"] = {}
            for platform in ("native", "linux"):
                report["suites"][platform] = test_package(run, state, platform, "baseline", names)
    except BaseException as error:
        failure = error
    failure = finish(report, state, run, report["snapshot"], failure, unit=args.unit)
    if failure is not None:
        raise failure
    print(state["evidence"] / "result.json")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        with owned.interrupt_on_termination():
            main()
    except VerificationFailure as error:
        print("membership: " + str(error), file=sys.stderr)
        raise SystemExit(1)
