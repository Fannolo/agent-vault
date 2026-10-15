#!/usr/bin/env python3
"""Run synthetic checks and record their exact source and log hashes. No installation.

Raw logs and auxiliary JSON stay in a new run directory below verification-logs/, which
is git-ignored and never published automatically: logs may hold local paths. Records
refer to them by repository-relative path and SHA-256. Earlier runs are never replaced.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
LOGS = "verification-logs"
CHECKS = {
    "swift": ["swift", "test", "--force-resolved-versions", "-j", "4"],
    "mcp": [sys.executable, "scripts/verify-mcp.py"],
    "mcp-keychain": [sys.executable, "scripts/verify-mcp.py", "--keychain-demo"],
    "boundaries": [sys.executable, "scripts/verify-boundaries.py"],
    "installer": [sys.executable, "scripts/verify-installer.py"],
    "release-entitlements": [sys.executable, "-I", "deploy/tests/test_release.py"],
    "xpc-cleanup": [sys.executable, "-I", "deploy/tests/test_xpc_cleanup.py"],
    "recorder": [sys.executable, "-I", "deploy/tests/test_recorder.py"],
    "webhost-cleanup": [sys.executable, "-I", "deploy/tests/test_webhost_link_mutations.py"],
    "webhost-mutations": [sys.executable, "scripts/verify-webhost-link-mutations.py"],
    "webhost-real": ["swift", "test", "--force-resolved-versions", "-j", "4", "--filter", "AgentVaultWebHostTests"],
    "webhost-browser-mutations": [sys.executable, "scripts/verify-webhost-mutations.py"],
    "xpc": [sys.executable, "scripts/verify-xpc.py"],
    "xpc-mutations": [sys.executable, "scripts/verify-xpc-mutations.py"],
    "native-keychain": ["swift", "test", "--force-resolved-versions", "-j", "4", "--filter",
                        "privateKeychainRoundTripUsesOnlyExplicitDatabaseWhenEnabled|nativeKeychainRoundTripWhenExplicitlyEnabled"],
}
EVIDENCE = {"xpc", "xpc-mutations"}
DETAIL_LOGS = {"webhost-mutations", "webhost-browser-mutations"}
CHROMIUM_CHECKS = {"webhost-real", "webhost-browser-mutations"}


def artifact(path):
    """Ignored output the checks themselves produce. Any other ignored path is part of the snapshot."""
    return path in (LOGS + "/", ".build/") or Path(path).name == "__pycache__"


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_snapshot():
    paths = git("ls-files", "-z").decode().split("\0")
    status = [entry for entry in git("status", "--porcelain=v1", "-z", "--untracked-files=all",
                                     "--ignored=matching").decode().split("\0") if entry]
    return {
        "commit": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "dirty": any(not entry.startswith("!! ") for entry in status),
        "ignoredPaths": sorted(entry[3:] for entry in status if entry.startswith("!! ") and not artifact(entry[3:])),
        "trackedFileSha256": {name: sha256((ROOT / name).read_bytes()) for name in paths
                              if name and (ROOT / name).is_file()},
    }


def build_cache(checks):
    build = ROOT / ".build"
    state = {"buildDirectoryBefore": "symlink" if build.is_symlink() else "directory" if build.is_dir()
             else "absent" if not build.exists() else "other",
             "note": "Only .build presence is recorded. A present directory means incremental reuse, "
                     "not a clean build; global SwiftPM and compiler caches are not inspected."}
    if any(CHECKS[name][0] == "swift" for name in checks):
        try:
            state["swiftVersion"] = subprocess.run(["swift", "--version"], cwd=ROOT, capture_output=True,
                                                   text=True, timeout=60).stdout.strip()
        except (OSError, subprocess.SubprocessError) as error:
            state["swiftVersion"] = f"unavailable: {type(error).__name__}"
    return state


def run_check(name, run_dir, chromium=None):
    log = run_dir / (name + ".log")
    relative = run_dir.relative_to(ROOT)
    argv = list(CHECKS[name])
    evidence = run_dir / (name + ".json") if name in EVIDENCE else None
    if evidence:
        argv += ["--evidence", str(relative / evidence.name)]
    detail = run_dir / (name + ".details.log") if name in DETAIL_LOGS else None
    if detail:
        argv += ["--log", str(relative / detail.name)]
    env = os.environ.copy()
    env.pop("AGENT_VAULT_KEYCHAIN_TEST", None)
    env.pop("AGENT_VAULT_NETWORK_TEST", None)
    env.pop("AGENT_VAULT_TEST_CHROMIUM", None)
    if name in CHROMIUM_CHECKS:
        env["AGENT_VAULT_TEST_CHROMIUM"] = str(chromium)
    if name == "native-keychain":
        env["AGENT_VAULT_KEYCHAIN_TEST"] = "1"
    check = {"name": name, "argv": argv, "log": str(relative / log.name)}
    started = time.monotonic()
    with log.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        try:
            check["exitCode"] = subprocess.run(argv, cwd=ROOT, env=env, stdout=handle,
                                               stderr=subprocess.STDOUT).returncode
        except OSError as error:
            check["exitCode"] = None
            check["error"] = f"could not start: {type(error).__name__}: {error.strerror}"
    check["elapsedSeconds"] = round(time.monotonic() - started, 3)
    content = log.read_bytes()
    check["logSha256"] = sha256(content)
    lines = content.decode(errors="replace").splitlines()
    skipped = [line for line in lines if line.startswith(("➜ Test ", "➜ Suite ")) and " skipped:" in line]
    if skipped or any(line.startswith("✔ Test run") for line in lines):
        check["swiftTesting"] = {"reportedSkipCount": len(skipped), "skipReports": skipped}
    check["observedSummary"] = [line for line in lines
                                if line.startswith(("✔ Test run", "Ran ", "OK", "FAILED", "PASS", "FAIL",
                                                    "tests ", "mutation ", "verify-installer:", "➜ Test ", "➜ Suite "))][-64:]
    if evidence:
        if not evidence.exists():
            check.setdefault("error", "the check wrote no evidence file")
        else:
            evidence.chmod(0o600)
            data = evidence.read_bytes()
            check["evidenceFile"] = {"path": str(relative / evidence.name), "sha256": sha256(data)}
            try:
                check["evidence"] = json.loads(data)
            except ValueError as error:
                check.setdefault("error", f"evidence is not JSON: {error}")
    if detail:
        if not detail.is_file():
            check.setdefault("error", "the check wrote no detail log")
        else:
            detail.chmod(0o600)
            check["detailLog"] = {"path": str(relative / detail.name),
                                  "sha256": sha256(detail.read_bytes())}
    check["passed"] = check["exitCode"] == 0 and "error" not in check
    return check


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--checks", nargs="+", choices=CHECKS, required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--chromium", type=Path, help="explicit synthetic-fixture headless shell; opt-in checks only")
    args = parser.parse_args(argv)
    chromium = None
    if CHROMIUM_CHECKS.intersection(args.checks):
        if args.chromium is None or not args.chromium.is_file() or not os.access(args.chromium, os.X_OK):
            parser.error("browser checks require --chromium pointing at an executable fixture binary")
        chromium = args.chromium.resolve()
    before = source_snapshot()
    if before["dirty"]:
        parser.error("commit the source checkpoint before recording verification")
    output = args.record.resolve()
    if output.exists():
        parser.error("choose a new record path; previous evidence must be preserved")
    if subprocess.run(["git", "check-ignore", "-q", LOGS + "/"], cwd=ROOT).returncode != 0:
        parser.error(f"{LOGS}/ must be git-ignored so retained logs are never committed")
    started = datetime.now(timezone.utc)
    logs = ROOT / LOGS
    logs.mkdir(mode=0o700, exist_ok=True)
    logs.chmod(0o700)
    run_dir = logs / f"{started.strftime('%Y%m%dT%H%M%S.%fZ')}-{output.stem}"
    run_dir.mkdir(mode=0o700, exist_ok=False)
    record = {
        "scope": "Local synthetic checks; not installed isolation, production browser or notarization proof",
        "clockNote": "Wall-clock observations are local metadata, not an attestation of command order",
        "startedAt": started.isoformat(),
        "source": before,
        "buildCache": build_cache(args.checks),
        "logDirectory": str(run_dir.relative_to(ROOT)),
        "logNote": "Raw logs are retained locally in a git-ignored directory and are not published",
        "checks": [],
    }
    if chromium:
        binary = chromium.read_bytes()
        record["chromiumFixture"] = {"fileName": chromium.name, "sizeBytes": len(binary),
                                     "sha256": sha256(binary),
                                     "note": "Only executable bytes are hashed; adjacent resources and OS state "
                                             "are not inventoried. Interactive same-UID fixture, not installed proof."}
    try:
        for name in args.checks:
            record["checks"].append(run_check(name, run_dir, chromium))
            check = record["checks"][-1]
            print(f"{name}: exit {check['exitCode']}; passed {check['passed']}; log {check['log']}", flush=True)
            if not check["passed"]:
                break
    finally:
        record["sourceUnchanged"] = before == source_snapshot()
        if chromium:
            try:
                record["chromiumFixture"]["unchanged"] = sha256(chromium.read_bytes()) == record["chromiumFixture"]["sha256"]
            except OSError:
                record["chromiumFixture"]["unchanged"] = False
        record["finishedAt"] = datetime.now(timezone.utc).isoformat()
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x") as handle:
            handle.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(f"record: {output}", flush=True)
    return 0 if (record["sourceUnchanged"] and record.get("chromiumFixture", {}).get("unchanged", True)
                 and all(x["passed"] for x in record["checks"])) else 1


if __name__ == "__main__":
    sys.exit(main())
