#!/usr/bin/env python3
"""Run synthetic checks and record their exact source and log hashes. No installation."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CHECKS = {
    "swift": ["swift", "test", "--force-resolved-versions", "-j", "4"],
    "mcp": [sys.executable, "scripts/verify-mcp.py"],
    "boundaries": [sys.executable, "scripts/verify-boundaries.py"],
    "installer": [sys.executable, "scripts/verify-installer.py"],
    "release-entitlements": [sys.executable, "-I", "deploy/tests/test_release.py"],
    "xpc": [sys.executable, "scripts/verify-xpc.py"],
    "xpc-mutations": [sys.executable, "scripts/verify-xpc-mutations.py"],
    "native-keychain": ["swift", "test", "--force-resolved-versions", "-j", "4", "--filter",
                        "privateKeychainRoundTripUsesOnlyExplicitDatabaseWhenEnabled|nativeKeychainRoundTripWhenExplicitlyEnabled"],
}


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_snapshot():
    paths = git("ls-files", "-z").decode().split("\0")
    return {
        "commit": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "dirty": bool(git("status", "--porcelain")),
        "trackedFileSha256": {name: sha256((ROOT / name).read_bytes()) for name in paths
                              if name and (ROOT / name).is_file()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checks", nargs="+", choices=CHECKS, required=True)
    parser.add_argument("--record", type=Path, required=True)
    args = parser.parse_args()
    before = source_snapshot()
    if before["dirty"]:
        parser.error("commit the source checkpoint before recording verification")
    output = args.record.resolve()
    if output.exists():
        parser.error("choose a new record path; previous evidence must be preserved")
    logs = Path(tempfile.mkdtemp(prefix="agent-vault-verification-"))
    record = {
        "scope": "Local synthetic checks; not installed isolation, production browser or notarization proof",
        "clockNote": "Wall-clock observations are local metadata, not an attestation of command order",
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "source": before,
        "checks": [],
    }
    for name in args.checks:
        log = logs / (name + ".log")
        env = os.environ.copy()
        env.pop("AGENT_VAULT_KEYCHAIN_TEST", None)
        env.pop("AGENT_VAULT_NETWORK_TEST", None)
        if name == "native-keychain":
            env["AGENT_VAULT_KEYCHAIN_TEST"] = "1"
        started = time.monotonic()
        with log.open("wb") as handle:
            result = subprocess.run(CHECKS[name], cwd=ROOT, env=env, stdout=handle,
                                    stderr=subprocess.STDOUT)
        content = log.read_bytes()
        lines = content.decode(errors="replace").splitlines()
        summaries = [line for line in lines if line.startswith(("✔ Test run", "Ran ", "OK", "FAILED",
                     "PASS", "FAIL", "tests ", "mutation ", "verify-installer:"))]
        record["checks"].append({"name": name, "argv": CHECKS[name], "exitCode": result.returncode,
                                 "elapsedSeconds": round(time.monotonic() - started, 3),
                                 "logSha256": sha256(content), "observedSummary": summaries[-64:]})
        print(f"{name}: exit {result.returncode}; log {log}", flush=True)
        if result.returncode:
            break
    record["sourceUnchanged"] = before == source_snapshot()
    record["finishedAt"] = datetime.now(timezone.utc).isoformat()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"record: {output}", flush=True)
    return 0 if record["sourceUnchanged"] and all(x["exitCode"] == 0 for x in record["checks"]) else 1


if __name__ == "__main__":
    sys.exit(main())
