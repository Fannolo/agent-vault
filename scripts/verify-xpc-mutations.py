#!/usr/bin/env python3
"""Show that each XPC defense is what makes its verify-xpc scenario pass.

Copies the source tree (without .build or .git) to a private temporary directory,
disables one defense at a time there, reruns scripts/verify-xpc.py and checks that
the expected scenarios fail. Two mutations remove one of the two server requirement
layers; they must keep every scenario passing, because each layer enforces alone.
The working tree is never modified.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SERVER = "Sources/AgentVaultIPC/VaultXPCServer.swift"
CLIENT = "Sources/AgentVaultIPC/VaultXPCClients.swift"
ROLE_SCENARIOS = {"bridge cannot call the admin service", "human app cannot call the read service",
                  "copied bridge signing identifier is refused"}

MUTATIONS = [
    ("no server UID check", SERVER,
     "guard uid == configuration.allowedUID, uid != 0 else { return false }", "_ = uid",
     {"broker refuses an unexpected kernel UID", "only the genuine broker's handlers ran, each with the bound UID"}),
    ("no server code requirements", SERVER,
     ("readListener.setConnectionCodeSigningRequirement(configuration.readRequirement)\n"
      "        adminListener.setConnectionCodeSigningRequirement(configuration.adminRequirement)",
      "connection.setCodeSigningRequirement(admin ? configuration.adminRequirement : configuration.readRequirement)"),
     ("", ""), ROLE_SCENARIOS),
    ("listener requirement only", SERVER,
     "connection.setCodeSigningRequirement(admin ? configuration.adminRequirement : configuration.readRequirement)",
     "", set()),
    ("connection requirement only", SERVER,
     ("readListener.setConnectionCodeSigningRequirement(configuration.readRequirement)\n"
      "        adminListener.setConnectionCodeSigningRequirement(configuration.adminRequirement)",),
     ("",), set()),
    ("no client broker requirement", CLIENT,
     "connection.setCodeSigningRequirement(configuration.brokerRequirement)", "",
     {"bridge refuses a spoofed broker", "human app refuses a spoofed broker",
      "only the genuine broker's handlers ran, each with the bound UID"}),
    ("requests not gated on the broker probe", CLIENT,
     "if let failure = await link.verified.value {", "if false, let failure = await link.verified.value {",
     {"only the genuine broker's handlers ran, each with the bound UID"}),
    ("no client broker UID check", CLIENT,
     "guard UInt32(connection.effectiveUserIdentifier) == brokerUID else {",
     "guard true else {",
     {"bridge refuses a genuine broker with an unexpected kernel UID",
      "human app refuses a genuine broker with an unexpected kernel UID"}),
    ("no per-connection concurrency limit", SERVER,
     "guard connectionInFlight.acquire() else", "guard connectionInFlight.acquire() || true else",
     {"excess concurrency on one connection returns busy"}),
]


def mutate(path, old, new):
    text = path.read_text()
    for before, after in zip(*((old, new) if isinstance(old, tuple) else ((old,), (new,)))):
        assert text.count(before) == 1, f"mutation anchor not unique in {path.name}: {before[:60]}"
        text = text.replace(before, after)
    path.write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence", type=Path, help="retain each mutation's cleanup and scenario results")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="agentvault-xpc-mutations-"))
    tree = work / "tree"
    report = []
    try:
        shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(".build", ".git", ".swiftpm", "dist", "__pycache__"))
        for name, relative, old, new, expected in MUTATIONS:
            target = tree / relative
            original = target.read_text()
            mutate(target, old, new)
            evidence = work / "evidence.json"
            evidence.unlink(missing_ok=True)
            result = subprocess.run([sys.executable, str(tree / "scripts/verify-xpc.py"), "--evidence", str(evidence)],
                                    cwd=tree, capture_output=True, text=True)
            target.write_text(original)
            if not evidence.exists():
                report.append({"mutation": name, "ok": False, "failed": ["harness produced no evidence"],
                               "harnessExitCode": result.returncode, "diagnostics": (result.stdout + result.stderr)[-4000:]})
            else:
                record = json.loads(evidence.read_text())
                failed = {r["scenario"] for r in record["results"] if not r["passed"]}
                clean = all(v in ("removed", True) for v in record["cleanup"].values())
                report.append({"mutation": name, "ok": failed == expected and clean,
                               "failed": sorted(failed), "expected": sorted(expected),
                               "harnessExitCode": result.returncode, "cleanup": record["cleanup"]})
            print(f"{'PASS' if report[-1]['ok'] else 'FAIL'}  {name}: failed={report[-1]['failed']}")
            if not report[-1]["ok"]:
                print("diagnostics:", json.dumps(report[-1], sort_keys=True))
    finally:
        shutil.rmtree(work, ignore_errors=True)
        # SwiftPM leaves empty lock files in TMPDIR named after the scratch path.
        mangled = str(tree.resolve()).replace("/", "_")
        for lock in Path(tempfile.gettempdir()).glob(f"{mangled}*.lock"):
            lock.unlink(missing_ok=True)
    if args.evidence:
        args.evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not all(r["ok"] for r in report):
        sys.exit(1)
    print(f"{len(report)}/{len(report)} mutations behaved as expected")


if __name__ == "__main__":
    main()
