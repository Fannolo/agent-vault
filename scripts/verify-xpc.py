#!/usr/bin/env python3
"""Cross-process proof of the Agent Vault XPC identity checks with synthetic data.

Builds the fixture binaries, signs private copies ad hoc with distinct identifiers, and
starts temporary per-user launch agents whose labels are unique to this run. The plists
live in a private temporary directory, never in ~/Library/LaunchAgents. Cleanup boots out
exactly the labels this run bootstrapped, confirms they are gone and deletes the directory.

Every process runs as the invoking user. This proves code-requirement and message checks
between real processes; it does not prove separation by a dedicated broker UID.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
UID = os.getuid()
DOMAIN = f"gui/{UID}"
ID_PREFIX = "dev.agentvault.fixture"


class Harness:
    def __init__(self):
        self.labels = []
        self.work = Path(tempfile.mkdtemp(prefix="agentvault-xpc-"))
        os.chmod(self.work, 0o700)
        self.run_id = secrets.token_hex(4)
        self.results = []
        self.cleanup_record = {}

    # Build and signing

    def build(self):
        for product in ("agent-vault-ipc-fixture", "agent-vault-ipc-impostor"):
            subprocess.run(["swift", "build", "--product", product], cwd=ROOT, check=True,
                           stdout=subprocess.DEVNULL)
        bin_dir = Path(subprocess.run(["swift", "build", "--show-bin-path"], cwd=ROOT, check=True,
                                      capture_output=True, text=True).stdout.strip())
        genuine, impostor = bin_dir / "agent-vault-ipc-fixture", bin_dir / "agent-vault-ipc-impostor"
        self.binaries = {
            "broker": self.sign(genuine, "broker", f"{ID_PREFIX}.broker"),
            "bridge": self.sign(genuine, "bridge", f"{ID_PREFIX}.bridge"),
            "app": self.sign(genuine, "app", f"{ID_PREFIX}.app"),
            # Different code that copies the bridge's and broker's signing identifiers.
            "impostor-bridge": self.sign(impostor, "impostor-bridge", f"{ID_PREFIX}.bridge"),
            "impostor-broker": self.sign(impostor, "impostor-broker", f"{ID_PREFIX}.broker"),
        }

    def sign(self, source, name, identifier):
        target = self.work / name
        shutil.copy2(source, target)
        subprocess.run(["codesign", "--force", "--sign", "-", "--identifier", identifier, str(target)],
                       check=True, capture_output=True)
        info = subprocess.run(["codesign", "-d", "--verbose=4", str(target)], check=True,
                              capture_output=True, text=True).stderr
        cdhash = re.search(r"^CDHash=([0-9a-f]{40})$", info, re.M).group(1)
        signed_id = re.search(r"^Identifier=(.+)$", info, re.M).group(1)
        assert re.search(r"^Signature=adhoc$", info, re.M), "fixtures must be ad hoc signed"
        return {"path": str(target), "identifier": signed_id, "cdhash": cdhash,
                "requirement": f'identifier "{signed_id}" and cdhash H"{cdhash}"'}

    # Configuration and launch agents

    def config(self, name, services, broker="broker", allowed_uid=UID, development=True, broker_uid=UID):
        prefix = f"dev.agentvault.ipcproof.{self.run_id}.{services}"
        value = {
            "readServiceName": f"{prefix}.read", "adminServiceName": f"{prefix}.admin",
            "brokerRequirement": self.binaries[broker]["requirement"],
            "readRequirement": self.binaries["bridge"]["requirement"],
            "adminRequirement": self.binaries["app"]["requirement"],
            "brokerUID": broker_uid, "allowedUID": allowed_uid, "development": development,
        }
        path = self.work / f"{name}.json"
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return str(path)

    def launch(self, suffix, binary, config, *extra):
        label = f"dev.agentvault.ipcproof.{self.run_id}.{suffix}"
        record = self.work / f"{suffix}.record"
        services = json.loads(Path(config).read_text())
        plist = {
            "Label": label,
            "ProgramArguments": [self.binaries[binary]["path"], "serve", "--config", config,
                                 "--record", str(record), *extra],
            "MachServices": {services["readServiceName"]: True, services["adminServiceName"]: True},
            "StandardErrorPath": str(self.work / f"{suffix}.stderr"),
            "ProcessType": "Background",
        }
        path = self.work / f"{label}.plist"
        path.write_bytes(plistlib.dumps(plist))
        self.labels.append(label)
        subprocess.run(["launchctl", "bootstrap", DOMAIN, str(path)], check=True, capture_output=True)
        return record

    def cleanup(self):
        for label in self.labels:
            subprocess.run(["launchctl", "bootout", f"{DOMAIN}/{label}"], capture_output=True)
            gone = subprocess.run(["launchctl", "print", f"{DOMAIN}/{label}"], capture_output=True).returncode != 0
            self.cleanup_record[label] = "removed" if gone else "STILL LOADED"
        self.labels = []
        shutil.rmtree(self.work, ignore_errors=True)
        self.cleanup_record["work_dir_removed"] = not self.work.exists()

    # Scenarios

    def invoke(self, binary, *args):
        completed = subprocess.run([self.binaries[binary]["path"], *args], capture_output=True, text=True,
                                   timeout=60)
        lines = completed.stdout.strip().splitlines()
        return json.loads(lines[-1]) if lines else {"outcome": f"exit_{completed.returncode}"}

    def expect(self, name, result, check):
        passed = bool(check(result))
        self.results.append({"scenario": name, "passed": passed, "result": result})
        print(f"{'PASS' if passed else 'FAIL'}  {name}: {json.dumps(result, sort_keys=True)}")


def run(harness):
    h = harness
    h.build()
    main = h.config("main", "main")
    wrong_broker_uid = h.config("wrong-broker-uid", "main", broker_uid=UID + 1)
    uid_server = h.config("uid-server", "uid", allowed_uid=UID + 1)
    uid_client = h.config("uid-client", "uid")
    spoof_server = h.config("spoof-server", "spoof", broker="impostor-broker")
    spoof_client = h.config("spoof-client", "spoof")
    production_same_uid = h.config("production-same-uid", "prod", development=False)

    main_record = h.launch("main", "broker", main, "--delay-ms", "500", "--per-connection", "4")
    uid_record = h.launch("uid", "broker", uid_server)
    spoof_record = h.launch("spoof", "impostor-broker", spoof_server)

    bridge, app, impostor = h.binaries["bridge"], h.binaries["app"], h.binaries["impostor-bridge"]
    h.expect("impostor copies the bridge signing identifier with a different cdhash",
             {"bridge": [bridge["identifier"], bridge["cdhash"]], "impostor": [impostor["identifier"], impostor["cdhash"]]},
             lambda r: r["bridge"][0] == r["impostor"][0] and r["bridge"][1] != r["impostor"][1])

    h.expect("bridge reads accounts", h.invoke("bridge", "read", "--config", main, "--op", "accounts"),
             lambda r: r["outcome"] == "ok" and r["accounts"] == 1)
    h.expect("broker binds the bridge's kernel UID", h.invoke("bridge", "read", "--config", main, "--op", "run"),
             lambda r: r["outcome"] == "ok" and r["login"] == f"uid-{UID}")
    h.expect("human app completes snapshot, begin, authorize and replay refusal",
             h.invoke("app", "admin", "--config", main),
             lambda r: r == {"outcome": "ok", "snapshotUID": UID, "pendingStatus": "approved", "audit": 1,
                             "enroll": "fixture_holds_no_credentials",
                             "authorize": "applied", "replay": "unknown_challenge"})
    h.expect("bridge cannot call the admin service", h.invoke("bridge", "admin", "--config", main),
             lambda r: r["outcome"] == "connection_failed")
    h.expect("human app cannot call the read service", h.invoke("app", "read", "--config", main, "--op", "accounts"),
             lambda r: r["outcome"] == "connection_failed")
    h.expect("copied bridge signing identifier is refused",
             h.invoke("impostor-bridge", "read", "--config", main, "--op", "accounts"),
             lambda r: r["outcome"] == "connection_failed")
    for payload, code in (("oversize", "request_too_large"), ("unknown-key", "invalid_request"),
                          ("unknown-operation", "invalid_request"), ("null-value", "invalid_request")):
        h.expect(f"raw {payload} request gets {code}",
                 h.invoke("bridge", "raw-read", "--config", main, "--payload", payload),
                 lambda r, code=code: r["outcome"] == code)
    h.expect("admin selector on the read service is not dispatched",
             h.invoke("bridge", "raw-admin-selector", "--config", main),
             lambda r: r["outcome"].startswith("xpc_error_") or r["outcome"] == "timeout")
    h.expect("excess concurrency on one connection returns busy",
             h.invoke("bridge", "burst", "--config", main, "--count", "12"),
             lambda r: r["counts"] == {"ok": 4, "busy": 8})
    h.expect("broker refuses an unexpected kernel UID",
             h.invoke("bridge", "read", "--config", uid_client, "--op", "accounts"),
             lambda r: r["outcome"] == "connection_failed")
    h.expect("bridge refuses a spoofed broker", h.invoke("bridge", "read", "--config", spoof_client, "--op", "run"),
             lambda r: r["outcome"] == "broker_rejected")
    h.expect("human app refuses a spoofed broker", h.invoke("app", "admin", "--config", spoof_client),
             lambda r: r["outcome"] == "broker_rejected")
    h.expect("bridge refuses a genuine broker with an unexpected kernel UID",
             h.invoke("bridge", "read", "--config", wrong_broker_uid, "--op", "accounts"),
             lambda r: r["outcome"] == "broker_rejected")
    h.expect("human app refuses a genuine broker with an unexpected kernel UID",
             h.invoke("app", "admin", "--config", wrong_broker_uid),
             lambda r: r["outcome"] == "broker_rejected")
    h.expect("production configuration in a user-owned file is refused",
             h.invoke("broker", "check-config", "--config", production_same_uid, "--role", "broker"),
             lambda r: r["outcome"] == "invalid_configuration")

    def lines(path):
        return path.read_text().splitlines() if path.exists() else []
    h.expect("only the genuine broker's handlers ran, each with the bound UID",
             {"main": sorted(set(lines(main_record))), "uid": lines(uid_record), "spoof": lines(spoof_record)},
             lambda r: r["uid"] == [] and r["spoof"] == [] and r["main"] and all(
                 line.endswith(f"uid={UID}") for line in r["main"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence", help="write a JSON evidence record to this path")
    args = parser.parse_args()
    if sys.platform != "darwin":
        sys.exit("verify-xpc requires macOS")
    if subprocess.run(["launchctl", "print", DOMAIN], capture_output=True).returncode != 0:
        sys.exit(f"verify-xpc requires a logged-in GUI session ({DOMAIN} is unavailable)")

    harness = Harness()

    def interrupted(signum, _frame):
        harness.cleanup()
        sys.exit(128 + signum)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)

    signing = {}
    try:
        run(harness)
        signing = {name: {k: v for k, v in info.items() if k != "path"}
                   for name, info in harness.binaries.items()}
    finally:
        harness.cleanup()

    failed = [r["scenario"] for r in harness.results if not r["passed"]]
    clean = all(v in ("removed", True) for v in harness.cleanup_record.values())
    print("cleanup:", json.dumps(harness.cleanup_record, sort_keys=True))
    if args.evidence:
        Path(args.evidence).write_text(json.dumps({
            "uid": UID, "scope": "same-UID inter-process; separate broker UID unproven",
            "signing": signing, "results": harness.results, "cleanup": harness.cleanup_record,
        }, indent=2, sort_keys=True) + "\n")
    print(f"{len(harness.results) - len(failed)}/{len(harness.results)} scenarios passed")
    if failed or not clean:
        sys.exit(1)


if __name__ == "__main__":
    main()
