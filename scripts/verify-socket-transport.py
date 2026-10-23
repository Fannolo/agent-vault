#!/usr/bin/env python3
"""Build and run the native Unix-socket broker transport tests with owned, bounded processes.

Every build and test runs through run_owned from scripts/verify-webhost-link-mutations.py:
a new session whose recorded process group is the only one ever signalled. A timeout (None)
is a failure. Output goes to a fresh private directory under verification-logs/ and is
scanned for the synthetic canaries the tests use; a canary in any log fails the run.

--mutations reverts one transport defense at a time and requires its named test to fail.
Run it on a clean tree; each file is restored byte-for-byte afterwards.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SUITE = "AgentVaultSocketTests"
# Must match Tests/AgentVaultSocketTests/Support.swift.
CANARIES = [b"SYNTHETIC-socket-canary-credential-6c41", b"SYNTHETIC-socket-canary-rotated-93be"]
SERVER = "Sources/AgentVaultIPC/VaultSocketServer.swift"
CLIENT = "Sources/AgentVaultIPC/VaultSocketClients.swift"
IO = "Sources/AgentVaultIPC/SocketIO.swift"
MUTATIONS = [
    ("server ignores the kernel peer UID", SERVER,
     "uid == endpoint.clientUID, uid != 0 else { return refuse(fd) }", "uid != 0 else { return refuse(fd) }",
     "deniedPeerUIDIsClosedBeforeAnyRequestIsRead"),
    ("client sends before checking the broker UID", IO,
     "guard uid == brokerUID, uid != 0 else { close(fd); return .failure(.brokerRejected) }", "",
     "clientRefusesAMismatchedBrokerBeforeSendingAByte"),
    ("read work survives its disconnect", SERVER,
     "        for task in work.invalidate() { task.cancel() }\n", "",
     "disconnectCancelsTheBrokerReadButAdminMutationsComplete"),
    ("admin identity minted per request", SERVER,
     "case (.admin, .begin, .some(let identity)):", "case (.admin, .begin, .some(_)):\n            let identity = AdminConnection(uid: uid)",
     "adminIdentityIsPerConnectionAndEndsWithIt"),
    ("read socket serves admin opcodes", SERVER,
     "        case (.read, .read, nil):", "        case (.read, .snapshot, nil):\n            return start(id: id, connection: connectionWork, service: lanes.readWork,\n                         parse: {}, work: { _ in await handlers.snapshotReply(uid: uid, limits: limits) })\n        case (.read, .read, nil):",
     "readSocketRefusesAdminOpcodes"),
    ("partial frame waits forever", IO,
     "                if filled == 0 { deadline = .after(timeout) }\n", "",
     "stalledPartialFrameIsClosedAtItsDeadline"),
    ("oversized body is read", IO,
     "        guard length <= maxBody else { return .success(.oversized(header: header)) }\n", "",
     "oversizedFrameIsRefusedFromItsHeader"),
    ("stop does not wake connection readers", SERVER,
     "switch SocketIO.readFrame(fd, wake: wake, headerSize: SocketFrame.requestHeader,",
     "switch SocketIO.readFrame(fd, wake: -1, headerSize: SocketFrame.requestHeader,",
     "stopClosesPeersAwaitsWorkAndRemovesOnlyItsSockets"),
]


def load_helper():
    spec = importlib.util.spec_from_file_location("owned_socket", ROOT / "scripts/verify-webhost-link-mutations.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--filter", default=SUITE)
    parser.add_argument("--full", action="store_true", help="also run the whole package suite and verify-mcp.py")
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument("--only", default="", help="run only mutations whose name contains this text")
    args = parser.parse_args()
    for name in ("AGENT_VAULT_KEYCHAIN_TEST", "AGENT_VAULT_TEST_CHROMIUM"):
        os.environ.pop(name, None)
    logs = ROOT / "verification-logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="socket-", dir=logs))
    helper = load_helper()
    failures = []

    def step(name, command, timeout):
        code, output = helper.run_owned(command, timeout=timeout, cwd=ROOT)
        path = run / (name + ".log")
        with path.open("x") as log:
            os.fchmod(log.fileno(), 0o600)
            log.write(output)
        status = "TIMEOUT" if code is None else ("PASS" if code == 0 else f"FAIL({code})")
        print(f"{name}: {status}; private log {path}", flush=True)
        return code, output

    build = ["swift", "build", "--build-tests", "--force-resolved-versions", "-j", "8"]
    commands = [] if args.skip_build else [("build", build, 900)]
    commands.append(("socket-tests", ["swift", "test", "--skip-build", "--filter", args.filter], 300))
    if args.full:
        commands.append(("full-suite", ["swift", "test", "--skip-build"], 1500))
        commands.append(("verify-mcp", [sys.executable, "scripts/verify-mcp.py"], 900))
        commands.append(("verify-boundaries", [sys.executable, "scripts/verify-boundaries.py"], 300))
    for name, command, timeout in commands:
        code, _ = step(name, command, timeout)
        if code != 0:
            failures.append(name)
            break

    if args.mutations and not failures:
        for index, (name, path, old, new, test) in enumerate(MUTATIONS):
            if args.only not in name:
                continue
            source = ROOT / path
            original = source.read_bytes()
            text = original.decode()
            if text.count(old) != 1:
                print(f"mutation {name}: ANCHOR_MISSING", flush=True)
                failures.append(name)
                continue
            with helper.changed_source(source, original, text.replace(old, new).encode()):
                code, _ = step(f"mutant-{index}-build", build, 900)
                if code != 0:
                    status = "BUILD_FAILED"
                else:
                    code, _ = step(f"mutant-{index}-test", ["swift", "test", "--skip-build", "--filter", test], 240)
                    status = "KILLED(timeout)" if code is None else ("KILLED" if code != 0 else "SURVIVED")
            print(f"mutation {name}: {status}", flush=True)
            if not status.startswith("KILLED"):
                failures.append(name)
        code, _ = step("restored-build", build, 900)
        if code != 0:
            failures.append("restored-build")

    leaked = sorted(str(path) for path in run.iterdir() if any(c in path.read_bytes() for c in CANARIES))
    if leaked:
        print("FAIL: synthetic canary present in logs: " + ", ".join(leaked), flush=True)
        failures.append("canary")
    else:
        print(f"canary scan: PASS ({len(list(run.iterdir()))} logs)", flush=True)
    print("FAIL: " + ", ".join(failures) if failures else "PASS", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
