#!/usr/bin/env python3
"""Build and run the native Unix-socket broker transport tests with owned, bounded processes.

Every build, test and git query runs through run_owned from scripts/verify-webhost-link-mutations.py:
a new session whose recorded process group is the only one ever signalled. A timeout (None)
is a failure. Output goes to a fresh private directory under verification-logs/, is scanned
for the synthetic canaries the tests use (a canary in any log fails the run), and is listed
with its SHA-256 in MANIFEST.txt next to the commit and source hashes it was produced from.

--stress N reruns the socket suite N times in the same run directory.

--mutations reverts one transport defense at a time and requires every named test to fail.
After each mutant the file is restored byte-for-byte, rebuilt, and the same named tests must
pass again. Run it on a clean tree.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SUITE = "AgentVaultSocketTests"
# Must match Tests/AgentVaultSocketTests/Support.swift.
CANARIES = [b"SYNTHETIC-socket-canary-credential-6c41", b"SYNTHETIC-socket-canary-rotated-93be"]
SERVER = "Sources/AgentVaultIPC/VaultSocketServer.swift"
CLIENT = "Sources/AgentVaultIPC/VaultSocketClients.swift"
IO = "Sources/AgentVaultIPC/SocketIO.swift"
SUPPORT = "Tests/AgentVaultSocketTests/Support.swift"
HASHED = ["Sources/AgentVaultIPC", "Sources/CAgentVaultSocket", "Sources/AgentVaultBrokerDaemon",
          "Tests/AgentVaultSocketTests", "scripts/verify-socket-transport.py", "Package.swift", "Package.resolved"]
# (name, file, exact text, replacement, tests that must fail)
MUTATIONS = [
    ("server ignores the kernel peer UID", SERVER,
     "uid == endpoint.clientUID, uid != 0 else { return refuse(fd) }", "uid != 0 else { return refuse(fd) }",
     ["deniedPeerUIDIsClosedBeforeAnyRequestIsRead"]),
    ("client sends before checking the broker UID", IO,
     "guard uid == brokerUID, uid != 0 else { close(fd); return .failure(.brokerRejected) }", "",
     ["clientRefusesAMismatchedBrokerBeforeSendingAByte"]),
    ("read work survives its disconnect", SERVER,
     "        for task in work.invalidate() { task.cancel() }\n", "",
     ["disconnectCancelsTheBrokerReadButAdminMutationsComplete"]),
    ("admin identity minted per request", SERVER,
     "case (.admin, .begin, .some(let identity)):", "case (.admin, .begin, .some(_)):\n            let identity = AdminConnection(uid: uid)",
     ["adminIdentityIsPerConnectionAndEndsWithIt"]),
    ("read socket serves admin opcodes", SERVER,
     "        case (.read, .read, nil):", "        case (.read, .snapshot, nil):\n            return start(id: id, connection: connectionWork, service: lanes.readWork,\n                         parse: {}, work: { _ in await handlers.snapshotReply(uid: uid, limits: limits) })\n        case (.read, .read, nil):",
     ["readSocketRefusesAdminOpcodes"]),
    ("partial frame waits forever", IO,
     "                if filled == 0 { deadline = .after(timeout) }\n", "",
     ["stalledPartialFrameIsClosedAtItsDeadline"]),
    ("oversized body is read", IO,
     "        guard length <= maxBody else { return .success(.oversized(header: header)) }\n", "",
     ["oversizedFrameIsRefusedFromItsHeader"]),
    ("stop does not wake connection readers", SERVER,
     "switch SocketIO.readFrame(fd, wake: wake, headerSize: SocketFrame.requestHeader,",
     "switch SocketIO.readFrame(fd, wake: -1, headerSize: SocketFrame.requestHeader,",
     ["stopClosesPeersAwaitsWorkAndRemovesOnlyItsSockets"]),
    ("test peer closes its descriptor twice", SUPPORT,
     "        guard lock.withLock({ () -> Bool in defer { open = false }; return open }) else { return }\n", "",
     ["rawPeerCloseIsOneShot"]),
    ("reads skip the stop and deadline check while bytes are ready", IO,
     "            switch wait(fd, wake: wake, events: Int32(AV_WAIT_READ), deadline: deadline) {\n"
     "            case .ready: break\n            case .woken: return .failure(.stopped)\n"
     "            case .expired, .failed: return .failure(.broken)\n            }\n", "",
     ["readerObservesStopWhileBytesAreReady"]),
    ("writes skip the stop and deadline check while the buffer has room", IO,
     "                guard case .ready = wait(fd, wake: wake, events: Int32(AV_WAIT_WRITE), deadline: deadline) else { return false }\n", "",
     ["writerSendsNothingAfterStopOrPastItsDeadline"]),
    ("client sends a call that expired while queued", CLIENT,
     "                guard deadline.pollTimeout != nil else { return resolve(id, .failure(.timeout)) }\n", "",
     ["anExpiredQueuedCallIsNeverSentAndTheConnectionStaysUsable"]),
    ("accept drains queued connections without checking stop", SERVER,
     "            if fd >= 0 { admit(fd); continue }",
     "            if fd >= 0 {\n                admit(fd)\n                while true {\n                    let next = av_socket_accept(listenFD)\n"
     "                    if next < 0 { break }\n                    admit(next)\n                }\n                continue\n            }",
     ["acceptLoopStopsBetweenConnectionsWhileMoreAreQueued"]),
    ("reader ignores the reply backlog", SERVER,
     "                guard awaitReplyRoom(),\n", "                guard true,\n",
     ["errorRepliesCountAgainstTheReplyBacklog"]),
    ("work capacity is released before its reply is written", SERVER,
     "            send(id: id, data) { connection.release(); service.release() }",
     "            connection.release(); service.release()\n            send(id: id, data)",
     ["unwrittenRepliesKeepTheirServiceCapacity"]),
    ("writer never wakes a reader waiting for backlog room", SERVER,
     "                backlog.broadcast()\n", "",
     ["aDisconnectStillCancelsReadsWhileTheReaderWaitsForTheWriter"]),
    ("admin slot is released before the closed callback ends", SERVER,
     "            Task {\n                await closedHandler(identity)\n                released()\n",
     "            released()\n            Task {\n                await closedHandler(identity)\n",
     ["anAdminSlotStaysTakenUntilTheClosedCallbackFinishes"]),
    ("startup takes no lock", SERVER,
     "        let lock = try SocketPath.lock(path)\n", "        let lock: Int32 = -1\n",
     ["aConcurrentStartCannotTakeOverOrRemoveAStartingServersSockets"]),
]


def load_helper():
    spec = importlib.util.spec_from_file_location("owned_socket", ROOT / "scripts/verify-webhost-link-mutations.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_hashes():
    files = []
    for entry in HASHED:
        path = ROOT / entry
        files += sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    return [(str(p.relative_to(ROOT)), sha256(p.read_bytes())) for p in files]


def failed_tests(output):
    return set(re.findall(r"✘ Test (\w+)\(", output))


def passed_tests(output):
    return set(re.findall(r"✔ Test (\w+)\(", output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--filter", default=SUITE)
    parser.add_argument("--full", action="store_true", help="also run the whole package suite and verify-mcp.py")
    parser.add_argument("--stress", type=int, default=0, help="rerun the socket suite this many times")
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument("--only", default="", help="run only mutations whose name contains this text")
    parser.add_argument("--check-anchors", action="store_true", help="only check that every mutation anchor is unique")
    args = parser.parse_args()
    if args.check_anchors:
        bad = [name for name, path, old, _, _ in MUTATIONS if (ROOT / path).read_text().count(old) != 1]
        print("ANCHOR_MISSING: " + ", ".join(bad) if bad else f"anchors: PASS ({len(MUTATIONS)})")
        return 1 if bad else 0
    for name in ("AGENT_VAULT_KEYCHAIN_TEST", "AGENT_VAULT_TEST_CHROMIUM"):
        os.environ.pop(name, None)
    logs = ROOT / "verification-logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="socket-", dir=logs))
    helper = load_helper()
    failures = []
    results = []

    def step(name, command, timeout):
        code, output = helper.run_owned(command, timeout=timeout, cwd=ROOT)
        path = run / (name + ".log")
        with path.open("x") as log:
            os.fchmod(log.fileno(), 0o600)
            log.write(output)
        status = "TIMEOUT" if code is None else ("PASS" if code == 0 else f"FAIL({code})")
        results.append((path.name, status))
        print(f"{name}: {status}; private log {path}", flush=True)
        return code, output

    def git(*arguments):
        code, output = helper.run_owned(["git", *arguments], timeout=60, cwd=ROOT)
        return output.strip() if code == 0 else f"<git {' '.join(arguments)} failed: {code}>"

    commit, tracked = git("rev-parse", "HEAD"), git("status", "--porcelain", "--untracked-files=no")
    hashes = source_hashes()
    build = ["swift", "build", "--build-tests", "--force-resolved-versions", "-j", "8"]
    commands = [] if args.skip_build else [("build", build, 900)]
    commands.append(("socket-tests", ["swift", "test", "--skip-build", "--filter", args.filter], 300))
    if args.full:
        commands.append(("full-suite", ["swift", "test", "--skip-build"], 1500))
        commands.append(("verify-mcp", [sys.executable, "scripts/verify-mcp.py"], 900))
        commands.append(("verify-boundaries", [sys.executable, "scripts/verify-boundaries.py"], 300))
    commands += [(f"stress-{n}", ["swift", "test", "--skip-build", "--filter", SUITE], 300) for n in range(1, args.stress + 1)]
    for name, command, timeout in commands:
        code, _ = step(name, command, timeout)
        if code != 0:
            failures.append(name)
            break

    if args.mutations and not failures:
        for index, (name, path, old, new, tests) in enumerate(MUTATIONS):
            if args.only not in name:
                continue
            source = ROOT / path
            original = source.read_bytes()
            text = original.decode()
            if text.count(old) != 1:
                print(f"mutation {name}: ANCHOR_MISSING", flush=True)
                failures.append(name)
                continue
            selection = ["--filter", "/(" + "|".join(tests) + r")\(\)"]
            with helper.changed_source(source, original, text.replace(old, new).encode()):
                code, _ = step(f"mutant-{index}-build", build, 900)
                if code != 0:
                    status = "BUILD_FAILED"
                else:
                    code, output = step(f"mutant-{index}-test", ["swift", "test", "--skip-build", *selection], 120)
                    unkilled = set(tests) - failed_tests(output)
                    if code == 0 or unkilled:
                        status = "SURVIVED" + (f" ({', '.join(sorted(unkilled))})" if unkilled else "")
                    else:
                        status = "KILLED(timeout)" if code is None else "KILLED"
            if source.read_bytes() != original:
                status += "; RESTORE_FAILED"
            else:
                code, _ = step(f"mutant-{index}-restored-build", build, 900)
                if code == 0:
                    code, output = step(f"mutant-{index}-restored-test", ["swift", "test", "--skip-build", *selection], 120)
                    missing = set(tests) - passed_tests(output)
                    status += "; restored tests PASS" if code == 0 and not missing else "; RESTORED_TESTS_FAILED"
                else:
                    status += "; RESTORED_BUILD_FAILED"
            print(f"mutation {name}: {status}", flush=True)
            results.append((f"mutation {index}: {name}", status))
            if not status.startswith("KILLED") or not status.endswith("restored tests PASS"):
                failures.append(name)

    leaked = sorted(str(path) for path in run.iterdir() if any(c in path.read_bytes() for c in CANARIES))
    if leaked:
        print("FAIL: synthetic canary present in logs: " + ", ".join(leaked), flush=True)
        failures.append("canary")
    else:
        print(f"canary scan: PASS ({len(list(run.iterdir()))} logs)", flush=True)
    verdict = "FAIL: " + ", ".join(failures) if failures else "PASS"
    lines = [f"commit\t{commit}", "tracked changes\t" + (tracked.replace("\n", "; ") or "none"),
             f"arguments\t{' '.join(sys.argv[1:])}", f"verdict\t{verdict}", "", "# logs: name, status, sha256, bytes"]
    for name, status in results:
        log = run / name
        if log.is_file():
            data = log.read_bytes()
            lines.append(f"{name}\t{status}\t{sha256(data)}\t{len(data)}")
        else:
            lines.append(f"{name}\t{status}")
    lines += ["", "# sources: path, sha256"] + [f"{path}\t{digest}" for path, digest in hashes]
    manifest = run / "MANIFEST.txt"
    with manifest.open("x") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write("\n".join(lines) + "\n")
    print(f"manifest: {manifest}", flush=True)
    print(verdict, flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
