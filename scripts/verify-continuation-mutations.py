#!/usr/bin/env python3
"""Revert each human-continuation defense once and require a focused test to fail.

Edits one source file in place, runs `swift test --filter`, and restores the original bytes
in a `finally` block. It starts no other process and sends no signal. Logs go to the ignored
verification-logs/ directory with private permissions.
"""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / "verification-logs" / "continuation-mutations"

CORE = "ContinuationRelayTests"
XPC = "ContinuationXPCTests"
WIRE = "ContinuationWireTests"
APP = "HumanStepTests"
E2E = "HumanContinuationE2ETests"

MUTATIONS = [
    ("lease ignores its connection", "Sources/AgentVaultCore/Broker.swift",
     "guard let held = run.lease, held.connection == connection,", "guard let held = run.lease,", CORE),
    ("no authority recheck after the host answers a frame", "Sources/AgentVaultCore/Broker.swift",
     "        relays[lease]?.framePending = false\n        _ = try await current(lease, connection: connection, step: step)\n",
     "        relays[lease]?.framePending = false\n", CORE),
    ("replayed input batch accepted", "Sources/AgentVaultCore/Broker.swift",
     "guard batch > relay.lastBatch else { return false }", "", CORE),
    ("input aimed at a stale frame accepted", "Sources/AgentVaultCore/Broker.swift",
     "guard let served = relay.served, served.sequence == frame,", "guard let served = relay.served,", CORE),
    ("input checked against any frame size, not the served one", "Sources/AgentVaultCore/Broker.swift",
     "HumanInputBatch(events.events, width: served.width, height: served.height)", "Optional(events)", CORE),
    ("no poll pacing", "Sources/AgentVaultCore/Broker.swift",
     "if let last = relay.lastPoll, started - last < LeaseRelay.minimumPollInterval { throw VaultError.busy }", "", CORE),
    ("concurrent frame polls on one lease", "Sources/AgentVaultCore/Broker.swift",
     "guard let web, var relay = relays[lease], !relay.framePending else", "guard let web, var relay = relays[lease] else", CORE),
    ("relay state outlives its lease", "Sources/AgentVaultCore/Broker.swift",
     "if let ended = run.lease?.id, next?.lease?.id != ended { relays.removeValue(forKey: ended) }", "", CORE),
    ("open succeeds when the host cannot show the step", "Sources/AgentVaultCore/Broker.swift",
     "        guard shown else {", "        guard shown || true else {", CORE),
    ("begin accepts an open for a step that does not exist", "Sources/AgentVaultCore/Administration.swift",
     "guard connection != nil, try await broker.pendingHumanSteps().contains(where: { request.names($0) })",
     "guard connection != nil", CORE),
    ("open authorized on another connection", "Sources/AgentVaultCore/Administration.swift",
     "guard let connection, connection == invocation.connection else", "guard let connection else", CORE),
    ("stale signed open follows the run to its current step", "Sources/AgentVaultCore/Administration.swift",
     "let step = HumanStepID(run: BrowserRunID(request.requestID!), epoch: request.stepEpoch!)\n"
     "            guard try await broker.pendingHumanSteps().contains(where: { request.names($0) }) else { throw VaultError.denied }",
     "guard let step = try await broker.pendingHumanSteps().first(where: { $0.id.run.uuid == request.requestID })?.id"
     " else { throw VaultError.denied }", CORE),
    ("connection identity minted per call", "Sources/AgentVaultIPC/VaultXPCServer.swift",
     "let limits = continuation.limits, handler = handlers.continuation, identity = identity",
     "let limits = continuation.limits, handler = handlers.continuation, identity = AdminConnection(uid: identity.uid)", XPC),
    ("continuation shares the admin lane", "Sources/AgentVaultIPC/VaultXPCServer.swift",
     "        continuation.dispatch(size: data.count, reply: reply, parse: { () throws(IPCError) in\n            try WireCodec.decodeContinuation",
     "        peer.dispatch(size: data.count, reply: reply, parse: { () throws(IPCError) in\n            try WireCodec.decodeContinuation", XPC),
    ("closed connection not reported", "Sources/AgentVaultIPC/VaultXPCServer.swift",
     "                Task { await closed(identity) }\n", "", XPC),
    ("client accepts a frame that is not newer", "Sources/AgentVaultIPC/VaultXPCClients.swift",
     "frame.sequence <= after {", "frame.sequence < 0 {", XPC),
    ("event keys not exact", "Sources/AgentVaultIPC/ContinuationWire.swift",
     'guard keys == ["type", "key"], let key', 'guard let key', WIRE),
    ("operation keys not exact", "Sources/AgentVaultIPC/ContinuationWire.swift",
     'guard keys == ["operation", "lease"] else { throw .invalidRequest }', "", WIRE),
    ("declared frame size trusted over the decoded raster", "Sources/AgentVaultAppSupport/HumanFrameImage.swift",
     "width == frame.width, height == frame.height, width * height <= Self.maximumPixels,", "", APP),
    ("rotated JPEG accepted", "Sources/AgentVaultAppSupport/HumanFrameImage.swift",
     "(properties[kCGImagePropertyOrientation] as? NSNumber)?.intValue ?? 1 == 1", "true", APP),
    ("points outside the drawn frame mapped", "Sources/AgentVaultAppSupport/HumanFrameImage.swift",
     "clamped || rect.contains(point)", "true", APP),
    ("queued input survives a new frame", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "            queue.removeAll { $0.frame != frame.sequence }\n", "", APP),
    ("closing the window leaves it live", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "        end(.closed)\n", "", APP),
    ("no client-side deadline", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "if now() >= step.expiresAt {", "if false {", APP),
    ("long text sent as one oversized event", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "if chunk.utf8.count + String(character).utf8.count > HumanInput.maximumTextBytes {", "if false {", APP),
    ("frame request names no previous frame", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "let after = frame?.sequence ?? 0", "let after: UInt64 = 0", APP),
    ("composition binds leases to a fresh identity per call", "Tests/AgentVaultContinuationE2ETests/HumanContinuationE2ETests.swift",
     "continuation: { peer, request in await operations.perform(request, connection: ContinuationConnectionID(minted: peer.id)) },",
     "continuation: { peer, request in await operations.perform(request, connection: ContinuationConnectionID()) },", E2E),
]


def run(filter_name, log):
    with open(log, "w") as out:
        os.chmod(log, 0o600)
        result = subprocess.run(["swift", "test", "--force-resolved-versions", "--filter", filter_name],
                                cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    return result.returncode


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    os.chmod(LOGS.parent, 0o700); os.chmod(LOGS, 0o700)
    for name in sorted({m[4] for m in MUTATIONS}):
        code = run(name, LOGS / f"baseline-{name}.log")
        if code != 0:
            print(f"FAIL: baseline {name} is not green (exit {code})")
            return 1
    survivors = []
    for index, (label, path, old, new, filter_name) in enumerate(MUTATIONS, 1):
        file = ROOT / path
        original = file.read_bytes()
        text = original.decode()
        if text.count(old) != 1:
            print(f"FAIL: mutation {index} ({label}) does not match exactly once")
            return 1
        try:
            file.write_bytes(text.replace(old, new).encode())
            code = run(filter_name, LOGS / f"mutation-{index:02d}.log")
        finally:
            file.write_bytes(original)
        status = "detected" if code != 0 else "SURVIVED"
        print(f"{index:02d} {status} ({filter_name}): {label}")
        if code == 0:
            survivors.append(label)
    if survivors:
        print("FAIL: undetected mutations: " + "; ".join(survivors))
        return 1
    print(f"PASS: all {len(MUTATIONS)} continuation mutations detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
