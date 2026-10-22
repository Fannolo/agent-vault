#!/usr/bin/env python3
"""Revert one continuation defense at a time after its focused tests pass unmodified.

Builds and tests use the link harness's bounded, owned process groups. Source bytes are
restored before interruption propagates; compile failures never count as detected defects.
Raw output is private and retained separately from the printed mutation summary.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("link_harness", ROOT / "scripts/verify-webhost-link-mutations.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
LOG = ROOT / "verification-logs" / "continuation-mutations.log"
TEST_TIMEOUT = 90

CORE = "ContinuationRelayTests"
XPC = "ContinuationXPCTests"
WIRE = "ContinuationWireTests"
APP = "HumanStepTests"
E2E = "HumanContinuationE2ETests"

MUTATIONS = [
    ("lease ignores its connection", "Sources/AgentVaultCore/Broker.swift",
     "guard connection.isOpen, let held = run.lease, held.connection == connection,",
     "guard connection.isOpen, let held = run.lease,", CORE),
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
    ("signed open binds a lease to a connection that already closed", "Sources/AgentVaultCore/Broker.swift",
     "        guard connection.isOpen else { throw VaultError.denied }\n", "", CORE),
    ("frame and input accept a synchronously closed connection", "Sources/AgentVaultCore/Broker.swift",
     "guard connection.isOpen, let held = run.lease,", "guard let held = run.lease,", CORE),
    ("finish and cancel accept a synchronously closed connection", "Sources/AgentVaultCore/Broker.swift",
     "guard connection.isOpen, let run = runs.values.first(where: { $0.lease?.id == lease }),",
     "guard let run = runs.values.first(where: { $0.lease?.id == lease }),", CORE),
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
    ("finish discards queued input", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "        flush()\n        await drained()\n", "", APP),
    ("polling continues during finish", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "        phase = .finishing\n        poller?.cancel(); poller = nil\n", "        phase = .finishing\n", APP),
    ("closing the window leaves it live", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "        end(.closed)\n", "", APP),
    ("no client-side deadline", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "if now() >= step.expiresAt {", "if false {", APP),
    ("long text sent as one oversized event", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "if chunk.utf8.count + String(character).utf8.count > HumanInput.maximumTextBytes {", "if false {", APP),
    ("frame request names no previous frame", "Sources/AgentVaultAppSupport/HumanStepModel.swift",
     "let after = frame?.sequence ?? 0", "let after: UInt64 = 0", APP),
    ("composition binds leases to a fresh identity per call", "Tests/AgentVaultContinuationE2ETests/HumanContinuationE2ETests.swift",
     "continuation: { peer, request in await operations.perform(request, connection: ContinuationConnectionID(peer)) },",
     "continuation: { peer, request in await operations.perform(request, connection: ContinuationConnectionID()) },", E2E),
]


def main():
    global LOG
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, help="retain full output at this fresh path")
    args = parser.parse_args()
    if args.log:
        LOG = args.log.resolve()
    LOG.parent.mkdir(exist_ok=True)
    with LOG.open("x" if args.log else "w") as log:
        os.fchmod(log.fileno(), 0o600)
    code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=600)
    filters = "|".join(sorted({m[4] for m in MUTATIONS}))
    if code == 0:
        code, out = harness.run_owned(["swift", "test", "--skip-build", "--filter", filters], timeout=TEST_TIMEOUT * 3)
    with LOG.open("a") as log:
        log.write(f"=== baseline [{filters}] -> {code}\n{out}\n")
    if code != 0:
        print("baseline FAILED: targeted tests must pass before mutating", flush=True)
        return 2
    print("PASS: mutation baseline", flush=True)
    results = []
    for label, path, old, new, filter_name in MUTATIONS:
        source = ROOT / path
        original = source.read_bytes()
        text = original.decode()
        if text.count(old) != 1:
            print(f"FAIL: mutation {label} does not match exactly once", flush=True)
            return 2
        with harness.changed_source(source, original, text.replace(old, new).encode()):
            code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=600)
            if code != 0:
                status = "BUILD_FAILED"
            else:
                code, out = harness.run_owned(["swift", "test", "--skip-build", "--filter", filter_name], timeout=TEST_TIMEOUT)
                status = "KILLED(hang)" if code is None else ("KILLED" if code != 0 else "SURVIVED")
        results.append(status)
        with LOG.open("a") as log:
            log.write(f"=== {label} [{filter_name}] -> {status}\n{out}\n")
        print(f"mutation {label}: {status}", flush=True)
    code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=600)
    with LOG.open("a") as log:
        log.write(f"=== restored source build -> {code}\n{out}\n")
    if code != 0:
        print("FAIL: restored source build", flush=True)
        return 2
    return 0 if all(status.startswith("KILLED") for status in results) else 1


if __name__ == "__main__":
    with harness.interrupt_on_termination():
        sys.exit(main())
