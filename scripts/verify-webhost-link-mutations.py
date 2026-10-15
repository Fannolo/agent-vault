#!/usr/bin/env python3
"""Reverts one U1 web host link defense at a time and requires its targeted test to fail.

Edits the working tree in place and restores each file in `finally`; run it on a clean tree.
A test that hangs past the timeout counts as detecting the defect. Raw output goes to
verification-logs/webhost-link-mutations.log (gitignored).

Process ownership: every build and test runs in a new session whose process group this
script records at spawn. On timeout, or if anything is left in that group after the leader
exits, only that recorded group is signalled (TERM, bounded wait, then KILL). Nothing is
ever found or signalled by name, path or search, so other test runs, worktrees and
applications are untouched.
"""
import argparse
import os
import pathlib
import select
import signal
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOG = ROOT / "verification-logs" / "webhost-link-mutations.log"
TEST_TIMEOUT = 90
TERM_GRACE = 5

M = [
 ("finished handler retained", "Sources/AgentVaultIPC/VaultXPCServer.swift",
  "            guard reserved.contains(key) else { return true }   // already finished: nothing to keep\n", "",
  "handlerFinishingBeforeRegistrationIsNotRetained"),
 ("late registration survives invalidation", "Sources/AgentVaultIPC/VaultXPCServer.swift",
  "            if invalidated { return false }\n", "", "registrationAfterInvalidationCancelsTheHandler"),
 ("cancelled caller keeps waiting", "Sources/AgentVaultCore/Broker.swift",
  "        await withTaskCancellationHandler { await settled.wait() } onCancel: { settled.fire() }\n        timer.cancel()\n        if Task.isCancelled { return true }",
  "        await settled.wait()\n        timer.cancel()", "cancelledInitialCallerLeavesNoPausedRunOrContext"),
 ("ended runs retained by generation", "Sources/AgentVaultWebHostLink/WebHostLink.swift",
  "            generation?.runs.remove(run)\n", "", "endedRunsDoNotAccumulateOnALongLivedConnection"),
 ("link sends without asking authority", "Sources/AgentVaultWebHostLink/WebHostLink.swift",
  "            guard let lifetime = await authority.lifetimeIfStillAuthorized() else { return nil }",
  "            let lifetime = 60", "withdrawnAuthorityAfterTheProbeSendsNoCredential"),
 ("broker authority callback unconditional", "Sources/AgentVaultCore/Broker.swift",
  "        await sweep()\n        guard let run = runs[id], run.epoch == epoch, case .dispatching(let deadline) = run.phase,\n              now() < deadline.date else { return nil }\n        guard isAuthorized(run) else {\n            await apply(id, .authorityLost)\n            return nil\n        }\n        return min",
  "        guard let run = runs[id] else { return nil }\n        return min", "startPastItsDeadlineIsWithheldEvenWithAValidGrant"),
 ("dispatch deadline outlives grant", "Sources/AgentVaultCore/BrowserRuns.swift",
  "min(grantExpiresAt, now.addingTimeInterval(windows.startReply))", "now.addingTimeInterval(windows.startReply)",
  "grantExpiryWhileDispatchingEndsTheRunAsALossOfAuthority"),
 ("host accepts a peer after loss", "Sources/AgentVaultWebHostProtocol/WebHostServer.swift",
  "guard peer == nil, !terminated else { return false }", "guard peer == nil else { return false }", "hostServesOnePeer"),
 ("peer loss leaves handlers running", "Sources/AgentVaultWebHostProtocol/WebHostServer.swift",
  "        for handler in running { handler.cancel() }\n", "        _ = running\n", "peerLossCancelsRunningHandlers"),
 ("read handlers outlive their connection", "Sources/AgentVaultIPC/VaultXPCServer.swift",
  "            peer.connectionInvalidated()\n", "", "readHandlersAreCancelledWhenTheirConnectionGoes"),
 ("wheel bound uses abs", "Sources/AgentVaultContracts/HumanContinuation.swift",
  "            (-Self.maximumWheelDelta...Self.maximumWheelDelta).contains(dx)\n                && (-Self.maximumWheelDelta...Self.maximumWheelDelta).contains(dy) && (dx != 0 || dy != 0)",
  "            abs(dx) <= Self.maximumWheelDelta && abs(dy) <= Self.maximumWheelDelta && (dx != 0 || dy != 0)",
  "extremeValuesAreRefusedWithoutTrapping"),
 ("no broker reply deadline", "Sources/AgentVaultCore/Broker.swift",
  "        await withTaskCancellationHandler { await settled.wait() } onCancel: { settled.fire() }\n        timer.cancel()",
  "        timer.cancel(); _ = await request()", "hungHostStartEndsAtTheBrokerDeadline"),
 ("no lifetime guard", "Sources/AgentVaultCore/Broker.swift",
  "guard lifetime.isFinite, lifetime >= 1 else {", "guard lifetime.isFinite || true else {", "clockJumpLeavingLessThanOneSecond"),
 ("unscoped loss ends every run", "Sources/AgentVaultCore/Broker.swift",
  "for id in lost { await apply(id, .hostLost) }", "for id in Array(runs.keys) { await apply(id, .hostLost) }", "lateLoss"),
 ("dispatch has no sweep deadline", "Sources/AgentVaultCore/BrowserRuns.swift",
  "        case .dispatching(let reply): reply.date\n", "        case .dispatching: nil\n", "unansweredStartEndsAtItsDeadlineEvenWithoutAWaiter"),
 ("credential sent before probe", "Sources/AgentVaultWebHostLink/WebHostLink.swift",
  "        case .verified: break\n        case .rejected: return .failure(.unavailable)", "        case .verified, .rejected: break", "impostorFailingTheHostRequirement"),
 ("no reply UID pin", "Sources/AgentVaultWebHostLink/WebHostLink.swift",
  "guard UInt32(connection.effectiveUserIdentifier) == hostUID else {", "guard UInt32(connection.effectiveUserIdentifier) == hostUID || true else {", "hostWithAnotherKernelUID"),
 ("timed-out start not ended", "Sources/AgentVaultWebHostLink/WebHostLink.swift",
  "            await end(run)\n        }\n        return step(outcome)", "        }\n        return step(outcome)", "stalledStartTimesOut"),
 ("unconfirmed end keeps host", "Sources/AgentVaultWebHostLink/WebHostLink.swift",
  "        generation.connection.invalidate()\n    }\n\n    public func showHuman", "    }\n\n    public func showHuman", "stalledClassifyAndUnconfirmedEnd"),
 ("no late-start tombstone", "Sources/AgentVaultWebHostLink/WebHostLink.swift",
  "            tombstones.insert(run)\n            let generation = bound.removeValue", "            let generation = bound.removeValue", "startAfterEndIsRefused"),
 ("host accepts second peer", "Sources/AgentVaultWebHostProtocol/WebHostServer.swift",
  "guard peer == nil, !terminated else { return false }", "guard !terminated else { return false }", "hostServesOnePeer"),
 ("host ignores broker UID", "Sources/AgentVaultWebHostProtocol/WebHostServer.swift",
  "guard uid == configuration.brokerUID, uid != 0 else { return false }", "guard uid != 0 else { return false }", "hostRefusesBroker"),
 ("teardown shares frame lane", "Sources/AgentVaultWebHostProtocol/HostCommand.swift",
  "        case .end: .teardown\n        case .frame: .frame", "        case .end, .frame: .frame", "excessControlRequestsFailFast"),
 ("wire accepts extra keys", "Sources/AgentVaultWebHostProtocol/HostWire.swift",
  "            guard remaining.isEmpty else { throw error }", "            _ = remaining", "startHasExactlyItsKeys"),
]


def group_has_live_members(pgid):
    """True while any process in the owned group can still run.

    Measured on macOS: signal 0 to a group succeeds while a live member exists, fails with
    EPERM when only the unreaped (zombie) leader remains, and with ESRCH once it is reaped.
    """
    try:
        os.killpg(pgid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def terminate_group(pgid, grace=TERM_GRACE):
    """Ends exactly the process group created for one owned child: TERM, bounded wait, KILL.

    Call it only while that child is unreaped, so its group ID cannot have been reused.
    """
    if pgid <= 1 or pgid == os.getpgrp():
        raise ValueError("refusing to signal a process group this harness does not own")
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if not group_has_live_members(pgid):
            return
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError):
            return
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and group_has_live_members(pgid):
            time.sleep(0.05)


def wait_for_exit_without_reaping(pid, timeout):
    """Waits for `pid` to exit but leaves it unreaped, keeping its PID and group ID reserved."""
    queue = select.kqueue()
    try:
        event = select.kevent(pid, filter=select.KQ_FILTER_PROC,
                              flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT, fflags=select.KQ_NOTE_EXIT)
        try:
            return len(queue.control([event], 1, timeout)) > 0
        except ProcessLookupError:
            return True  # already exited (zombie) before registration
    finally:
        queue.close()


def run_owned(command, timeout, cwd=ROOT):
    """Runs `command` as the leader of a new session and process group.

    Returns (returncode, or None on timeout; combined output). The group ID is the child's PID,
    taken from the spawn handle before anything else, and is the only group ever signalled.
    """
    child = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True)
    pgid = child.pid
    chunks = []
    reader = threading.Thread(target=lambda: chunks.append(child.stdout.read()), daemon=True)
    reader.start()
    exited = wait_for_exit_without_reaping(pgid, timeout)
    # The leader is alive or a zombie here; either way the group ID is still ours.
    terminate_group(pgid)
    code = child.wait()
    reader.join(TERM_GRACE)
    child.stdout.close()
    output = b"".join(chunks).decode("utf-8", "replace")
    return (code if exited else None), output


def main():
    global LOG
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=pathlib.Path, help="retain full output at this fresh path")
    args = parser.parse_args()
    if args.log:
        LOG = args.log.resolve()
    LOG.parent.mkdir(exist_ok=True)
    # Explicit paths are never overwritten; the recorder supplies a new private run directory.
    with LOG.open("x" if args.log else "w") as log:
        os.fchmod(log.fileno(), 0o600)
    # A mutant only counts as detected if its test passes on the unmutated tree.
    code, out = run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=600)
    filters = "|".join(sorted({test for *_, test in M}))
    if code == 0:
        code, out = run_owned(["swift", "test", "--skip-build", "--filter", filters], timeout=TEST_TIMEOUT * 3)
    with open(LOG, "a") as log:
        log.write(f"=== baseline [{filters}] -> {code}\n{out}\n")
    if code != 0:
        print("baseline FAILED: targeted tests must pass before mutating", flush=True)
        return 2
    print("baseline passed", flush=True)
    results = []
    for name, path, old, new, test in M:
        source = ROOT / path
        original = source.read_text()
        assert original.count(old) == 1, name
        source.write_text(original.replace(old, new))
        try:
            code, out = run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=600)
            if code != 0:
                status = "BUILD_FAILED"
            else:
                code, out = run_owned(["swift", "test", "--skip-build", "--filter", test], timeout=TEST_TIMEOUT)
                if code is None:
                    status, out = "KILLED(hang)", f"test hung past {TEST_TIMEOUT} s; owned group ended\n" + out
                else:
                    status = "KILLED" if code != 0 else "SURVIVED"
        finally:
            source.write_text(original)
        results.append((name, status))
        with open(LOG, "a") as log:
            log.write(f"=== {name} [{test}] -> {status}\n{out}\n")
        print(name, status, flush=True)
    run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=600)
    return 0 if all(status.startswith("KILLED") for _, status in results) else 1


if __name__ == "__main__":
    sys.exit(main())
