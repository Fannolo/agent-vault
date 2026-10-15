#!/usr/bin/env python3
"""Reverts one U1 web host link defense at a time and requires its targeted test to fail.

Edits the working tree in place and restores each file in `finally`; run it on a clean tree.
A test that hangs past 90 s counts as detecting the defect. Raw output goes to
verification-logs/webhost-link-mutations.log (gitignored)."""
import subprocess, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
LOG = ROOT / "verification-logs" / "webhost-link-mutations.log"
LOG.parent.mkdir(exist_ok=True)
LOG.write_text("")
M = [
 ("no broker reply deadline", "Sources/AgentVaultCore/Broker.swift",
  "        await settled.wait()\n        timer.cancel()", "        timer.cancel(); _ = await request()\n        await settled.wait()",
  "hungHostStartEndsAtTheBrokerDeadline"),
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
  "            tombstones.insert(run)\n            return bound.removeValue", "            return bound.removeValue", "startAfterEndIsRefused"),
 ("host accepts second peer", "Sources/AgentVaultWebHostProtocol/WebHostServer.swift",
  "guard peer == nil, !tearingDown else { return false }", "guard !tearingDown else { return false }", "hostServesOnePeer"),
 ("host ignores broker UID", "Sources/AgentVaultWebHostProtocol/WebHostServer.swift",
  "guard uid == configuration.brokerUID, uid != 0 else { return false }", "guard uid != 0 else { return false }", "hostRefusesBroker"),
 ("teardown shares frame lane", "Sources/AgentVaultWebHostProtocol/HostCommand.swift",
  "        case .end: .teardown\n        case .frame: .frame", "        case .end, .frame: .frame", "excessControlRequestsFailFast"),
 ("wire accepts extra keys", "Sources/AgentVaultWebHostProtocol/HostWire.swift",
  "            guard remaining.isEmpty else { throw error }", "            _ = remaining", "startHasExactlyItsKeys"),
]
results = []
for name, path, old, new, test in M:
    f = ROOT / path; original = f.read_text()
    assert original.count(old) == 1, name
    f.write_text(original.replace(old, new))
    try:
        b = subprocess.run(["swift", "build", "--build-tests", "-j", "8"], cwd=ROOT, capture_output=True, text=True)
        if b.returncode != 0:
            out, status = b.stdout[-3000:] + b.stderr[-2000:], "BUILD_FAILED"
        else:
            try:
                r = subprocess.run(["swift", "test", "--skip-build", "--filter", test], cwd=ROOT, capture_output=True, text=True, timeout=90)
                out = r.stdout + r.stderr
                status = "KILLED" if r.returncode != 0 else "SURVIVED"
            except subprocess.TimeoutExpired as e:
                subprocess.run(["pkill", "-f", "AgentVaultPackageTests"])
                out, status = "test hung past 90 s: " + str(e.stdout or "")[-2000:], "KILLED(hang)"
    finally:
        f.write_text(original)
    results.append((name, status))
    with open(LOG, "a") as log: log.write(f"=== {name} [{test}] -> {status}\n{out[-4000:]}\n")
    print(name, status, flush=True)
subprocess.run(["swift", "build", "--build-tests", "-j", "8"], cwd=ROOT, capture_output=True)
sys.exit(0 if all(s.startswith("KILLED") for _, s in results) else 1)
