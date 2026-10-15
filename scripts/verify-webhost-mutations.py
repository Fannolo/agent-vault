#!/usr/bin/env python3
"""Reverts one U2 web host defense at a time and requires its targeted test to fail.

Needs AGENT_VAULT_TEST_CHROMIUM pointing at a Chrome for Testing chrome-headless-shell, because
most defenses are only observable in the real browser. Every targeted test must pass on the
unmutated tree first. Edits the working tree in place, restores each file in `finally`, and runs
every build and test through the link harness's `run_owned`: only process groups this script
created are ever signalled. Raw output goes to verification-logs/webhost-mutations.log.
"""
import importlib.util
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("link_harness", ROOT / "scripts/verify-webhost-link-mutations.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
LOG = ROOT / "verification-logs" / "webhost-mutations.log"
TEST_TIMEOUT = 240

H = "Sources/AgentVaultWebHost/"
# Not listed, because no fixture can observe it: removing the fill recipe's form-action origin and
# path check. The fixed form selector already refuses the off-origin form, and CSP `base-uri
# 'none'` stops a <base> element from redirecting a matching form. It remains a third layer.
# Likewise removing the frame's pixel-size check survives against a browser that honours the clip;
# the parser it relies on is mutated instead.
M = [
 ("pipe writes ignore their deadline", H + "ChromiumPipe.swift",
  "                guard remaining > 0, !isClosed else { return false }\n", "                guard !isClosed else { return false }\n",
  "stalledWriteEndsAtItsOwnDeadlineAndBreaksThePipe"),
 ("teardown waits for a writer that ignores shutdown", H + "ChromiumPipe.swift",
  "        // Never waits for a writer: kill first; the writer notices within one poll slice.\n        kill(-processGroup, SIGKILL)\n",
  "        writer.sync {}\n        kill(-processGroup, SIGKILL)\n", "teardownIsBoundedWhileALargeWriteIsStalled",
  ("                guard remaining > 0, !isClosed else { return false }\n", "                guard remaining > 0 else { return false }\n")),
 ("runs use the browser before auto-attach", H + "HostService.swift",
  "        if launch == nil { launch = Task { await self.launchBrowser() } }\n",
  "        if let pipe { return pipe }\n        if launch == nil { launch = Task { await self.launchBrowser() } }\n",
  "concurrentColdStartsCreateNoTargetBeforeAutoAttachIsConfirmed"),
 ("concluded run IDs are reusable", H + "HostService.swift",
  "        if case .humanStep = reply { return reply }\n        await end(id)\n",
  "        if case .humanStep = reply { return reply }\n        await end(id)\n        tombstones.remove(id)\n",
  "fixedWorkflowReturnsOnlyTheTypedProfileAndDisposesTheContext"),
 ("gate allows every document", H + "RequestGate.swift",
  "            guard origin == policy.primary else { return .deny(.originMismatch) }\n",
  "", "offOriginNavigationFailsBeforeTheCredentialIsUsed"),
 ("no CSP on documents", H + "EventRouter.swift",
  '        fields.append(["name": "Content-Security-Policy", "value": network.gate.contentSecurityPolicy(phase: network.phase)])\n',
  "", "backgroundChannelsNeverLeaveTheReviewedOrigin"),
 ("popups not blocked", H + "ChromiumPipe.swift",
  '"--block-new-web-contents", ', "", "backgroundChannelsNeverLeaveTheReviewedOrigin"),
 ("subresources reach any origin", H + "RequestGate.swift",
  "        return .block\n    }\n\n    private func allowsMainFrame", "        return .allow\n    }\n\n    private func allowsMainFrame",
  "backgroundChannelsNeverLeaveTheReviewedOrigin"),
 ("profile accepts duplicate fields", H + "Recipe.swift",
  "if (logins.length !== 1 || ids.length !== 1) return null;", "if (logins.length < 1 || ids.length < 1) return null;",
  "reflectedProfileFieldsAreRejectedOrIgnored"),
 ("frame shows the whole viewport", H + "WebRun.swift",
  '"clip": ["x": region.x, "y": region.y, "width": region.width, "height": region.height, "scale": 1],',
  '"clip": ["x": 0, "y": 0, "width": WebRun.viewport.width, "height": WebRun.viewport.height, "scale": 1],',
  "humanStepIsShownAsABoundCropAndCompletedOnlyByThePerson"),
 ("input not bound to the latest frame", H + "WebRun.swift",
  "        guard epoch == step, let latest, latest.sequence == frame,", "        guard epoch == step, let latest,",
  "humanStepIsShownAsABoundCropAndCompletedOnlyByThePerson"),
 ("step epochs may repeat", H + "WebRun.swift",
  "        guard epoch > step else { return .rejected(.staleStep) }\n", "", "humanStepIsShownAsABoundCropAndCompletedOnlyByThePerson"),
 ("no host lifetime cap", H + "HostService.swift",
  "            await self?.end(id)\n        }\n        let reply", "            _ = self\n        }\n        let reply",
  "lifetimeAndEndDisposeTheContextAndRefuseALateStart"),
 ("start after end allowed", H + "HostService.swift",
  "    private func admissible(_ id: UUID) -> Bool { !terminal && !tombstones.contains(id) }",
  "    private func admissible(_ id: UUID) -> Bool { !terminal }",
  "lifetimeAndEndDisposeTheContextAndRefuseALateStart"),
 ("teardown is not terminal", H + "HostService.swift",
  "    func teardown() async {\n        terminal = true\n", "    func teardown() async {\n",
  "peerLossIsTerminalAndEndsTheBrowserTree"),
 ("unconfirmed disposal is not fatal", H + "HostService.swift",
  "            await fail()\n            return\n", "            return\n", "browserThatStopsAnsweringIsKilledAndReportedFatal"),
 ("teardown leaves the browser running", H + "ChromiumPipe.swift",
  "        kill(-processGroup, SIGKILL)\n", "", "browserThatStopsAnsweringIsKilledAndReportedFatal"),
 ("frame size parser reads the wrong fields", H + "WebRun.swift",
  "                return (width, height)\n", "                return (height, width)\n", "hostReadsTheEncodedPixelSizeOfAFrame"),
]


def main():
    if not os.environ.get("AGENT_VAULT_TEST_CHROMIUM"):
        print("AGENT_VAULT_TEST_CHROMIUM is required", flush=True)
        return 2
    LOG.parent.mkdir(exist_ok=True)
    LOG.write_text("")
    code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=900)
    filters = "|".join(sorted({m[4] for m in M}))
    if code == 0:
        code, out = harness.run_owned(["swift", "test", "--skip-build", "--filter", filters], timeout=TEST_TIMEOUT * 2)
    with open(LOG, "a") as log:
        log.write(f"=== baseline [{filters}] -> {code}\n{out}\n")
    if code != 0:
        print("baseline FAILED: targeted tests must pass before mutating", flush=True)
        return 2
    print("baseline passed", flush=True)
    results = []
    for name, path, old, new, test, *also in M:
        source = ROOT / path
        original = source.read_text()
        assert original.count(old) == 1, name
        mutated = original.replace(old, new)
        # A compound mutant also reverts a second, independent layer in the same file.
        for extra_old, extra_new in also:
            assert mutated.count(extra_old) == 1, name
            mutated = mutated.replace(extra_old, extra_new)
        source.write_text(mutated)
        try:
            code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=900)
            if code != 0:
                status = "BUILD_FAILED"
            else:
                code, out = harness.run_owned(["swift", "test", "--skip-build", "--filter", test], timeout=TEST_TIMEOUT)
                status = "KILLED(hang)" if code is None else ("KILLED" if code != 0 else "SURVIVED")
        finally:
            source.write_text(original)
        results.append((name, status))
        with open(LOG, "a") as log:
            log.write(f"=== {name} [{test}] -> {status}\n{out}\n")
        print(name, status, flush=True)
    harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=900)
    return 0 if all(status.startswith("KILLED") for _, status in results) else 1


if __name__ == "__main__":
    sys.exit(main())
