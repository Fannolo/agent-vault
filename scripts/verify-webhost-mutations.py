#!/usr/bin/env python3
"""Reverts one U2 web host defense at a time and requires its targeted test to fail.

Needs AGENT_VAULT_TEST_CHROMIUM pointing at a Chrome for Testing chrome-headless-shell, because
most defenses are only observable in the real browser. Every targeted test must pass on the
unmutated tree first. Edits the working tree in place, restores each file in `finally`, and runs
every build and test through the link harness's `run_owned`: only process groups this script
created are ever signalled. Raw output goes to verification-logs/webhost-mutations.log.
"""
import argparse
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
  "        // Never waits for a writer: kill first; the writer notices within one poll slice.\n        killGroup()\n",
  "        writer.sync {}\n        killGroup()\n", "teardownIsBoundedWhileALargeWriteIsStalled",
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
  '        fields.append(["name": "Content-Security-Policy", "value": network.contentSecurityPolicy()])\n',
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
 ("step epochs may regress", H + "WebRun.swift",
  "        guard epoch > 0, epoch >= step else { return .rejected(.staleStep) }\n", "", "reopeningAStepPreservesItsFrameWatermarkAndRefusesOlderEpochs"),
 ("reopening a step resets the frame watermark", H + "WebRun.swift",
  "        if epoch > step { step = epoch; latest = nil }\n", "        step = epoch; latest = nil\n",
  "reopeningAStepPreservesItsFrameWatermarkAndRefusesOlderEpochs"),
 ("pages share the default browser context", H + "WebRun.swift",
  'let page = try? await pipe.call(.targetCreateTarget, ["url": "about:blank", "browserContextId": context])',
  'let page = try? await pipe.call(.targetCreateTarget, ["url": "about:blank"])',
  "separateContextsNeverReuseAnotherSessionsCookieAndEndIndependently"),
 ("no host lifetime cap", H + "HostService.swift",
  "            await self?.end(id)\n        }\n    }\n", "            _ = self\n        }\n    }\n",
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
  "        killGroup()\n        writer.async", "        writer.async", "browserThatStopsAnsweringIsKilledAndReportedFatal"),
 ("frame size parser reads the wrong fields", H + "WebRun.swift",
  "                return (width, height)\n", "                return (height, width)\n", "hostReadsTheEncodedPixelSizeOfAFrame"),
 # Continuing-site sessions. The credential-origin check has two layers (host and recipe); the
 # mutant removes both, leaving only the login-phase gate, which the test also observes.
 ("site login trusts any navigable page", H + "SiteSession.swift",
  "              policy.credential.contains(origin) else { return .rejected(.credentialOrigin) }",
  "              true else { return .rejected(.credentialOrigin) }",
  "credentialEligibilityComesFromTheObservedPageNeverTheCallerURL",
  ("        let fill = await run(.loginFill, origins: policy.credential, fields, while: held)",
   "        let fill = await run(.loginFill, origins: policy.navigation, fields, while: held)")),
 ("site targets ignore their document", H + "SiteSession.swift",
  "        return mode == .agent && target.control == control && target.document == page.epoch\n",
  "        return mode == .agent && target.control == control\n",
  "targetsAreBoundToTheirSessionDocumentAndControlEpoch"),
 ("site targets survive takeover", H + "SiteSession.swift",
  "        guard mode == .agent, target.control == control, let (_, page) = await currentDocument() else { return false }\n"
  "        return mode == .agent && target.control == control && target.document == page.epoch\n",
  "        guard mode == .agent, let (_, page) = await currentDocument() else { return false }\n"
  "        return mode == .agent && target.document == page.epoch\n",
  "targetsAreBoundToTheirSessionDocumentAndControlEpoch",
  # The recipe call's own hold on the target's control epoch is the second layer.
  ("values.merging([\"index\": target.element]) { $1 }, while: target.control) {",
   "values.merging([\"index\": target.element]) { $1 }) {")),
 ("takeover does not fence agent operations", H + "SiteSession.swift",
  "            guard command.fits else { return .rejected(.notPermitted) }\n            guard mode == .agent else { return .rejected(.humanControl) }\n",
  "            guard command.fits else { return .rejected(.notPermitted) }\n",
  "targetsAreBoundToTheirSessionDocumentAndControlEpoch"),
 ("operation ID reused for another command", H + "SiteSession.swift",
  "            guard entry.command == command else { return .rejected(.operationConflict) }\n", "",
  "continuingSessionLogsInPrivatelyThenSubmitsAnAuthenticatedFormAndSeesTheResult"),
 ("operation retry dispatches again", H + "SiteSession.swift",
  "        if let entry = journal[operation] {\n", "        if let entry = journal[operation], Bool(\"false\")! {\n",
  "continuingSessionLogsInPrivatelyThenSubmitsAnAuthenticatedFormAndSeesTheResult"),
 ("site login POST may go to any page origin", H + "RequestGate.swift",
  "            if phase == .login || phase == .submitted, !readOnly, !policy.credential.contains(origin) {\n"
  "                return .deny(.originMismatch)\n            }\n", "",
  "navigationCredentialAndResourceOriginsAreSeparate"),
 ("site subresources reach any origin", H + "RequestGate.swift",
  "        return .block\n    }\n\n    /// The filled form's POST", "        return .allow\n    }\n\n    /// The filled form's POST",
  "navigationCredentialAndResourceOriginsAreSeparate"),
 # Review findings on c4bdb69 (verification-logs/continuing-site/astra-review-v1.md), one or two each.
 ("site login ignores the submit button's formaction", H + "Recipe.swift",
  "                if (!Array.prototype.includes.call(origins, override.origin)) return \"origin\";\n", "",
  "loginSubmissionCannotBeRedirectedBySubmitterOrListener"),
 ("site login phase lets the filled form leave as a GET", H + "RequestGate.swift",
  "            if phase == .login && readOnly { return .deny(.unexpectedPage) }\n", "",
  "loginSubmissionCannotBeRedirectedBySubmitterOrListener"),
 ("site click lands at a point after the page moved", H + "Recipe.swift",
  "            HTMLElement.prototype.click.call(e);\n",
  "            setTimeout(() => HTMLElement.prototype.click.call(Document.prototype.elementFromPoint.call(document, x, y)), 100);\n",
  "inputReachesTheValidatedElementEvenWhenThePageMovesFocusOrReplacesIt"),
 ("site text goes to whatever has focus later", H + "Recipe.swift",
  '            Object.getOwnPropertyDescriptor(proto, "value").set.call(e, text);\n',
  '            HTMLElement.prototype.focus.call(e);\n'
  '            setTimeout(() => { const f = document.activeElement; Object.getOwnPropertyDescriptor(Object.getPrototypeOf(f), "value").set.call(f, text);'
  ' f.dispatchEvent(new Event("input", { bubbles: true })); }, 100);\n',
  "inputReachesTheValidatedElementEvenWhenThePageMovesFocusOrReplacesIt"),
 ("site observation ignores a takeover while reading", H + "SiteSession.swift",
  "            guard await currentDocument()?.document.epoch == page.epoch, holds(held) else { continue }\n",
  "            guard await currentDocument()?.document.epoch == page.epoch else { continue }\n",
  "takeoverWhileALoginOrObservationIsSuspendedFencesIt"),
 ("site login submits after a takeover and release", H + "SiteSession.swift",
  "        // Taken over, ended or replaced since the fill: the host submits nothing.\n        guard holds(held) else { return .siteUnknown }\n", "",
  "takeoverWhileALoginOrObservationIsSuspendedFencesIt",
  ('        guard case .sent(.string("ok")?) = await run(.loginSubmit, origins: policy.credential, [:], while: held) else {',
   '        guard case .sent(.string("ok")?) = await run(.loginSubmit, origins: policy.credential, [:]) else {'),
  # A fence also restores the agent phase, which the page-sent check below reads.
  ("        guard network?.phase == .login else { return await dispatched(loadedAfter: nil, judgingLogin: true) }\n", "")),
 ("site errors after dispatch become refusals and failures", H + "SiteSession.swift",
  "        guard !ended, network?.takeFailure() == nil else { return .siteUnknown }\n",
  "        if ended { return .rejected(.unknownRun) }\n        if let failure = network?.takeFailure() { return .failed(failure) }\n",
  "anEffectThatMayHaveCommittedIsNeverReportedAsARefusalOrFailure",
  ("        guard case .site(let page) = await observation() else { return .siteUnknown }\n        return .site(page)\n",
   "        return await observation()\n")),
 ("site observation has no aggregate budget", H + "Recipe.swift",
  "            let budget = \\(Self.observationBudget);\n", "            let budget = Infinity;\n",
  "anOversizedPageCannotEndTheBrowserForOtherSessions"),
 ("site login journal ignores the credential version", H + "SiteSession.swift",
  "        await journaled(operation, .login(account)) {\n",
  "        await journaled(operation, .login(CredentialVersion(item: UUID(uuid: UUID_NULL), version: 1)!)) {\n",
  "reusingALoginOperationForAnotherCredentialIsAConflict"),
 ("site login is signed in whenever no password shows", H + "SiteSession.swift",
  "            auth = policy.showsSignedIn(url) ? .signedIn : .unknown\n", "            auth = .signedIn\n",
  "signedInNeedsPositiveEvidenceNotAMissingPasswordField"),
 ("site sign-in survives a later password form", H + "SiteSession.swift",
  '            if auth == .signedIn && fields["password"]?.bool != false { auth = .unknown }\n', "",
  "signedInNeedsPositiveEvidenceNotAMissingPasswordField"),
 ("site takeover and release may answer a failure", H + "SiteSession.swift",
  "        let reply = await observation()\n        guard case .failed = reply, let page = document else { return reply }\n"
  "        return .site(summary(page.epoch))\n", "        return await observation()\n",
  "everySiteReplyTheHostProducesIsOneTheWireContractPermits"),
 ("site observe failure is outside the wire contract", "Sources/AgentVaultWebHostProtocol/HostCommand.swift",
  "(.siteObserve, .failed), ", "", "siteCommandsAcceptOnlySiteReplies"),
 # Review findings on 34ceaa9 (verification-logs/continuing-site/astra-review-v2.md).
 ("site login refuses after a fill that may have acted", H + "SiteSession.swift",
  "        case .sent: return .siteUnknown\n        }\n        try? await Task.sleep(for: timing.settle)\n",
  "        case .sent: return .rejected(.unsupportedLogin)\n        }\n        try? await Task.sleep(for: timing.settle)\n",
  "aLoginWhosePageActsOnTheFillIsNeverReportedAsARefusal"),
 ("site login ignores a form the page already sent", H + "SiteSession.swift",
  "        guard network?.phase == .login else { return await dispatched(loadedAfter: nil, judgingLogin: true) }\n", "",
  "aLoginWhosePageActsOnTheFillIsNeverReportedAsARefusal"),
 ("site login taken over after the fill claims it did nothing", H + "SiteSession.swift",
  "        guard holds(held) else { return .siteUnknown }\n", "        guard holds(held) else { return fenced }\n",
  "aLoginWhosePageActsOnTheFillIsNeverReportedAsARefusal"),
 ("site takeover leaves the login's fill in place", H + "SiteSession.swift",
  "        _ = await run(.loginClear, origins: policy.navigation + policy.credential, [:])\n    }\n", "    }\n",
  "loginCleanupNeverTouchesAFieldAfterTakeoverIsAcknowledged"),
 # Two layers: the handover marks the fill cleared, and the login clears only while it holds control.
 ("site login clears the field after a takeover", H + "SiteSession.swift",
  "policy.navigation + policy.credential, [:], while: held) }\n", "policy.navigation + policy.credential, [:]) }\n",
  "loginCleanupNeverTouchesAFieldAfterTakeoverIsAcknowledged",
  ("        guard filled else { return }\n        filled = false\n", "        guard filled else { return }\n")),
 ("site recipes read only an element's own disabled", H + "Recipe.swift",
  '        const disabled = (e) => Element.prototype.matches.call(e, ":disabled");\n',
  "        const disabled = (e) => e.disabled === true;\n",
  "controlsDisabledByAnAncestorAreNeitherObservedNorOperated"),
 ("site choice reads only an option's own disabled", H + "Recipe.swift",
  "e.options.length || disabled(e.options[option])) return", "e.options.length || e.options[option].disabled) return",
  "controlsDisabledByAnAncestorAreNeitherObservedNorOperated"),
]


def main():
    global LOG
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=pathlib.Path, help="retain full output at this fresh path")
    args = parser.parse_args()
    if args.log:
        LOG = args.log.resolve()
    if not os.environ.get("AGENT_VAULT_TEST_CHROMIUM"):
        print("AGENT_VAULT_TEST_CHROMIUM is required", flush=True)
        return 2
    LOG.parent.mkdir(exist_ok=True)
    with LOG.open("x" if args.log else "w") as log:
        os.fchmod(log.fileno(), 0o600)
    code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=900)
    filters = "|".join(sorted({m[4] for m in M}))
    if code == 0:
        code, out = harness.run_owned(["swift", "test", "--skip-build", "--filter", filters], timeout=TEST_TIMEOUT * 2)
    with open(LOG, "a") as log:
        log.write(f"=== baseline [{filters}] -> {code}\n{out}\n")
    if code != 0:
        print("baseline FAILED: targeted tests must pass before mutating", flush=True)
        return 2
    print("PASS: mutation baseline", flush=True)
    results = []
    for name, path, old, new, test, *also in M:
        source = ROOT / path
        original = source.read_bytes()
        text = original.decode()
        assert text.count(old) == 1, name
        mutated = text.replace(old, new)
        # A compound mutant also reverts a second, independent layer in the same file.
        for extra_old, extra_new in also:
            assert mutated.count(extra_old) == 1, name
            mutated = mutated.replace(extra_old, extra_new)
        with harness.changed_source(source, original, mutated.encode()):
            code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=900)
            if code != 0:
                status = "BUILD_FAILED"
            else:
                code, out = harness.run_owned(["swift", "test", "--skip-build", "--filter", test], timeout=TEST_TIMEOUT)
                status = "KILLED(hang)" if code is None else ("KILLED" if code != 0 else "SURVIVED")
        results.append((name, status))
        with open(LOG, "a") as log:
            log.write(f"=== {name} [{test}] -> {status}\n{out}\n")
        print(f"mutation {name}: {status}", flush=True)
    code, out = harness.run_owned(["swift", "build", "--build-tests", "-j", "8"], timeout=900)
    with LOG.open("a") as log:
        log.write(f"=== restored source build -> {code}\n{out}\n")
    if code != 0:
        print("FAIL: restored source build", flush=True)
        return 2
    return 0 if all(status.startswith("KILLED") for _, status in results) else 1


if __name__ == "__main__":
    with harness.interrupt_on_termination():
        sys.exit(main())
