import AgentVaultCredentials
@testable import AgentVaultWebHost
import AgentVaultBrowserFixture
import AgentVaultContracts
import AgentVaultWebHostProtocol
import Foundation
import Testing

// Continuing-site sessions against the real headless shell and the synthetic loopback site. These
// extend `RealBrowserTests`, so they run serialized with it and share its owned-browser cleanup.

private func observed(_ reply: HostReply) -> SiteObservation? { if case .site(let page) = reply { page } else { nil } }

private extension SiteObservation {
    func element(_ role: SiteRole, _ label: String) -> SiteElement? {
        elements.first { $0.role == role && $0.label == label }
    }
    func ref(_ role: SiteRole, _ label: String) -> SiteTarget? { element(role, label).flatMap(target) }
    func need(_ role: SiteRole, _ label: String) throws -> SiteTarget {
        guard let found = ref(role, label) else { throw Missing(description: "no \(role) \"\(label)\" on \(path)") }
        return found
    }
}

private let fixtureAccount = CredentialVersion(item: UUID(uuidString: "00000000-0000-4000-8000-0000000000a1")!, version: 1)!

private struct Missing: Error, CustomStringConvertible { let description: String }

private extension Host {
    func open(_ session: UUID = UUID(), lifetime: Int = 120) async -> (UUID, HostReply) {
        (session, await service.perform(.openSite(session: session, site: .syntheticFixture, lifetime: lifetime)))
    }

    func login(_ session: UUID, operation: UUID = UUID(), user: String = FixtureSite.loginName,
               password: String = FixtureSite.password, account: CredentialVersion = fixtureAccount) async -> HostReply {
        let credential = WebLoginCredential(FixtureSite.credential(user: user, password: password))!
        return await service.perform(.siteLogin(session: session, operation: operation, account: account, credential: credential))
    }

    func operate(_ session: UUID, _ command: SiteCommand, operation: UUID = UUID()) async -> HostReply {
        await service.perform(.siteOperate(session: session, operation: operation, command: command))
    }

    func observe(_ session: UUID) async -> HostReply { await service.perform(.siteObserve(session: session)) }

    func url(_ path: String) -> String { site.origin.absoluteString + path }

    /// Every request any fixture origin saw that carried the synthetic password.
    var passwordSightings: [FixtureRequest] {
        (site.trusted.requests + site.partner.requests + site.elsewhereRequests).filter {
            String(decoding: $0.body, as: UTF8.self).contains("synthetic-password") || $0.target.contains("synthetic-password")
        }
    }
}

/// The reply as the broker would receive it: nothing secret or session-bearing may be in it.
private func expectNoSecret(_ reply: HostReply, _ session: UUID, sourceLocation: SourceLocation = #_sourceLocation) throws {
    let wire = String(decoding: try HostWire.encode(HostResponse(request: 1, run: session, reply: reply)), as: UTF8.self)
    for forbidden in [FixtureSite.password, "sid=", "cookie", "HttpOnly"] {
        #expect(!wire.lowercased().contains(forbidden.lowercased()), "reply carries \(forbidden)", sourceLocation: sourceLocation)
    }
}

extension RealBrowserTests {
    @Test func continuingSessionLogsInPrivatelyThenSubmitsAnAuthenticatedFormAndSeesTheResult() async throws {
        try await Host.using { h in
            let (session, opened) = await h.open()
            let login = try #require(observed(opened))
            #expect(login.path == "/login" && login.auth == .signedOut && login.mode == .agent)
            let password = try #require(login.elements.first { $0.role == .password })
            #expect(password.value.isEmpty)

            let signedIn = await h.login(session)
            try expectNoSecret(signedIn, session)
            let home = try #require(observed(signedIn))
            #expect(home.auth == .signedIn && home.path == "/home" && home.document > login.document)
            #expect(h.posts.filter { $0.path == "/session" }.count == 1)

            let notes = try #require(observed(await h.operate(session, .click(try home.need(.link, "Notes")))))
            #expect(notes.path == "/notes" && notes.document > home.document)
            let typed = try #require(observed(await h.operate(session, .typePublic(try notes.need(.textField, "Note"),
                                                                                   "Buy synthetic milk"))))
            #expect(typed.document == notes.document && typed.element(.textField, "Note")?.value == "Buy synthetic milk")
            let chosen = try #require(observed(await h.operate(session, .select(try typed.need(.select, "Priority"), option: 1))))
            #expect(chosen.element(.select, "Priority")?.value == "high")

            let save = SiteCommand.click(try chosen.need(.submit, "Save note"))
            let submitID = UUID()
            let submitted = await h.operate(session, save, operation: submitID)
            try expectNoSecret(submitted, session)
            let result = try #require(observed(submitted))
            #expect(result.path == "/notes" && result.document > chosen.document)
            #expect(result.text.contains("Saved: Buy synthetic milk (high)"))
            #expect(h.site.notes == ["Buy synthetic milk (high)"])
            // The same context kept the private login: the submission carried its session cookie.
            let notePost = try #require(h.posts.last { $0.path == "/notes" })
            #expect(notePost.headers["cookie"]?.contains("sid=") == true)

            let again = try #require(observed(await h.observe(session)))
            #expect(again.text.contains("Saved: Buy synthetic milk (high)") && again.auth == .signedIn)

            // Retrying the operation returns its first reply and never submits again; reusing the
            // ID for anything else is refused; a new ID cannot reuse the old document's target.
            #expect(await h.operate(session, save, operation: submitID) == submitted)
            #expect(await h.operate(session, .scroll(dy: 100), operation: submitID) == .rejected(.operationConflict))
            #expect(await h.operate(session, save) == .rejected(.staleTarget))
            #expect(h.site.notes.count == 1)

            #expect(h.passwordSightings.allSatisfy { $0.path == "/session" && $0.method == "POST" })
            #expect(h.passwordSightings.count == 1, "the password reached only the trusted login POST, once")
            #expect(h.site.partner.requests.isEmpty && h.site.elsewhereRequests.isEmpty)

            #expect(await h.service.perform(.end(run: session)) == .ended)
            #expect(await h.service.liveSessions == 0)
            #expect(await h.observe(session) == .rejected(.unknownRun))
            #expect(await h.operate(session, .scroll(dy: 100)) == .rejected(.unknownRun))
        }
    }

    @Test func targetsAreBoundToTheirSessionDocumentAndControlEpoch() async throws {
        try await Host.using { h in
            let (first, firstReply) = await h.open()
            let (second, secondReply) = await h.open()
            let a = try #require(observed(firstReply)), b = try #require(observed(secondReply))
            #expect(a.document != b.document, "document epochs are host-wide")
            let user = try #require(a.elements.first { $0.role == .textField }.flatMap(a.target))
            #expect(await h.operate(second, .typePublic(user, "cross")) == .rejected(.staleTarget), "another session's target")
            let field = try #require(a.elements.first { $0.role == .password }.flatMap(a.target))
            #expect(await h.operate(first, .typePublic(field, "guess")) == .rejected(.notPermitted), "password fields are never typed into")

            // Takeover fences every agent command and expires earlier targets for good.
            let taken = try #require(observed(await h.service.perform(.siteTakeover(session: first))))
            #expect(taken.mode == .human && taken.control > a.control && taken.elements.isEmpty && taken.text.isEmpty)
            #expect(await h.observe(first) == .rejected(.humanControl))
            #expect(await h.operate(first, .typePublic(user, "during")) == .rejected(.humanControl))
            #expect(await h.login(first) == .rejected(.humanControl))
            let released = try #require(observed(await h.service.perform(.siteRelease(session: first))))
            #expect(released.mode == .agent && released.control > taken.control && released.document == a.document)
            #expect(await h.operate(first, .typePublic(user, "after")) == .rejected(.staleTarget), "a target from before takeover")
            let fresh = try #require(released.elements.first { $0.role == .textField }.flatMap(released.target))
            let typed = try #require(observed(await h.operate(first, .typePublic(fresh, "after"))))
            #expect(typed.elements.first { $0.role == .textField }?.value == "after")

            // One operation at a time: a second command while the first is in flight is refused, not queued.
            async let pending = h.operate(first, .navigate(h.url("/login")))
            try await Task.sleep(for: .milliseconds(40))
            #expect(await h.observe(first) == .rejected(.busy))
            #expect(await h.operate(first, .press(.tab)) == .rejected(.busy))
            #expect(observed(await pending) != nil)

            // A navigation replaces the document: its targets expire.
            let moved = try #require(observed(await h.operate(first, .navigate(h.url("/login")))))
            #expect(moved.document > typed.document)
            #expect(await h.operate(first, .typePublic(fresh, "stale")) == .rejected(.staleTarget))

            // Fixed runs and sessions never accept each other's commands.
            let (run, paused) = await h.start(user: "mfa-user")
            #expect(paused == .humanStep(.mfa))
            #expect(await h.observe(run) == .rejected(.unknownRun))
            #expect(await h.operate(run, .navigate(h.url("/home"))) == .rejected(.unknownRun))
            #expect(await h.service.perform(.siteTakeover(session: run)) == .rejected(.unknownRun))
            #expect(await h.service.perform(.classify(run: second)) == .rejected(.unknownRun))
            #expect(await h.service.perform(.showHuman(run: second, step: 1)) == .rejected(.unknownRun))
            #expect(await h.service.perform(.openSite(session: run, site: .syntheticFixture, lifetime: 60)) == .rejected(.duplicateRun))
            await h.service.end(run)
            #expect(await h.service.perform(.openSite(session: run, site: .syntheticFixture, lifetime: 60)) == .rejected(.unknownRun))
            await h.service.end(first); await h.service.end(second)
            #expect(await h.service.liveSessions == 0)
            #expect(await h.service.liveRuns == 0)
        }
    }

    @Test func credentialEligibilityComesFromTheObservedPageNeverTheCallerURL() async throws {
        try await Host.using { h in
            let (session, _) = await h.open()
            // A navigable origin that is not a credential origin, reached directly or by a redirect
            // from a credential-origin URL: the observed page decides, and nothing is filled.
            let partner = try #require(observed(await h.operate(session, .navigate(h.site.partner.origin + "/signin"))))
            #expect(partner.origin == h.site.partner.origin && partner.elements.contains { $0.role == .password })
            #expect(await h.login(session) == .rejected(.credentialOrigin))
            let redirected = try #require(observed(await h.operate(session, .navigate(h.url("/to-partner")))))
            #expect(redirected.origin == h.site.partner.origin)
            #expect(await h.login(session) == .rejected(.credentialOrigin))
            #expect(h.site.partner.requests.allSatisfy { $0.method == "GET" }, "the partner never received a form post")
            #expect(h.passwordSightings.isEmpty)

            // Off-policy destinations: refused before loading, or stopped by the gate after a redirect.
            #expect(await h.operate(session, .navigate(h.site.elsewhere.origin + "/x")) == .rejected(.notPermitted))
            #expect(await h.operate(session, .navigate("javascript:alert(1)")) == .rejected(.notPermitted))
            // The site saw the request (and redirected), so the effect is unknown, not a failure.
            #expect(await h.operate(session, .navigate(h.url("/to-elsewhere"))) == .siteUnknown)
            let stranded = try #require(observed(await h.observe(session)))
            #expect(stranded.origin.isEmpty && stranded.elements.isEmpty, "a refused page shows nothing")

            _ = await h.operate(session, .navigate(h.url("/login")))
            let home = try #require(observed(await h.login(session)))
            #expect(home.auth == .signedIn)
            let notes = try #require(observed(await h.operate(session, .navigate(h.url("/notes")))))
            #expect(await h.operate(session, .click(try notes.need(.link, "Leave"))) == .siteUnknown)
            let back = try #require(observed(await h.operate(session, .navigate(h.url("/notes")))))
            let leak = try back.need(.textField, "Leak")
            let filled = try #require(observed(await h.operate(session, .typePublic(leak, "public words"))))
            // The document's CSP refuses the off-policy form in the renderer, or the gate refuses its request.
            let sent = await h.operate(session, .click(try filled.need(.submit, "Send elsewhere")))
            #expect(sent == .siteUnknown || observed(sent)?.path == "/notes", "\(sent)")
            #expect(h.site.elsewhereRequests.isEmpty, "no request ever reached the off-policy origin")
            // The session survives refusals and carries on.
            #expect(observed(await h.operate(session, .navigate(h.url("/notes"))))?.path == "/notes")
            // A credential-origin page without a login form: nothing is filled.
            #expect(await h.login(session) == .rejected(.unsupportedLogin))
            #expect(h.passwordSightings.count == 1)
        }
    }

    @Test func loginOutcomesAreTypedAndAOneTimeCodeHandsTheSessionToAPerson() async throws {
        try await Host.using { h in
            let (wrong, _) = await h.open()
            let rejected = try #require(observed(await h.login(wrong, password: "wrong")))
            #expect(rejected.auth == .rejected && rejected.mode == .agent)

            let (mfa, _) = await h.open()
            let step = try #require(observed(await h.login(mfa, user: "mfa-user")))
            #expect(step.auth == .humanRequired && step.mode == .human && step.elements.isEmpty)
            #expect(await h.observe(mfa) == .rejected(.humanControl))
            #expect(await h.operate(mfa, .press(.enter)) == .rejected(.humanControl))
            let released = try #require(observed(await h.service.perform(.siteRelease(session: mfa))))
            #expect(released.mode == .agent && released.auth == .humanRequired, "the code is still required")

            // An ambiguous form is refused before anything is filled or posted.
            h.site.loginPage = .duplicateLoginFields
            let (ambiguous, _) = await h.open()
            #expect(await h.login(ambiguous) == .rejected(.unsupportedLogin))
            #expect(h.posts.filter { $0.path == "/session" }.count == 2, "only the two earlier logins posted")
        }
    }

    @Test func lifetimeEndAndTeardownStopSessionsAndProductionCompilesNoSite() async throws {
        try await Host.using { h in
            let (session, opened) = await h.open(lifetime: 2)
            #expect(observed(opened) != nil)
            #expect(await eventually(5) { await h.service.liveSessions == 0 }, "the host's own lifetime cap ends the session")
            #expect(await h.observe(session) == .rejected(.unknownRun))
            #expect(await h.open(session).1 == .rejected(.unknownRun), "an expired session ID never opens again")

            let (other, _) = await h.open()
            #expect(await h.service.perform(.siteTakeover(session: other)) != .rejected(.unknownRun))
            await h.service.teardown()
            #expect(await h.service.liveSessions == 0)
            #expect(await h.observe(other) == .rejected(.unknownRun))
            #expect(await h.open().1 == .rejected(.unknownRun), "nothing opens after teardown")
        }
        // Production policy: the site path exists but nothing can open it, and no browser starts.
        let production = HostService(policy: .production, binary: URL(fileURLWithPath: "/nonexistent"),
                                     runDirectory: FileManager.default.temporaryDirectory, onFatal: {})
        #expect(await production.perform(.openSite(session: UUID(), site: .syntheticFixture, lifetime: 60))
                == .rejected(.unsupportedSite))
        #expect(await production.launched == nil)
    }
}

/// Runs `action` once, the first time `session` reaches `point`, while the session waits there.
private func at(_ point: SiteSession.Checkpoint, of session: UUID, _ action: @escaping @Sendable () async -> Void) {
    let once = Flag()
    SiteSession.hooks.hook = { id, reached in
        guard id == session, reached == point, !once.isSet else { return }
        once.set()
        await action()
    }
}

// Regressions for the eight source-review findings on c4bdb69 (verification-logs/continuing-site/astra-review-v1.md).
extension RealBrowserTests {
    /// Finding 1: the submit button's overrides, or a submit listener, must not send the filled
    /// credential to a navigation-only origin.
    @Test(arguments: [FixtureSite.LoginPage.submitterOverridesToPartner, .submitterTargetsFrame,
                      .submitListenerRedirectsToPartner, .submitListenerTargetsFrame])
    func loginSubmissionCannotBeRedirectedBySubmitterOrListener(_ variant: FixtureSite.LoginPage) async throws {
        try await Host.using { h in
            h.site.loginPage = variant
            let (session, opened) = await h.open()
            #expect(observed(opened)?.path == "/login")
            let reply = await h.login(session)
            if variant == .submitterOverridesToPartner || variant == .submitterTargetsFrame {
                #expect(reply == .rejected(.credentialOrigin), "refused before anything is filled: \(reply)")
            } else {
                // The listener runs after the host's checks and the submission; the gate refuses what it
                // rewrote. The form was submitted, so the result is unknown rather than a refusal.
                #expect(reply == .siteUnknown, "\(reply)")
            }
            #expect(h.passwordSightings.isEmpty, "the password left the browser: \(h.passwordSightings.map(\.target))")
            #expect(!h.site.partner.requests.contains { $0.path == "/collect" }, "the partner received the login")
            #expect(h.posts.filter { $0.path == "/session" }.isEmpty)
        }
    }

    @Test func aSubmitButtonWhoseOverridesStayOnACredentialOriginStillLogsIn() async throws {
        try await Host.using { h in
            h.site.loginPage = .submitterOverridesWithinPolicy
            let (session, _) = await h.open()
            #expect(observed(await h.login(session))?.auth == .signedIn)
            #expect(h.passwordSightings.count == 1 && h.passwordSightings.allSatisfy { $0.path == "/session" && $0.method == "POST" })
        }
    }

    /// Finding 2: the element that was checked is the element that receives the input, even if
    /// the page moves focus to a password field or swaps the button between check and action.
    @Test func inputReachesTheValidatedElementEvenWhenThePageMovesFocusOrReplacesIt() async throws {
        try await Host.using { h in
            defer { SiteSession.hooks.hook = nil }
            let (session, _) = await h.open()
            let page = try #require(observed(await h.operate(session, .navigate(h.url("/focus-trap")))))
            // A slow browser: 300 ms before the host acts, long after the page's own 50 ms timers.
            SiteSession.hooks.hook = { id, point in
                if id == session && point == .beforeInput { try? await Task.sleep(for: .milliseconds(300)) }
            }
            let typed = try #require(observed(await h.operate(session, .typePublic(try page.need(.textField, "Search"), "public words"))))
            #expect(typed.element(.textField, "Search")?.value == "public words")
            #expect(!typed.text.contains("secret field received input"), "the text went to the password field")
            let clicked = try #require(observed(await h.operate(session, .click(try typed.need(.button, "Save")))))
            #expect(!clicked.text.contains("delete clicked"), "the click hit the replacement button")
            #expect(clicked.text.contains("save clicked"))
            // The swapped-in button is a new element: the old target cannot reach it.
            #expect(await h.operate(session, .click(try typed.need(.button, "Save"))) == .rejected(.staleTarget))
            #expect(observed(await h.observe(session))?.text.contains("delete clicked") == false)
        }
    }

    /// Finding 3: a takeover while a login or observation is suspended fences what resumes.
    @Test func takeoverWhileALoginOrObservationIsSuspendedFencesIt() async throws {
        try await Host.using { h in
            defer { SiteSession.hooks.hook = nil }
            // Taken over and released at once: the mode is the agent's again, the generation is not.
            for point in [SiteSession.Checkpoint.loginDocument, .loginFilled] {
                let (session, _) = await h.open()
                at(point, of: session) {
                    _ = await h.service.perform(.siteTakeover(session: session))
                    _ = await h.service.perform(.siteRelease(session: session))
                }
                let reply = await h.login(session)
                // Before the fill nothing was done; after it, the page may have acted on the filled form.
                #expect(reply == (point == .loginDocument ? .rejected(.staleTarget) : .siteUnknown), "\(point): \(reply)")
                #expect(h.posts.filter { $0.path == "/session" }.isEmpty, "\(point): submitted under a later control epoch")
                await h.service.end(session)
            }
            // Taken over and kept: nothing is filled or submitted while the person has control.
            let (kept, _) = await h.open()
            at(.loginDocument, of: kept) { _ = await h.service.perform(.siteTakeover(session: kept)) }
            #expect(await h.login(kept) == .rejected(.humanControl))
            #expect(h.posts.filter { $0.path == "/session" }.isEmpty)

            let (session, _) = await h.open()
            at(.observed, of: session) { _ = await h.service.perform(.siteTakeover(session: session)) }
            let seen = try #require(observed(await h.observe(session)))
            #expect(seen.mode == .human)
            #expect(seen.elements.isEmpty && seen.text.isEmpty && seen.title.isEmpty, "contents released during human control")

            // Untargeted input and navigation are fenced the same way.
            _ = await h.service.perform(.siteRelease(session: session))
            at(.beforeInput, of: session) { _ = await h.service.perform(.siteTakeover(session: session)) }
            #expect(await h.operate(session, .navigate(h.url("/home"))) == .rejected(.humanControl))
            #expect(!h.site.trusted.requests.contains { $0.path == "/home" }, "the navigation was sent")
            _ = await h.service.perform(.siteRelease(session: session))
            at(.beforeInput, of: session) { _ = await h.service.perform(.siteTakeover(session: session)) }
            #expect(await h.operate(session, .press(.enter)) == .rejected(.humanControl))
        }
    }

    /// Finding 4: once input may have reached the site, later errors leave the effect unknown.
    @Test func anEffectThatMayHaveCommittedIsNeverReportedAsARefusalOrFailure() async throws {
        try await Host.using { h in
            defer { SiteSession.hooks.hook = nil }
            let (session, _) = await h.open()
            _ = await h.login(session)
            let notes = try #require(observed(await h.operate(session, .navigate(h.url("/notes")))))
            let typed = try #require(observed(await h.operate(session, .typePublic(try notes.need(.textField, "Note"), "committed"))))
            // The submission reaches the site and commits; the session ends while it settles.
            let save = SiteCommand.click(try typed.need(.submit, "Save note")), operation = UUID()
            at(.dispatched, of: session) {
                _ = await eventually { h.site.notes.count == 1 }
                await h.service.end(session)
            }
            let ended = await h.operate(session, save, operation: operation)
            #expect(h.site.notes == ["committed (low)"])
            #expect(ended == .siteUnknown, "\(ended)")
            // The submission commits, then the page it lands on cannot be observed.
            let (other, _) = await h.open()
            let form = try #require(observed(await h.operate(other, .navigate(h.url("/commit-churn")))))
            let commit = SiteCommand.click(try form.need(.submit, "Save")), committing = UUID()
            #expect(await h.operate(other, commit, operation: committing) == .siteUnknown)
            #expect(h.site.notes.count == 2)
            // The unknown result is what a retry gets; it is never dispatched again.
            #expect(await h.operate(other, commit, operation: committing) == .siteUnknown)
            #expect(h.site.notes.count == 2)
        }
    }

    /// Finding 8: what the host answers on a page that never holds still is what the wire permits,
    /// and a change of control is always reported, so `WebHostServer` never turns it into `unavailable`.
    @Test func everySiteReplyTheHostProducesIsOneTheWireContractPermits() async throws {
        try await Host.using { h in
            let (session, _) = await h.open()
            let operate = HostCommand.siteOperate(session: session, operation: UUID(), command: .navigate(h.url("/churn")))
            let churn = await h.service.perform(operate)
            #expect(churn.answers(operate) && churn == .siteUnknown, "\(churn)")
            let seen = await h.observe(session)
            #expect(seen.answers(.siteObserve(session: session)), "\(seen)")
            let taken = await h.service.perform(.siteTakeover(session: session))
            #expect(taken.answers(.siteTakeover(session: session)) && observed(taken)?.mode == .human, "\(taken)")
            let released = await h.service.perform(.siteRelease(session: session))
            #expect(released.answers(.siteRelease(session: session)), "\(released)")
            let back = try #require(observed(released), "control returned, but the reply says otherwise")
            #expect(back.mode == .agent && back.control > (observed(taken)?.control ?? 0))
        }
    }

    /// Finding 5: one page's observation is bounded before the browser serializes it, so it cannot
    /// break the shared pipe and end every other session.
    @Test func anOversizedPageCannotEndTheBrowserForOtherSessions() async throws {
        try await Host.using { h in
            let (bystander, _) = await h.open()
            let (session, _) = await h.open()
            let huge = try #require(observed(await h.operate(session, .navigate(h.url("/huge")))))
            #expect(!h.fatal.isSet, "one page ended the shared browser")
            #expect(observed(await h.observe(bystander))?.path == "/login", "another session was lost")
            #expect(huge.path == "/huge" && huge.elements.contains { $0.role == .select && !$0.options.isEmpty })
            let wire = try HostWire.encode(HostResponse(request: HostWire.maximumCounter, run: session, reply: .site(huge)))
            #expect(wire.count <= HostWire.maximumReplyBytes)
        }
    }

    /// Finding 6: a login operation ID is bound to the credential version it used. A retry, even
    /// one that crossed the wire again (a new credential object), gets the first reply; the same ID
    /// with another credential version, or another item, is refused and nothing is submitted.
    @Test func reusingALoginOperationForAnotherCredentialIsAConflict() async throws {
        try await Host.using { h in
            let (session, _) = await h.open()
            let operation = UUID()
            let first = await h.login(session, operation: operation)
            #expect(observed(first)?.auth == .signedIn)
            let rotated = CredentialVersion(item: fixtureAccount.item, version: 2)!
            let other = CredentialVersion(item: UUID(), version: 1)!
            #expect(await h.login(session, operation: operation, password: "rotated-password", account: rotated) == .rejected(.operationConflict))
            #expect(await h.login(session, operation: operation, user: "other-user", account: other) == .rejected(.operationConflict))
            let credential = WebLoginCredential(FixtureSite.credential())!
            let retry = HostRequest(id: 9, command: .siteLogin(session: session, operation: operation, account: fixtureAccount,
                                                               credential: credential))
            let decoded = try HostWire.decodeRequest(try HostWire.encode(retry))
            #expect(await h.service.perform(decoded.command) == first, "a serialized retry gets the first reply")
            #expect(h.posts.filter { $0.path == "/session" }.count == 1)
        }
    }

    /// Finding 7: signed in needs the policy's positive evidence; a page without a password field
    /// (a CAPTCHA, an error page) is unknown, and a login form later withdraws the claim.
    @Test func signedInNeedsPositiveEvidenceNotAMissingPasswordField() async throws {
        try await Host.using { h in
            for (user, path) in [("captcha-user", "/captcha"), ("error-user", "/oops")] {
                let (session, _) = await h.open()
                let page = try #require(observed(await h.login(session, user: user)))
                #expect(page.auth == .unknown && page.mode == .agent && page.path == path, "\(user): \(page.auth) on \(page.path)")
            }
            let (session, _) = await h.open()
            #expect(observed(await h.login(session))?.auth == .signedIn)
            #expect(observed(await h.operate(session, .navigate(h.url("/notes"))))?.auth == .signedIn, "an ordinary signed-in page")
            let back = try #require(observed(await h.operate(session, .navigate(h.url("/login")))))
            #expect(back.auth == .unknown, "a login form again, still reported signed in")
            #expect(observed(await h.operate(session, .navigate(h.url("/home"))))?.auth == .unknown, "only a login establishes it")
        }
    }
}

// Regressions for the three source-review findings on 34ceaa9 (verification-logs/continuing-site/astra-review-v2.md).
extension RealBrowserTests {
    /// Finding 1: filling dispatches events the page can act on, even by submitting the form. From
    /// the fill on, a login answers with what the host then observes or `siteUnknown`, never a refusal.
    @Test func aLoginWhosePageActsOnTheFillIsNeverReportedAsARefusal() async throws {
        try await Host.using { h in
            defer { SiteSession.hooks.hook = nil }
            // The password field's input listener submits the form; its response lands on /home before
            // the host looks at the page again.
            h.site.loginPage = .fillListenerSubmits
            let (session, _) = await h.open()
            at(.loginFilled, of: session) {
                _ = await eventually { h.site.trusted.requests.contains { $0.path == "/home" } }
                try? await Task.sleep(for: .milliseconds(500))
            }
            let operation = UUID()
            let reply = await h.login(session, operation: operation)
            #expect(h.posts.filter { $0.path == "/session" }.count == 1, "the page's own submission, sent once")
            #expect(observed(reply)?.auth == .signedIn && observed(reply)?.path == "/home", "\(reply)")
            #expect(await h.login(session, operation: operation) == reply, "a retry gets the first reply")
            #expect(h.posts.filter { $0.path == "/session" }.count == 1)
            #expect(h.passwordSightings.allSatisfy { $0.path == "/session" && $0.method == "POST" })

            // The username's listener submits, then breaks the fill: the recipe throws after the page acted.
            h.site.loginPage = .fillListenerBreaksFill
            let (broken, _) = await h.open()
            let failing = UUID()
            let unknown = await h.login(broken, operation: failing)
            #expect(await eventually { h.posts.filter { $0.path == "/session" }.count == 2 }, "the page submitted the form")
            #expect(unknown == .siteUnknown, "\(unknown)")
            #expect(await h.login(broken, operation: failing) == .siteUnknown)
            #expect(h.posts.filter { $0.path == "/session" }.count == 2)

            // Taken over once the fill has run: the host submits nothing, and does not claim it did nothing.
            h.site.loginPage = .normal
            let (taken, _) = await h.open()
            at(.loginFilled, of: taken) { _ = await h.service.perform(.siteTakeover(session: taken)) }
            #expect(await h.login(taken) == .siteUnknown)
            #expect(h.posts.filter { $0.path == "/session" }.count == 2)
        }
    }

    /// Finding 3: a control disabled by its fieldset, or an option in a disabled group, is disabled.
    /// It is never observed as operable, and typing or choosing is refused before any event fires.
    @Test func controlsDisabledByAnAncestorAreNeitherObservedNorOperated() async throws {
        try await Host.using { h in
            let (session, _) = await h.open()
            let page = try #require(observed(await h.operate(session, .navigate(h.url("/disabled")))))
            #expect(page.ref(.textField, "Locked note") == nil, "a field in a disabled fieldset was offered")
            let inside = try page.need(.textField, "Inside"), size = try page.need(.select, "Inside size")

            let priority = try page.need(.select, "Priority")
            #expect(await h.operate(session, .select(priority, option: 1)) == .rejected(.staleTarget))
            let locked = try #require(observed(await h.operate(session, .click(try page.need(.button, "Lock")))))
            #expect(locked.ref(.textField, "Inside") == nil && locked.ref(.select, "Inside size") == nil)
            #expect(await h.operate(session, .typePublic(inside, "words")) == .rejected(.staleTarget))
            #expect(await h.operate(session, .select(size, option: 1)) == .rejected(.staleTarget))

            let after = try #require(observed(await h.observe(session)))
            #expect(after.element(.select, "Priority")?.value == "open")
            #expect(!after.text.contains { $0.hasPrefix("input on") || $0.hasPrefix("change on") }, "events fired: \(after.text)")
            // An enabled option in the same select is still chosen.
            #expect(observed(await h.operate(session, .select(try after.need(.select, "Priority"), option: 0)))?
                .text.contains("change on Priority") == true)
        }
    }
}
