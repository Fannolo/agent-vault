import AgentVaultBrowser
import AgentVaultBrowserFixture
import Foundation
import Testing
import WebKit

@Suite(.serialized) @MainActor
struct BrowserWorkflowTests {
    @Test func demoWorkflowReturnsTypedProfileAndDestroysSession() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        let outcome = await h.run()
        #expect(outcome == .profile(WebProfile(login: "fixture-user", userID: 4242)))
        #expect(!h.manager.hasSession(accountID: h.account))
        let paths = h.site.trusted.requests.map(\.path)
        #expect(paths.contains("/pixel") && paths.contains("/script.js"))   // same-origin subresources still load
        #expect(h.site.elsewhereRequests.isEmpty)
    }

    @Test func rejectedPasswordFailsWithoutProfile() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        #expect(await h.run(password: "wrong") == .failed(.loginRejected))
        #expect(!h.manager.hasSession(accountID: h.account))
    }

    @Test func malformedCredentialNeverReachesAWebView() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        for bad in [Data(), Data("only-one-line".utf8), Data("user\n".utf8), Data("\npw".utf8),
                    Data("user\npw\u{7}".utf8), Data([0xFF, 0x0A, 0x41])] {
            #expect(await h.manager.run(.demo, accountID: h.account, credential: bad) == .failed(.invalidCredential))
        }
        #expect(h.site.trusted.requests.isEmpty)
    }

    @Test func workflowsNotInThePolicyAreUnsupported() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        #expect(await h.manager.run(.githubWebProfile, accountID: h.account,
                                     credential: FixtureSite.credential()) == .failed(.unsupportedWorkflow))
        let production = BrowserSessionManager(policy: .production)
        #expect(await production.run(.demo, accountID: UUID(),
                                      credential: FixtureSite.credential()) == .failed(.unsupportedWorkflow))
        #expect(h.site.trusted.requests.isEmpty)
    }

    @Test func concurrentRunForOneAccountIsBusy() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        async let first = h.run()
        async let second = h.run()
        let outcomes = await [first, second]
        #expect(outcomes.contains(.failed(.busy)))
        #expect(outcomes.contains(.profile(WebProfile(login: "fixture-user", userID: 4242))))
    }

    // MARK: Hostile origins

    @Test(arguments: [FixtureSite.LoginPage.redirectToElsewhere, .redirectToSameHostOtherName,
                      .metaRefreshToElsewhere, .scriptNavigationToElsewhere, .frameFromElsewhere])
    func offOriginNavigationIsBlockedBeforeCredentialsAreUsed(page: FixtureSite.LoginPage) async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.loginPage = page
        #expect(await h.run() == .failed(.originMismatch))
        #expect(h.site.elsewhereRequests.isEmpty, "the browser must not reach another origin")
        #expect(h.trustedPosts.isEmpty, "no credential may be submitted from a hostile page")
        #expect(!h.manager.hasSession(accountID: h.account))
    }

    @Test func popupsAreNeverCreated() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.loginPage = .openPopup
        _ = await h.run()
        #expect(h.site.elsewhereRequests.isEmpty)
    }

    @Test func formPostingToAnotherOriginGetsNoCredentials() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.loginPage = .formPostsToElsewhere
        #expect(await h.run() == .failed(.unexpectedPage))
        #expect(h.site.elsewhereRequests.isEmpty)
        #expect(h.trustedPosts.isEmpty)
    }

    @Test func ambiguousLoginFieldsAreNotFilled() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.loginPage = .duplicateLoginFields
        #expect(await h.run() == .failed(.unexpectedPage))
        #expect(h.trustedPosts.isEmpty)
    }

    @Test func subresourcesFromOtherOriginsAreBlockedButLoginStillWorks() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.loginPage = .subresourcesFromElsewhere
        #expect(await h.run() == .profile(WebProfile(login: "fixture-user", userID: 4242)))
        #expect(h.site.elsewhereRequests.isEmpty, "images and scripts from another origin must not load")
    }

    // MARK: Reflection

    @Test func reflectedDuplicateMetaInHeadIsRejected() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.profile = .reflectedMetaInHead
        #expect(await h.run() == .failed(.invalidProfile))
    }

    @Test(arguments: [FixtureSite.Profile.reflectedMetaInBody, .reflectedEscapedText])
    func reflectedMarkupOutsideTheFixedHeadFieldsDoesNotChangeOutput(profile: FixtureSite.Profile) async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.profile = profile
        #expect(await h.run() == .profile(WebProfile(login: "fixture-user", userID: 4242)))
    }

    @Test func profileValuesAreValidatedBeforeTheyLeave() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.profile = .invalidLogin
        #expect(await h.run() == .failed(.invalidProfile))
    }

    // MARK: Human steps

    @Test(arguments: [("mfa-user", HumanStepKind.mfa), ("captcha-user", .captcha)])
    func humanStepsPauseWithoutBypassAndResumeAfterThePerson(user: String, kind: HumanStepKind) async throws {
        let h = try await Harness.make(); defer { h.finish() }
        #expect(await h.run(user: user) == .humanStepRequired(kind))
        #expect(h.manager.hasSession(accountID: h.account))
        #expect(h.manager.humanContinuationView(accountID: h.account)?.kind == kind)
        #expect(h.trustedPosts.count == 1, "only the login post; the step form is never submitted automatically")
        // Still waiting on the person: continuing early reports the same step, not a profile.
        #expect(await h.manager.continueAfterHuman(accountID: h.account) == .humanStepRequired(kind))
        try await h.humanSubmitsCurrentForm()
        #expect(await h.manager.continueAfterHuman(accountID: h.account)
                == .profile(WebProfile(login: "fixture-user", userID: 4242)))
        #expect(!h.manager.hasSession(accountID: h.account))
    }

    @Test func humanViewExistsOnlyWhileAStepIsPending() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        #expect(h.manager.humanContinuationView(accountID: h.account) == nil)
        _ = await h.run()
        #expect(h.manager.humanContinuationView(accountID: h.account) == nil)
    }

    @Test func unfinishedHumanStepExpires() async throws {
        let h = try await Harness.make(humanPause: .milliseconds(400)); defer { h.finish() }
        #expect(await h.run(user: "mfa-user") == .humanStepRequired(.mfa))
        try await Task.sleep(for: .milliseconds(900))
        #expect(!h.manager.hasSession(accountID: h.account))
        #expect(await h.manager.continueAfterHuman(accountID: h.account) == .failed(.sessionUnavailable))
    }

    // MARK: Session invalidation

    @Test func revokeDestroysPausedSessionAndItsWebView() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        #expect(await h.run(user: "mfa-user") == .humanStepRequired(.mfa))
        weak let weakView = h.manager.testWebView(accountID: h.account)
        #expect(weakView != nil)
        h.manager.revoke(accountID: h.account)
        #expect(!h.manager.hasSession(accountID: h.account))
        #expect(h.manager.humanContinuationView(accountID: h.account) == nil)
        #expect(await h.manager.continueAfterHuman(accountID: h.account) == .failed(.sessionUnavailable))
        for _ in 0..<40 where weakView != nil { try await Task.sleep(for: .milliseconds(50)) }
        #expect(weakView == nil, "the web view must be released after revocation")
        // After revocation the server-side session cookie is no longer reachable from any browser state.
        #expect(h.manager.activeAccountIDs.isEmpty)
    }

    @Test func revokeCancelsRunInFlight() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        h.site.loginPage = .stall
        let started = ContinuousClock.now
        async let outcome = h.run()
        try await Task.sleep(for: .milliseconds(600))
        h.manager.revoke(accountID: h.account)
        #expect(await outcome == .failed(.sessionRevoked))
        #expect(ContinuousClock.now - started < .seconds(3), "revocation must not wait for the slow page")
        #expect(h.trustedPosts.isEmpty)
    }

    @Test func revokeBeforeSessionStartsStillWins() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        async let outcome = h.run()
        await Task.yield()
        h.manager.revoke(accountID: h.account)
        #expect(await outcome == .failed(.sessionRevoked))
        #expect(h.trustedPosts.isEmpty)
    }

    @Test func accountsUseSeparateEphemeralDataStores() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        let other = UUID()
        #expect(await h.run(user: "mfa-user") == .humanStepRequired(.mfa))
        #expect(await h.manager.run(.demo, accountID: other,
                                     credential: FixtureSite.credential(user: "captcha-user")) == .humanStepRequired(.captcha))
        let a = try #require(h.manager.testWebView(accountID: h.account))
        let b = try #require(h.manager.testWebView(accountID: other))
        #expect(!a.configuration.websiteDataStore.isPersistent && !b.configuration.websiteDataStore.isPersistent)
        #expect(a.configuration.websiteDataStore !== b.configuration.websiteDataStore)
        let cookiesA = await a.configuration.websiteDataStore.httpCookieStore.allCookies()
        let cookiesB = await b.configuration.websiteDataStore.httpCookieStore.allCookies()
        #expect(cookiesA.count == 1 && cookiesB.count == 1)
        #expect(cookiesA.first?.value != cookiesB.first?.value)
        // Revoking one account leaves the other session intact.
        h.manager.revoke(accountID: h.account)
        #expect(h.manager.hasSession(accountID: other))
    }

    // MARK: Output

    @Test func replyCarriesOnlyTypedFields() async throws {
        let h = try await Harness.make(); defer { h.finish() }
        let outcome = await h.run()
        let json = String(decoding: try JSONEncoder().encode(outcome.readReply()), as: UTF8.self)
        #expect(json.contains("fixture-user") && json.contains("completed"))
        for forbidden in [FixtureSite.password, "<html", "sid=", "cookie", "127.0.0.1", "/login"] {
            #expect(!json.lowercased().contains(forbidden.lowercased()), "\(forbidden)")
        }
        let pending = BrowserOutcome.humanStepRequired(.mfa).readReply()
        #expect(pending.status == "human_step_required" && pending.login == nil)
    }
}
