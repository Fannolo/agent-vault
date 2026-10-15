import AgentVaultContracts
import AppKit
import Foundation
import WebKit

/// Broker-linked owner of every browser session. Runs only the fixed workflows in its policy.
///
/// The surface is deliberately small: run a workflow, resume after a human step, revoke.
/// Callers never receive a web view, cookie, page text, URL or script entry point; the
/// human continuation view is a separate, explicitly presented type.
@MainActor
public final class BrowserSessionManager {
    private let policy: BrowserPolicy
    private let timeouts: BrowserTimeouts
    private var contexts: [UUID: BrowserContext] = [:]
    /// Bumped by every revoke so a run that was still starting cannot outlive its revocation.
    private var revocations: [UUID: Int] = [:]

    public init(policy: BrowserPolicy, timeouts: BrowserTimeouts = .production) {
        self.policy = policy
        self.timeouts = timeouts
    }

    public var activeAccountIDs: Set<UUID> { Set(contexts.keys) }

    public func hasSession(accountID: UUID) -> Bool { contexts[accountID] != nil }

    /// Logs in with the credential bytes and extracts the typed profile, or pauses for a human.
    public func run(_ workflow: BrowserWorkflow, accountID: UUID, credential: Data) async -> BrowserOutcome {
        guard let definition = policy.workflows[workflow] else { return .failed(.unsupportedWorkflow) }
        guard contexts[accountID] == nil else { return .failed(.busy) }
        guard let credential = WebLoginCredential(credential) else { return .failed(.invalidCredential) }
        let epoch = revocations[accountID, default: 0]
        #if DEBUG
        await testBeforeContextCreation?()
        #endif
        guard let context = await BrowserContext.make(accountID: accountID, policy: policy) else {
            return .failed(.sessionUnavailable)
        }
        guard revocations[accountID, default: 0] == epoch else {
            context.destroy(reason: .sessionRevoked)
            return .failed(.sessionRevoked)
        }
        guard contexts[accountID] == nil else { context.destroy(reason: .busy); return .failed(.busy) }
        context.definition = definition
        contexts[accountID] = context
        return await conclude(context, await login(context, credential: credential, definition: definition))
    }

    /// Re-examines the paused session after the person finished the step in the human view.
    public func continueAfterHuman(accountID: UUID) async -> BrowserOutcome {
        guard let context = contexts[accountID], !context.isDestroyed,
              case .awaitingHuman = context.phase else { return .failed(.sessionUnavailable) }
        context.stopPauseTimer()
        context.phase = .running
        return await conclude(context, await classify(context))
    }

    /// Destroys the account's session. Used on grant revocation, credential rotation or deletion.
    public func revoke(accountID: UUID) {
        revocations[accountID, default: 0] += 1
        guard let context = contexts.removeValue(forKey: accountID) else { return }
        context.destroy(reason: .sessionRevoked)
    }

    public func revokeAll() {
        for id in Array(contexts.keys) { revoke(accountID: id) }
    }

    /// A dedicated view for a person to complete an MFA/CAPTCHA step. Present it yourself;
    /// the manager never reads what happens inside it.
    public func humanContinuationView(accountID: UUID) -> HumanContinuationView? {
        guard let context = contexts[accountID], case .awaitingHuman(let kind) = context.phase,
              let webView = context.webView else { return nil }
        return HumanContinuationView(webView: webView, kind: kind)
    }

    // MARK: - Workflow

    private func login(_ context: BrowserContext, credential: WebLoginCredential,
                       definition: WorkflowDefinition) async -> BrowserOutcome {
        let loaded = await context.navigate(timeout: timeouts.load) {
            context.load(path: definition.loginPath)
        }
        if case .failure(let failure) = loaded { return .failed(failure) }
        try? await Task.sleep(for: timeouts.settle)
        if let stop = interruption(context) { return stop }
        guard let recipes = context.recipes else { return .failed(.sessionUnavailable) }
        switch await recipes.fill(credential) {
        case .ok: break
        case .origin: return .failed(.originMismatch)
        case .form, .fields: return .failed(.unexpectedPage)
        }
        if let stop = interruption(context) { return stop }

        var submission = FixedRecipes.LoginResult.fields
        let submitted = await context.navigate(timeout: timeouts.navigation) {
            submission = await recipes.submit()
            return submission == .ok ? nil : (submission == .origin ? .originMismatch : .unexpectedPage)
        }
        if case .failure(let failure) = submitted { return .failed(failure) }
        try? await Task.sleep(for: timeouts.settle)
        if let stop = interruption(context) { return stop }
        return await classify(context)
    }

    private func interruption(_ context: BrowserContext) -> BrowserOutcome? {
        if context.isDestroyed { return .failed(.sessionRevoked) }
        if context.hostileAttempts > 0 { return .failed(.originMismatch) }
        return nil
    }

    private func classify(_ context: BrowserContext) async -> BrowserOutcome {
        if let stop = interruption(context) { return stop }
        guard let definition = context.definition, let recipes = context.recipes,
              let url = context.currentURL, policy.primary.matches(url) else { return .failed(.originMismatch) }
        let path = url.path
        if let step = definition.humanStepPaths.first(where: { path.hasPrefix($0.prefix) }) {
            return .humanStepRequired(step.kind)
        }
        if await recipes.containsCaptcha() { return .humanStepRequired(.captcha) }
        // A rejected login re-renders the form, sometimes at a different path than the login page.
        let loginFormShown = await recipes.containsLoginForm()
        if path.hasPrefix(definition.loginPath) || loginFormShown { return .failed(.loginRejected) }
        if let stop = interruption(context) { return stop }
        guard let profile = await recipes.readProfile() else { return .failed(.invalidProfile) }
        return .profile(profile)
    }

    /// Keeps the session only while a person must act; every other outcome tears it down.
    private func conclude(_ context: BrowserContext, _ outcome: BrowserOutcome) async -> BrowserOutcome {
        guard contexts[context.accountID] === context, !context.isDestroyed else { return .failed(.sessionRevoked) }
        if case .humanStepRequired(let kind) = outcome {
            context.phase = .awaitingHuman(kind)
            let id = context.accountID
            context.startPauseTimer(timeouts.humanPause) { [weak self] in self?.revoke(accountID: id) }
            return outcome
        }
        contexts.removeValue(forKey: context.accountID)
        context.destroy(reason: .sessionRevoked)
        return outcome
    }

    #if DEBUG
    /// Stops fixture startup after capturing authority, before creating a context.
    package var testBeforeContextCreation: (@MainActor () async -> Void)?
    /// Test-only window onto the web view for automated tests acting as the human.
    package func testWebView(accountID: UUID) -> WKWebView? { contexts[accountID]?.webView }
    #endif
}
