import AppKit
import Foundation
import WebKit

@MainActor
final class NavigationGate {
    private var result: Result<Void, BrowserFailure>?
    private var continuation: CheckedContinuation<Result<Void, BrowserFailure>, Never>?

    func complete(_ value: Result<Void, BrowserFailure>) {
        guard result == nil else { return }
        result = value
        continuation?.resume(returning: value)
        continuation = nil
    }

    func wait() async -> Result<Void, BrowserFailure> {
        if let result { return result }
        return await withCheckedContinuation { continuation = $0 }
    }
}

/// One ephemeral WebKit session for one account. It owns a non-persistent data store, so
/// cookies and storage exist only in this object's web content process and are never exported.
@MainActor
final class BrowserContext: NSObject {
    enum Phase { case running, awaitingHuman(HumanStepKind) }

    let accountID: UUID
    let policy: BrowserPolicy
    var phase: Phase = .running
    private(set) var webView: WKWebView?
    private(set) var isDestroyed = false
    /// Off-origin navigations, popups and frames the page tried to open. Any is hostile.
    private(set) var hostileAttempts = 0
    private var gate: NavigationGate?
    private var ruleDirectory: URL?
    private var pauseTimer: Task<Void, Never>?

    private init(accountID: UUID, policy: BrowserPolicy) {
        self.accountID = accountID
        self.policy = policy
    }

    static func make(accountID: UUID, policy: BrowserPolicy) async -> BrowserContext? {
        let context = BrowserContext(accountID: accountID, policy: policy)
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentvault-browser-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            context.ruleDirectory = directory
            guard let store = WKContentRuleListStore(url: directory) else { throw CocoaError(.fileWriteUnknown) }
            guard let rules = try await store.compileContentRuleList(
                forIdentifier: "agentvault-origins", encodedContentRuleList: policy.contentRuleListJSON)
            else { throw CocoaError(.fileWriteUnknown) }

            let configuration = WKWebViewConfiguration()
            configuration.websiteDataStore = .nonPersistent()
            configuration.userContentController.add(rules)
            configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
            configuration.preferences.isFraudulentWebsiteWarningEnabled = true
            configuration.mediaTypesRequiringUserActionForPlayback = .all
            configuration.allowsAirPlayForMediaPlayback = false
            configuration.defaultWebpagePreferences.allowsContentJavaScript = true
            configuration.suppressesIncrementalRendering = false

            let view = WKWebView(frame: NSRect(x: 0, y: 0, width: 900, height: 700), configuration: configuration)
            view.isInspectable = false
            view.allowsBackForwardNavigationGestures = false
            view.allowsMagnification = false
            view.navigationDelegate = context
            view.uiDelegate = context
            context.webView = view
            return context
        } catch {
            context.destroy(reason: .sessionUnavailable)
            return nil
        }
    }

    var definition: WorkflowDefinition?

    var recipes: FixedRecipes? {
        guard let webView, !isDestroyed, let definition else { return nil }
        return FixedRecipes(webView: webView, origin: policy.primary, definition: definition)
    }

    var currentURL: URL? { webView?.url }

    /// Runs `trigger` while a navigation gate is armed, then waits for the next completed
    /// navigation. `trigger` returns a failure to abort without waiting.
    func navigate(timeout: Duration, trigger: () async -> BrowserFailure?) async -> Result<Void, BrowserFailure> {
        guard !isDestroyed else { return .failure(.sessionRevoked) }
        let gate = NavigationGate()
        self.gate = gate
        let timer = Task { [weak gate] in
            try? await Task.sleep(for: timeout)
            gate?.complete(.failure(.timeout))
        }
        defer { timer.cancel(); if self.gate === gate { self.gate = nil } }
        if let failure = await trigger() { return .failure(failure) }
        return await gate.wait()
    }

    func load(path: String) -> BrowserFailure? {
        guard let url = policy.primary.url(path: path), let webView else { return .sessionUnavailable }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        webView.load(request)
        return nil
    }

    func startPauseTimer(_ duration: Duration, onExpiry: @escaping @MainActor () -> Void) {
        pauseTimer?.cancel()
        pauseTimer = Task { [weak self] in
            try? await Task.sleep(for: duration)
            guard !Task.isCancelled, self != nil else { return }
            onExpiry()
        }
    }

    func stopPauseTimer() { pauseTimer?.cancel(); pauseTimer = nil }

    /// Irreversible. Cancels waiters, drops the data store and releases the web content process.
    func destroy(reason: BrowserFailure) {
        guard !isDestroyed else { return }
        isDestroyed = true
        stopPauseTimer()
        gate?.complete(.failure(reason))
        gate = nil
        if let webView {
            webView.stopLoading()
            webView.navigationDelegate = nil
            webView.uiDelegate = nil
            webView.configuration.userContentController.removeAllContentRuleLists()
            webView.configuration.userContentController.removeAllUserScripts()
            let store = webView.configuration.websiteDataStore
            store.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(),
                             modifiedSince: .distantPast) {}
            webView.removeFromSuperview()
            webView.window?.close()
        }
        webView = nil
        if let ruleDirectory { try? FileManager.default.removeItem(at: ruleDirectory) }
        ruleDirectory = nil
    }

    private func noteHostile() {
        hostileAttempts += 1
        gate?.complete(.failure(.originMismatch))
    }
}

extension BrowserContext: WKNavigationDelegate {
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 preferences: WKWebpagePreferences) async -> (WKNavigationActionPolicy, WKWebpagePreferences) {
        preferences.allowsContentJavaScript = true
        if navigationAction.shouldPerformDownload { noteHostile(); return (.cancel, preferences) }
        let url = navigationAction.request.url
        if policy.primary.matches(url) { return (.allow, preferences) }
        // Subframes may only be blank; any other off-origin load is a hostile attempt.
        if navigationAction.targetFrame?.isMainFrame == false, url?.absoluteString == "about:blank" {
            return (.allow, preferences)
        }
        noteHostile()
        return (.cancel, preferences)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse) async -> WKNavigationResponsePolicy {
        guard policy.primary.matches(navigationResponse.response.url), navigationResponse.canShowMIMEType else {
            noteHostile()
            return .cancel
        }
        if let http = navigationResponse.response as? HTTPURLResponse,
           let disposition = http.value(forHTTPHeaderField: "Content-Disposition"),
           disposition.lowercased().hasPrefix("attachment") {
            noteHostile()
            return .cancel
        }
        return .allow
    }

    func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
        if !policy.primary.matches(webView.url) { noteHostile(); webView.stopLoading() }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        gate?.complete(policy.primary.matches(webView.url) ? .success(()) : .failure(.originMismatch))
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        gate?.complete(.failure(hostileAttempts > 0 ? .originMismatch : .loadFailed))
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        gate?.complete(.failure(hostileAttempts > 0 ? .originMismatch : .loadFailed))
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        gate?.complete(.failure(.sessionUnavailable))
    }

    func webView(_ webView: WKWebView, respondTo challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        // Only default server-trust evaluation; never answer HTTP auth or client-certificate prompts.
        challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust
            ? (.performDefaultHandling, nil) : (.cancelAuthenticationChallenge, nil)
    }
}

extension BrowserContext: WKUIDelegate {
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        noteHostile()
        return nil
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo) async {}

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo) async -> Bool { false }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?, initiatedByFrame frame: WKFrameInfo) async -> String? { nil }

    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo) async -> [URL]? { nil }

    func webView(_ webView: WKWebView, decideMediaCapturePermissionsFor origin: WKSecurityOrigin,
                 initiatedBy frame: WKFrameInfo, type: WKMediaCaptureType) async -> WKPermissionDecision { .deny }

    func webView(_ webView: WKWebView, requestDeviceOrientationAndMotionPermissionFor origin: WKSecurityOrigin,
                 initiatedByFrame frame: WKFrameInfo) async -> WKPermissionDecision { .deny }
}
