import AgentVaultBrowser
import AgentVaultBrowserFixture
import Foundation
import Testing
import WebKit

@MainActor
struct Harness {
    let site: FixtureSite
    let manager: BrowserSessionManager
    let account = UUID()

    static func make(humanPause: Duration = .seconds(60)) async throws -> Harness {
        let site = FixtureSite()
        try await site.start()
        let policy = try #require(BrowserPolicy.fixture(origin: site.origin))
        let timeouts = BrowserTimeouts(load: .seconds(10), navigation: .seconds(10),
                                       humanPause: humanPause, settle: .milliseconds(250))
        return Harness(site: site, manager: BrowserSessionManager(policy: policy, timeouts: timeouts))
    }

    func finish() {
        manager.revokeAll()
        site.stop()
    }

    func run(user: String = FixtureSite.loginName, password: String = FixtureSite.password) async -> BrowserOutcome {
        await manager.run(.demo, accountID: account, credential: FixtureSite.credential(user: user, password: password))
    }

    var trustedPosts: [FixtureRequest] { site.trusted.requests.filter { $0.method == "POST" } }

    /// Acts as the person in the human view: fills nothing, submits the page's own form.
    func humanSubmitsCurrentForm() async throws {
        let webView = try #require(manager.testWebView(accountID: account))
        _ = try? await webView.evaluateJavaScript("document.forms[0].submit()")
        for _ in 0..<100 {
            try await Task.sleep(for: .milliseconds(50))
            if webView.url?.path == "/home", !webView.isLoading { return }
        }
    }
}
