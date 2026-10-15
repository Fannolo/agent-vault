import AgentVaultContracts
import AgentVaultBrowser
import Foundation
import Testing

struct PolicyTests {
    @Test func originsMatchExactlyAndNeverBySuffix() {
        let github = WebOrigin(url: URL(string: "https://github.com"))!
        #expect(github.matches(URL(string: "https://github.com/login")))
        #expect(github.matches(URL(string: "https://GITHUB.com:443/x")))
        for other in ["https://github.com.evil.example/", "https://evilgithub.com/", "https://api.github.com/",
                      "http://github.com/", "https://github.com:8443/", "https://user@github.com/",
                      "data:text/html,x", "javascript:alert(1)", "about:blank", "file:///etc/passwd"] {
            #expect(!github.matches(URL(string: other)), "\(other)")
        }
    }

    @Test func productionPolicyIsFixedToHTTPSGitHubAndHasNoDemoOrigin() throws {
        let rules = try JSONSerialization.jsonObject(with: Data(BrowserPolicy.production.contentRuleListJSON.utf8)) as? [[String: Any]]
        let filters = rules?.compactMap { ($0["trigger"] as? [String: String])?["url-filter"] }
        #expect(filters == [".*", "^https://github\\.com/", "^https://github\\.githubassets\\.com/",
                            "^https://avatars\\.githubusercontent\\.com/"])
        #expect((rules?.first?["action"] as? [String: String])?["type"] == "block")
    }

    @Test func fixtureOriginMustBeLoopbackHTTPWithExplicitPort() {
        #expect(BrowserPolicy.fixture(origin: URL(string: "http://127.0.0.1:8080")!) != nil)
        for bad in ["https://github.com", "http://127.0.0.1", "http://localhost:8080", "https://127.0.0.1:8080",
                    "http://192.168.1.2:8080", "http://example.com:80"] {
            #expect(BrowserPolicy.fixture(origin: URL(string: bad)!) == nil, "\(bad)")
        }
    }

    @Test func credentialFormatAndRedaction() {
        let credential = WebLoginCredential(Data("octo\nsynthetic-secret".utf8))
        #expect(credential != nil)
        var dumped = ""
        dump(credential!, to: &dumped)
        #expect(!"\(credential!) \(String(reflecting: credential!)) \(dumped)".contains("synthetic-secret"))
        #expect(WebLoginCredential(Data(repeating: 0x41, count: 5000)) == nil)
    }
}

/// Structural guarantees: the arbitrary-script and session-export surfaces must not exist.
struct SourceInvariantTests {
    private func browserSources() throws -> [(name: String, text: String)] {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Sources/AgentVaultBrowser")
        return try FileManager.default.contentsOfDirectory(atPath: root.path).filter { $0.hasSuffix(".swift") }.map {
            ($0, try String(contentsOf: root.appendingPathComponent($0), encoding: .utf8))
        }
    }

    @Test func pageScriptExecutionLivesOnlyInFixedRecipes() throws {
        let sources = try browserSources()
        #expect(sources.count >= 6)
        for (name, text) in sources where name != "FixedRecipes.swift" {
            for api in ["evaluateJavaScript", "callAsyncJavaScript", "WKUserScript", "WKScriptMessageHandler", "addUserScript"] {
                #expect(!text.contains(api), "\(api) found in \(name)")
            }
        }
        let recipes = try #require(sources.first { $0.name == "FixedRecipes.swift" }).text
        #expect(!recipes.contains("evaluateJavaScript"))
        #expect(recipes.components(separatedBy: ".callAsyncJavaScript(").count == 2, "single choke point")
    }

    @Test func noPublicSurfaceTakesScriptsUrlsOrReturnsCookiesOrPages() throws {
        for (name, text) in try browserSources() {
            for line in text.split(separator: "\n") where line.contains("public ") {
                for pattern in ["\\bscript\\b", "\\bjavascript\\b", "cookie", "\\bhtml\\b", "inspector", "devtools",
                                "-> URL", "WKWebView", "-> Data", "endpoint", "debugPort"] {
                    #expect(line.range(of: pattern, options: [.regularExpression, .caseInsensitive]) == nil,
                            "public API mentions \(pattern) in \(name): \(line)")
                }
            }
            for api in ["httpCookieStore", "isInspectable = true", "_remoteInspection", "_setInspectable", "takeSnapshot", "pdf(", "createWebArchive"] {
                #expect(!text.contains(api), "\(api) in \(name)")
            }
        }
    }
}
