import AgentVaultCredentials
@testable import AgentVaultWebHost
import AgentVaultWebHostProtocol
import AgentVaultContracts
import Foundation
import Testing

private let hostSources: [(name: String, text: String)] = {
    let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../Sources/AgentVaultWebHost").standardized
    let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
    return names.filter { $0.hasSuffix(".swift") }.sorted().map {
        ($0, (try? String(contentsOf: directory.appendingPathComponent($0), encoding: .utf8)) ?? "")
    }
}()

@Suite struct SourceInvariantTests {
    @Test func credentialGrammarAndAllDescriptionsStayRedacted() throws {
        let credential = try #require(WebLoginCredential(Data("fixture-user\nSYNTHETIC-redaction-fixture".utf8)))
        var mirrored = ""
        dump(credential, to: &mirrored)
        for text in [credential.description, credential.debugDescription, String(reflecting: credential), mirrored] {
            #expect(!text.contains("SYNTHETIC-redaction-fixture"))
        }
        for invalid in [Data(), Data("one-line".utf8), Data("user\n".utf8), Data("\npassword".utf8),
                        Data("user\npassword\u{7}".utf8), Data([0xFF, 0x0A, 0x41]), Data(repeating: 0x41, count: 5000)] {
            #expect(WebLoginCredential(invalid) == nil)
        }
    }

    @Test func hostSourcesAreReadable() {
        #expect(hostSources.count >= 7 && hostSources.allSatisfy { !$0.text.isEmpty })
    }

    @Test func noSandboxBypassDebugPortGenericEvaluationOrCookieAccess() {
        let forbidden = ["--no-sandbox", "remote-debugging-port", "Runtime.evaluate", "Runtime.compileScript",
                         "getCookies", "getAllCookies", "Storage.", "setCookie", "--disable-web-security",
                         "--single-process", "--no-zygote", "--disable-site-isolation", "IndexedDB.", "DOMStorage.",
                         "Fetch.continueWithAuth", "Page.setDownloadBehavior\", \"allow"]
        for (name, text) in hostSources {
            for word in forbidden { #expect(!text.contains(word), "\(name) contains \(word)") }
        }
        #expect(!ChromiumPipe.arguments.contains { $0.contains("sandbox") || $0.contains("remote-debugging-port") })
        #expect(ChromiumPipe.arguments.contains("--remote-debugging-pipe"))
        #expect(ChromiumPipe.arguments.contains("--use-mock-keychain"))
    }

    @Test func cdpVocabularyIsClosedAndFixed() {
        #expect(Set(CDPMethod.allCases.map(\.rawValue)) == [
            "Browser.getVersion", "Browser.setDownloadBehavior", "Target.setAutoAttach", "Target.createBrowserContext",
            "Target.disposeBrowserContext", "Target.createTarget", "Target.closeTarget", "Runtime.runIfWaitingForDebugger", "Fetch.enable", "Fetch.continueRequest",
            "Fetch.failRequest", "Fetch.getResponseBody", "Fetch.fulfillRequest", "Network.enable", "Page.enable",
            "Page.navigate", "Page.getFrameTree", "Page.createIsolatedWorld", "Page.captureScreenshot",
            "Runtime.callFunctionOn", "Emulation.setDeviceMetricsOverride", "Input.dispatchMouseEvent",
            "Input.dispatchKeyEvent", "Input.insertText", "Browser.close",
        ])
        // Only the pipe serializes a method name; every other file names `CDPMethod` cases.
        for (name, text) in hostSources where name != "ChromiumPipe.swift" {
            #expect(!text.contains("\"method\":"), "\(name) builds a raw CDP message")
        }
    }

    @Test func recipesAreConstantsWithFixedParameters() {
        for recipe in Recipe.allCases {
            #expect(recipe.declaration.hasPrefix("function (origin"))
            #expect(!recipe.body.contains("eval(") && !recipe.body.contains("Function("))
            #expect(!recipe.body.contains("cookie") && !recipe.body.contains("innerHTML") && !recipe.body.contains("outerHTML"))
        }
        // The page never gets a recipe it could call back into: only the five fixed bodies exist.
        #expect(Recipe.allCases.count == 5)
    }

    /// Continuing sites grow the vocabulary by eight more constant bodies, and no more.
    @Test func siteRecipesAreConstantsThatNeverReachStorageOrTheNetwork() {
        #expect(SiteRecipe.allCases.count == 8)
        for recipe in SiteRecipe.allCases {
            #expect(recipe.declaration.hasPrefix("function (origins"))
            for word in ["eval(", "Function(", "cookie", "innerHTML", "outerHTML", "Storage", "indexedDB", "fetch(",
                         "XMLHttpRequest", "postMessage", "sendBeacon", "WebSocket", "window.open"] {
                #expect(!recipe.body.contains(word), "\(recipe) contains \(word)")
            }
            // Only the fill recipe ever receives the credential.
            #expect(recipe == .loginFill || !recipe.parameters.contains("password"))
        }
        // Every observed string is cut from one budget in the page, at most 6 JSON bytes per unit, plus
        // fixed per-element structure: far below the pipe's message cap.
        let structure = SiteObservation.maximumElements * (200 + SiteElement.maximumOptions * 3) + SiteObservation.maximumTextItems * 3
        #expect(SiteRecipe.observationBudget * 6 + structure < ChromiumPipe.maximumMessageBytes / 2)
        #expect(SiteRecipe.observe.body.contains("budget -= s.length"))
                let session = hostSources.first { $0.name == "SiteSession.swift" }?.text ?? ""
        #expect(session.components(separatedBy: "withLoginBytes").count == 2, "one reveal, inside login")
    }
}
