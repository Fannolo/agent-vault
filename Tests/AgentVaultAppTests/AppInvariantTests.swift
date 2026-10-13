import Foundation
import Testing

/// Structural guarantees for the human app: no Core, no provider-credential storage, no logging
/// of approval material, and the unprotected fixture key stays out of release builds.
struct AppInvariantTests {
    private static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    private func sources(_ dirs: [String]) throws -> [(path: String, text: String)] {
        var result: [(String, String)] = []
        for dir in dirs {
            let base = Self.root.appendingPathComponent(dir)
            let enumerator = FileManager.default.enumerator(at: base, includingPropertiesForKeys: nil)
            while let url = enumerator?.nextObject() as? URL {
                guard url.pathExtension == "swift" else { continue }
                result.append((url.path.replacingOccurrences(of: Self.root.path + "/", with: ""), try String(contentsOf: url, encoding: .utf8)))
            }
        }
        return result
    }

    @Test func appNeverLinksCoreOrSecretStores() throws {
        let files = try sources(["Sources/AgentVaultApp", "Sources/AgentVaultAppSupport", "Sources/AgentVaultBrowser"])
        #expect(files.count >= 20)
        for (path, text) in files {
            #expect(!text.contains("import AgentVaultCore"), Comment(rawValue: String(describing: path)))
            #expect(!text.contains("import AgentVaultCLI"), Comment(rawValue: String(describing: path)))
            #expect(!text.contains("kSecClassGenericPassword"), Comment(rawValue: "provider credentials are never stored by the app: \(path)"))
            #expect(!text.contains("SecItemAdd"), Comment(rawValue: String(describing: path)))
            #expect(!text.contains("UserDefaults") && !text.contains("@AppStorage") && !text.contains("@SceneStorage"), Comment(rawValue: String(describing: path)))
        }
        let manifest = try String(contentsOf: Self.root.appendingPathComponent("Package.swift"), encoding: .utf8)
        let lines = manifest.components(separatedBy: "\n")
        for name in ["AgentVaultAppSupport", "AgentVaultApp", "AgentVaultBrowser"] {
            let index = try #require(lines.firstIndex { $0.contains("Target(name: \"\(name)\"") || $0.contains("target(name: \"\(name)\"") })
            #expect(!lines[index].contains("AgentVaultCore"), Comment(rawValue: lines[index]))
        }
    }

    @Test func approvalMaterialIsNeverLogged() throws {
        for (path, text) in try sources(["Sources/AgentVaultApp", "Sources/AgentVaultAppSupport"]) {
            for call in ["print", "NSLog", "os_log", "Logger", "debugPrint", "dump"] {
                #expect(text.range(of: "\\b\(call)\\(", options: .regularExpression) == nil, Comment(rawValue: "\(call) in \(path)"))
            }
        }
    }

    @Test func unprotectedFixtureCodeIsCompiledOutOfReleaseBuilds() throws {
        let files = try sources(["Sources/AgentVaultAppSupport"])
        for (path, text) in files where text.contains("SoftwareFixtureSigner") || text.contains("InMemoryBroker") || text.contains("ScreenshotTour") {
            let isDefinition = path.contains("Fixtures/") || path.hasSuffix("ScreenshotTour.swift")
            if isDefinition { #expect(text.hasPrefix("#if DEBUG"), Comment(rawValue: path)) }
            else {
                // Any other use must sit inside a DEBUG block.
                let lines = text.components(separatedBy: "\n")
                var depth = 0
                for line in lines {
                    if line.contains("#if DEBUG") { depth += 1 }
                    if line.contains("#endif") { depth -= 1 }
                    if line.contains("SoftwareFixtureSigner") || line.contains("InMemoryBroker") { #expect(depth > 0, Comment(rawValue: "\(path): \(line)")) }
                }
            }
        }
    }
}
