import Foundation

/// The single credential grammar. The broker enforces it before any Keychain write; the app
/// uses it only for early feedback, and browser hosts recheck it as defence in depth.
public enum CredentialFormat {
    /// Transport cap for every enrollment and rotation request.
    public static let transportMaximum = 8192

    public static func isValid(_ bytes: Data, for service: WireService) -> Bool {
        switch service {
        case .demo: !bytes.isEmpty && bytes.count <= transportMaximum
        case .github: (10...transportMaximum).contains(bytes.count) && bytes.allSatisfy { (0x21...0x7E).contains($0) }
        case .browserDemo, .githubWeb: WebLoginCredential(bytes) != nil
        }
    }
}

/// UTF-8 `username` LF `password`: at most 4096 bytes in total, a username of at most 255
/// characters, both parts non-empty and free of control characters. Descriptions are redacted.
public struct WebLoginCredential: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let maximumBytes = 4096
    public static let maximumUsernameCharacters = 255
    public let username: String
    public let password: String

    public init?(_ bytes: Data) {
        guard bytes.count <= Self.maximumBytes, let text = String(data: bytes, encoding: .utf8) else { return nil }
        let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty,
              parts[0].count <= Self.maximumUsernameCharacters,
              !parts.contains(where: { $0.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) } })
        else { return nil }
        username = String(parts[0]); password = String(parts[1])
    }

    public var description: String { "WebLoginCredential(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

extension WebLoginCredential: Equatable {
    /// The canonical `username` LF `password` bytes that `init?(_:)` accepts.
    public var bytes: Data { Data((username + "\n" + password).utf8) }
}
