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
        case .browserDemo, .githubWeb: WebLoginFormat.isValid(bytes)
        }
    }
}

/// UTF-8 `username` LF `password`: at most 4096 bytes in total, a username of at most 255
/// characters, both parts non-empty and excluding Unicode Cc/Cf control and format scalars.
/// Unicode separators such as U+2028 remain allowed. This validator retains no credential.
public enum WebLoginFormat {
    public static let maximumBytes = 4096
    public static let maximumUsernameCharacters = 255
    public static func isValid(_ bytes: Data) -> Bool {
        guard bytes.count <= maximumBytes else { return false }
        let text = String(decoding: bytes, as: UTF8.self)
        guard Data(text.utf8) == bytes else { return false }
        let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty,
              parts[0].count <= Self.maximumUsernameCharacters,
              !parts.contains(where: { $0.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) } })
        else { return false }
        return true
    }
}
