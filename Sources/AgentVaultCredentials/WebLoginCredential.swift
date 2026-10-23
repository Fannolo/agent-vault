import AgentVaultContracts
import Foundation
@_spi(SecretReveal) internal import VaultSecret

/// Trusted broker/host credential. Agent contracts contain only the format validator.
/// Construction cannot erase the caller's Data or temporary validation copies.
public struct WebLoginCredential: Sendable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let storage: SecretBytes
    private let usernameBytes: Int

    public init?(_ bytes: Data) {
        guard WebLoginFormat.isValid(bytes), let separator = bytes.firstIndex(of: 0x0A) else { return nil }
        usernameBytes = bytes.distance(from: bytes.startIndex, to: separator)
        var owned = Array(bytes)
        guard let secret = try? SecretBytes(consuming: &owned) else { return nil }
        storage = secret
    }

    /// Serialization is permitted only in the authenticated broker-to-host wire adapter.
    @_spi(CredentialUse)
    public func withCanonicalBytes<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result {
        try storage.withUnsafeBytes(body)
    }

    /// Borrowed UTF-8 fields, for the host's private fill adapter. No public String properties.
    @_spi(CredentialUse)
    public func withLoginBytes<Result>(
        _ body: (UnsafeRawBufferPointer, UnsafeRawBufferPointer) throws -> Result
    ) rethrows -> Result {
        try storage.withUnsafeBytes { bytes in
            try body(UnsafeRawBufferPointer(rebasing: bytes[..<usernameBytes]),
                     UnsafeRawBufferPointer(rebasing: bytes[(usernameBytes + 1)...]))
        }
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.storage.matches(rhs.storage)
    }

    public var description: String { "WebLoginCredential(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
