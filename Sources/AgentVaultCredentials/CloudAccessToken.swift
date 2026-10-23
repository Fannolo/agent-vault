import Foundation
@_spi(SecretReveal) internal import VaultSecret

/// Trusted transport access token. Not a vault key or authority to enroll a device.
/// Construction cannot erase the caller's Data or transient HTTP header copies.
public struct CloudAccessToken: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let storage: SecretBytes

    public init?(_ bytes: Data) {
        // JWT/base64url alphabet only: no whitespace, controls or header delimiters.
        guard (1...8192).contains(bytes.count), bytes.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
                || $0 == 45 || $0 == 95 || $0 == 46
        }) else { return nil }
        var owned = Array(bytes)
        guard let secret = try? SecretBytes(consuming: &owned) else { return nil }
        storage = secret
    }

    /// A separate SPI group: browser roles that import `CredentialUse` cannot reveal it.
    @_spi(CloudTokenUse)
    public func withTokenBytes<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result {
        try storage.withUnsafeBytes(body)
    }

    public var description: String { "CloudAccessToken(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
