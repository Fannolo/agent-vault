import Crypto
import Foundation

public enum VaultError: String, Error, LocalizedError, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case malformed, badSignature, badAuthentication, unexpectedIdentity, conflict
    public var errorDescription: String? { rawValue }
    public var description: String { rawValue }
    public var debugDescription: String { rawValue }
}

/// Secret-bearing values belong only in a trusted broker. Swift memory erasure is not guaranteed.
public struct LoginItem: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let username: String
    public let password: Data
    public let origins: [String]

    public init(username: String, password: Data, origins: [String]) {
        self.username = username
        self.password = password
        self.origins = origins
    }

    public var description: String { "LoginItem(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

public struct RevisionContext: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "RevisionContext(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let vaultID: Data
    public let itemID: Data
    public let revisionID: Data
    public let membershipHead: Data

    public init(vaultID: Data, itemID: Data, revisionID: Data, membershipHead: Data) throws {
        guard vaultID.count == 16, itemID.count == 16, revisionID.count == 16,
              membershipHead.count == 32 else { throw VaultError.malformed }
        self.vaultID = vaultID
        self.itemID = itemID
        self.revisionID = revisionID
        self.membershipHead = membershipHead
    }
}

public enum RecipientRole: UInt8, Sendable {
    case device = 1, recovery = 2
}

public struct RevisionRecipient: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "RevisionRecipient(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let role: RecipientRole
    public let publicKey: Curve25519.KeyAgreement.PublicKey

    /// Rejects zero-DH X25519 inputs with `VaultError.malformed`.
    public init(role: RecipientRole, publicKey: Curve25519.KeyAgreement.PublicKey) throws {
        try validateX25519PublicKey(publicKey)
        self.role = role
        self.publicKey = publicKey
    }
}

// RFC 9180 §7.1.4: any clamped X25519 scalar annihilates low-order inputs,
// including noncanonical and high-bit aliases. The probe carries no vault secret.
func validateX25519PublicKey(_ publicKey: Curve25519.KeyAgreement.PublicKey) throws {
    do {
        let probe = Curve25519.KeyAgreement.PrivateKey()
        let shared = try probe.sharedSecretFromKeyAgreement(with: publicKey)
        let hasNonzeroDH = shared.withUnsafeBytes { $0.reduce(UInt8(0), |) != 0 }
        guard hasNonzeroDH else { throw VaultError.malformed }
    } catch {
        throw VaultError.malformed
    }
}
