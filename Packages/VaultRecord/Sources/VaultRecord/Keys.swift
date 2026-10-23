import Crypto
import Foundation

public enum RecipientRole: UInt8, Sendable, Comparable {
    case device = 1, recovery = 2
    public static func < (left: Self, right: Self) -> Bool { left.rawValue < right.rawValue }
}

/// One member of the complete decrypting set, as supplied by trusted membership state.
public struct Recipient: Hashable, Sendable, CustomStringConvertible {
    public let role: RecipientRole
    /// Canonical X25519 u-coordinate (public value).
    public let publicKey: Data

    /// Raw 32-byte coordinate, validated here rather than by a platform key constructor.
    public init(role: RecipientRole, publicKey: Data) throws {
        try validateX25519(publicKey)
        self.role = role
        self.publicKey = Data(publicKey)
    }

    var sortKey: [UInt8] { [role.rawValue] + Array(publicKey) }
    public var description: String { "Recipient(\(role), \(hex(publicKey)))" }
}

/// Exact recipient set: 1–32 members, unique agreement keys, held in `(role, key)` order.
public struct RecipientSet: Hashable, Sendable {
    public static let maximumCount = 32
    public let members: [Recipient]

    public init(_ recipients: [Recipient]) throws {
        let sorted = recipients.sorted { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
        guard (1...Self.maximumCount).contains(sorted.count),
              Set(sorted.map(\.publicKey)).count == sorted.count else { throw RecordError.malformed }
        members = sorted
    }
}

/// Independently trusted expectations for one record. Never derived from the record itself.
public struct RecordAuthority: Sendable {
    public let vaultID: VaultID
    public let membershipBodyID: MembershipBodyID
    public let recipients: RecipientSet
    /// Expected writer key after weak/noncanonical screening only. Screening is not proof of
    /// enrollment, curve membership or possession; the effective verifier decodes it.
    let screenedAuthor: Data

    /// `authorEd25519` is the raw expected writer key. Platform key constructors are not
    /// used: their acceptance differs and is not key validation.
    public init(vaultID: VaultID, membershipBodyID: MembershipBodyID, authorEd25519: Data,
                recipients: RecipientSet) throws {
        guard SignatureProfile.screensPoint(authorEd25519) else { throw RecordError.invalidKey }
        self.vaultID = vaultID
        self.membershipBodyID = membershipBodyID
        self.screenedAuthor = Data(authorEd25519)
        self.recipients = recipients
    }
}

/// A recipient's software-held agreement key. No serialization or description of key bytes.
public struct RecipientKey: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let role: RecipientRole
    let privateKey: Curve25519.KeyAgreement.PrivateKey

    public init(role: RecipientRole, privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.role = role
        self.privateKey = privateKey
    }

    var publicKey: Data { privateKey.publicKey.rawRepresentation }
    public var description: String { "RecipientKey(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// Canonical (top bit clear, u < 2^255 − 19) and, per RFC 9180 §7.1.4, a nonzero DH result.
/// The probe is a fresh random scalar that carries no vault secret. Any clamped scalar
/// annihilates every low-order input.
func validateX25519(_ raw: Data) throws(RecordError) {
    let bytes = Array(raw)
    guard bytes.count == 32, bytes[31] & 0x80 == 0, !isAtLeastFieldPrime(bytes) else { throw .invalidKey }
    do {
        let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw)
        let shared = try Curve25519.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: key)
        guard shared.withUnsafeBytes({ $0.reduce(UInt8(0), |) }) != 0 else { throw RecordError.invalidKey }
    } catch {
        throw .invalidKey
    }
}
