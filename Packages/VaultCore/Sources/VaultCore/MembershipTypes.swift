import Crypto
import Foundation

public enum MembershipPolicyError: String, Error, LocalizedError, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case malformed, anchorMismatch, badMembershipSignature, unsupportedAuthorityChange,
         invalidMemberKey, missingPredecessor, membershipFork, sequenceExhausted,
         capacityExceeded, staleMembership, unauthorizedAuthor, unauthorizedRecipient,
         recipientSetMismatch, invalidEncapsulation, membershipSigningFailed
    public var errorDescription: String? { rawValue }
    public var description: String { rawValue }
    public var debugDescription: String { rawValue }
}

public struct VaultID: Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "VaultID(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let bytes: Data

    public init(_ bytes: Data) throws {
        guard bytes.count == 16 else { throw MembershipPolicyError.malformed }
        self.bytes = Data(bytes)
    }
}

/// SHA256 of the signed membership body, excluding the controller signature.
public struct MembershipDigest: Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "MembershipDigest(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let bytes: Data

    init(body: Data) { bytes = Data(SHA256.hash(data: body)) }

    init(pinned bytes: Data) throws {
        guard bytes.count == 32 else { throw MembershipPolicyError.malformed }
        self.bytes = Data(bytes)
    }
}

/// SHA256 of the full canonical AVSEAL01 record, signature included.
public struct RevisionDigest: Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "RevisionDigest(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let bytes: Data

    init(record: Data) { bytes = Data(SHA256.hash(data: record)) }
}

/// Records a trusted local bootstrap decision. There is deliberately no public decoder.
public struct FixtureTrustAnchor: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "FixtureTrustAnchor(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let vaultID: VaultID
    public let genesis: MembershipDigest

    init(vaultID: VaultID, genesis: MembershipDigest) {
        self.vaultID = vaultID
        self.genesis = genesis
    }

    /// Source-compiled pins only; never exchanged metadata.
    init(compiledVaultID: Data, genesisBodyDigest: Data) throws {
        try self.init(vaultID: VaultID(compiledVaultID), genesis: MembershipDigest(pinned: genesisBodyDigest))
    }
}

/// The closed role/capability combinations. Not an extensible bitmask.
enum MemberKind: Sendable, CaseIterable {
    case reader, writer, recovery

    var role: UInt8 {
        switch self {
        case .reader, .writer: 1
        case .recovery: 2
        }
    }

    var capability: UInt8 {
        switch self {
        case .reader: 0x01
        case .writer: 0x03
        case .recovery: 0x05
        }
    }

    init?(role: UInt8, capability: UInt8) {
        guard let kind = Self.allCases.first(where: { $0.role == role && $0.capability == capability }) else { return nil }
        self = kind
    }
}

public struct FixtureMember: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "FixtureMember(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    let kind: MemberKind
    let agreementKey: Data

    public static func reader(_ key: Curve25519.KeyAgreement.PublicKey) throws -> Self { try Self(.reader, key) }
    public static func writer(_ key: Curve25519.KeyAgreement.PublicKey) throws -> Self { try Self(.writer, key) }
    public static func recovery(_ key: Curve25519.KeyAgreement.PublicKey) throws -> Self { try Self(.recovery, key) }

    private init(_ kind: MemberKind, _ key: Curve25519.KeyAgreement.PublicKey) throws {
        let agreementKey = key.rawRepresentation
        try MembershipPolicy.validateAgreementKey(agreementKey)
        self.kind = kind
        self.agreementKey = agreementKey
    }

    var row: MembershipRow { MembershipRow(role: kind.role, capability: kind.capability, agreementKey: agreementKey) }
}

/// Immutable public authority established at genesis. Holds no private key.
struct MembershipAuthorityPins: Equatable, Sendable {
    let vaultID: VaultID
    let controllerKey: Data
    let writerKey: Data
    let writerAgreementKey: Data
}

/// Session-observed RAM state. Not a durable pin, freshness proof or persistence format.
public struct MembershipCheckpoint: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "MembershipCheckpoint(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let sequence: UInt64
    public let head: MembershipDigest
    let authority: MembershipAuthorityPins
}

public enum MembershipAdvance: Equatable, Sendable {
    case advanced(MembershipCheckpoint)
    /// Always carries the current head, never the duplicate's own position.
    case duplicate(MembershipCheckpoint)
}

/// One bounded pair of complete signed records. A wrong-parent pair does not prove that
/// its missing alternative parent exists.
public struct MembershipForkEvidence: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "MembershipForkEvidence(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public enum Kind: Sendable { case observedSequence, signedLineageContradiction }

    public let kind: Kind
    public var firstRecord: Data { first }
    public var secondRecord: Data { second }
    private let first: Data
    private let second: Data

    init(kind: Kind, first: Data, second: Data) {
        self.kind = kind
        self.first = first
        self.second = second
    }
}

/// A receipt of what was checked. It is never accepted as opening authority.
public struct AuthorizedRevision: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "AuthorizedRevision(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public let digest: RevisionDigest
    public let authorizedAt: MembershipCheckpoint
}
