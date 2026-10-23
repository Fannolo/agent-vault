import Crypto
import Foundation

/// Public opaque identifiers. Zero values are reserved and refused.
public struct VaultID: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: Data
    public init(_ rawValue: Data) throws { self.rawValue = try fixedNonzero(rawValue, 16) }
    public static func random() -> VaultID { VaultID(unchecked: randomBytes(16)) }
    init(unchecked rawValue: Data) { self.rawValue = Data(rawValue) }
    public var description: String { "VaultID(\(hex(rawValue)))" }
}

public struct ItemID: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: Data
    public init(_ rawValue: Data) throws { self.rawValue = try fixedNonzero(rawValue, 16) }
    public static func random() -> ItemID { ItemID(unchecked: randomBytes(16)) }
    init(unchecked rawValue: Data) { self.rawValue = Data(rawValue) }
    public var description: String { "ItemID(\(hex(rawValue)))" }
}

public struct RevisionID: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: Data
    public init(_ rawValue: Data) throws { self.rawValue = try fixedNonzero(rawValue, 16) }
    public static func random() -> RevisionID { RevisionID(unchecked: randomBytes(16)) }
    init(unchecked rawValue: Data) { self.rawValue = Data(rawValue) }
    public var description: String { "RevisionID(\(hex(rawValue)))" }
}

/// `SHA256("AV/membership/2\0" || membershipBody)`, supplied by trusted authority.
public struct MembershipBodyID: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: Data
    public init(_ rawValue: Data) throws { self.rawValue = try fixedNonzero(rawValue, 32) }
    init(unchecked rawValue: Data) { self.rawValue = Data(rawValue) }
    public var description: String { "MembershipBodyID(\(hex(rawValue)))" }
}

/// `SHA256("AV/revision/2\0" || P || u32(len(E)) || E)`. Excludes the signature.
public struct RevisionBodyID: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: Data
    public init(_ rawValue: Data) throws { self.rawValue = try fixedNonzero(rawValue, 32) }
    init(unchecked rawValue: Data) { self.rawValue = Data(rawValue) }
    public var description: String { "RevisionBodyID(\(hex(rawValue)))" }
}

/// SHA256 of the entire record, including its signature.
public struct TransportDigest: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: Data
    init(unchecked rawValue: Data) { self.rawValue = Data(rawValue) }
    public var description: String { "TransportDigest(\(hex(rawValue)))" }
}

private func fixedNonzero(_ value: Data, _ count: Int) throws(RecordError) -> Data {
    guard value.count == count, value.contains(where: { $0 != 0 }) else { throw .malformed }
    return Data(value)
}

func randomBytes(_ count: Int) -> Data {
    SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
}

func sha256(_ parts: Data...) -> Data {
    var hasher = SHA256()
    for part in parts { hasher.update(data: part) }
    return Data(hasher.finalize())
}
