import Crypto
import Foundation

// record = P || esdkLength:u32 || E || authorSignature[64]
// P = "AVREC002" || version:u8=2 || suite:u8=1 || kind:u8 || vaultID[16] || itemID[16] ||
//     revisionID[16] || membershipBodyID[32] || authorEd25519[32] || parentCount:u8 || parent[32]*
// authorSignature = Ed25519(P || u32(len(E)) || E)

public enum RecordFormat {
    public static let maximumParents = 16
    /// Largest grammatical record (kind 4, 16 parents, 32 recipients): B + 5012 with B = 524288.
    public static let maximumRecordBytes = 529_300
    static let magic = Array("AVREC002".utf8)
    static let version: UInt8 = 2
    static let suite: UInt8 = 1
    static let reservedSnapshotKind: UInt8 = 4
    static let bodyDomain = Data("AV/revision/2".utf8) + Data([0])
    static let signatureBytes = 64
}

/// Revision position supplied by the trusted writer. Parents are held in ascending order.
public struct RevisionIdentity: Sendable {
    public let itemID: ItemID
    public let revisionID: RevisionID
    public let parents: [RevisionBodyID]

    public init(itemID: ItemID, revisionID: RevisionID, parents: [RevisionBodyID]) throws {
        let sorted = parents.sorted { $0.rawValue.lexicographicallyPrecedes($1.rawValue) }
        guard sorted.count <= RecordFormat.maximumParents,
              strictlyAscending(sorted.map { Array($0.rawValue) }) else { throw RecordError.invalidContent }
        self.itemID = itemID
        self.revisionID = revisionID
        self.parents = sorted
    }
}

struct PublicHeader {
    let kind: RecordKind
    let vaultID: VaultID
    let itemID: ItemID
    let revisionID: RevisionID
    let membershipBodyID: MembershipBodyID
    let author: Data
    let parents: [RevisionBodyID]

    func encode() -> Data {
        var writer = ByteWriter(capacity: 124 + 32 * parents.count)
        writer.raw(RecordFormat.magic)
        writer.u8(RecordFormat.version)
        writer.u8(RecordFormat.suite)
        writer.u8(kind.rawValue)
        writer.raw(vaultID.rawValue)
        writer.raw(itemID.rawValue)
        writer.raw(revisionID.rawValue)
        writer.raw(membershipBodyID.rawValue)
        writer.raw(author)
        writer.u8(UInt8(parents.count))
        for parent in parents { writer.raw(parent.rawValue) }
        return writer.data
    }

    static func parse(_ reader: inout ByteReader) throws(RecordError) -> PublicHeader {
        guard Array(try reader.take(8)) == RecordFormat.magic, try reader.u8() == RecordFormat.version,
              try reader.u8() == RecordFormat.suite else { throw .malformed }
        let kindByte = try reader.u8()
        if kindByte == RecordFormat.reservedSnapshotKind { throw .unsupported }
        guard let kind = RecordKind(rawValue: kindByte) else { throw .malformed }
        let vault = try nonzero(reader.take(16))
        let item = try nonzero(reader.take(16))
        let revision = try nonzero(reader.take(16))
        let membership = try nonzero(reader.take(32))
        let author = try reader.take(32)
        let count = Int(try reader.u8())
        guard count <= RecordFormat.maximumParents else { throw .malformed }
        var parents: [RevisionBodyID] = []
        for _ in 0..<count { parents.append(RevisionBodyID(unchecked: try nonzero(reader.take(32)))) }
        guard strictlyAscending(parents.map { Array($0.rawValue) }) else { throw .malformed }
        return PublicHeader(kind: kind, vaultID: VaultID(unchecked: vault), itemID: ItemID(unchecked: item),
                            revisionID: RevisionID(unchecked: revision),
                            membershipBodyID: MembershipBodyID(unchecked: membership),
                            author: Data(author), parents: parents)
    }

    private static func nonzero(_ value: Data) throws(RecordError) -> Data {
        guard value.contains(where: { $0 != 0 }) else { throw .malformed }
        return value
    }
}

/// Public ciphertext and its two identities. Contains no plaintext or key material.
public struct SealedRecord: Sendable {
    public let bytes: Data
    public let bodyID: RevisionBodyID
    public let transportDigest: TransportDigest
}

public enum RecordSealer {
    /// Seals `content` for exactly `authority.recipients` and signs the complete body with
    /// `author`, which must be the authority's author key. Fresh DK and messageID per call.
    public static func seal(_ content: RecordContent, identity: RevisionIdentity, authority: RecordAuthority,
                            author: Curve25519.Signing.PrivateKey) throws -> SealedRecord {
        guard author.publicKey.rawRepresentation == authority.screenedAuthor else { throw RecordError.unexpectedAuthority }
        let header = PublicHeader(kind: content.kind, vaultID: authority.vaultID, itemID: identity.itemID,
                                  revisionID: identity.revisionID, membershipBodyID: authority.membershipBodyID,
                                  author: authority.screenedAuthor, parents: identity.parents).encode()
        let headerHash = sha256(header)
        let dataKey = SymmetricKey(size: .bits256)
        let messageID = randomBytes(32)
        let keys = ESDK.derive(dataKey: dataKey, messageID: messageID)
        var edks: [ESDK.EncryptedDataKey] = []
        for recipient in authority.recipients.members {
            edks.append(try ESDK.wrap(dataKey, for: recipient, headerHash: headerHash, messageID: messageID,
                                      commitment: keys.commitment))
        }
        let esdkHeader = ESDK.header(messageID: messageID, context: ESDK.context(headerHash: headerHash),
                                     edks: edks, commitment: keys.commitment)
        let headerTag = try ESDK.headerTag(key: keys.encryption, header: esdkHeader)
        var logical = Payload.logical(content)
        var padded = Payload.pad(logical)
        wipe(&logical)
        defer { wipe(&padded) }
        let (ciphertext, frameTag) = try ESDK.sealFrame(key: keys.encryption, messageID: messageID, padded: padded)
        let message = ESDK.body(header: esdkHeader, headerTag: headerTag, ciphertext: ciphertext, frameTag: frameTag)
        return try signRecord(header: header, message: message, author: author)
    }

    static func signRecord(header: Data, message: Data, author: Curve25519.Signing.PrivateKey) throws -> SealedRecord {
        var writer = ByteWriter(capacity: header.count + 4 + message.count + RecordFormat.signatureBytes)
        writer.raw(header)
        writer.u32(UInt32(message.count))
        writer.raw(message)
        let signed = writer.data
        let signature = try author.signature(for: signed)
        let record = signed + signature
        return SealedRecord(bytes: record, bodyID: RevisionBodyID(unchecked: sha256(RecordFormat.bodyDomain, signed)),
                            transportDigest: TransportDigest(unchecked: sha256(record)))
    }
}

/// Bounded canonical parse of untrusted bytes. Fields are claims until `verify` succeeds.
public struct ParsedRecord: Sendable {
    let header: PublicHeader
    let headerBytes: Data
    let signed: Data
    let signature: Data
    let message: ESDK.Message
    let record: Data

    public var kind: RecordKind { header.kind }
    public var claimedVaultID: VaultID { header.vaultID }
    public var claimedItemID: ItemID { header.itemID }
    public var claimedRevisionID: RevisionID { header.revisionID }
    public var claimedMembershipBodyID: MembershipBodyID { header.membershipBodyID }

    public init(_ bytes: Data) throws {
        guard bytes.count <= RecordFormat.maximumRecordBytes else { throw RecordError.malformed }
        var reader = ByteReader(bytes)
        let start = reader.position
        header = try PublicHeader.parse(&reader)
        headerBytes = bytes[start..<reader.position]
        let length = Int(try reader.u32())
        guard length == reader.remaining - RecordFormat.signatureBytes else { throw RecordError.malformed }
        let message = try reader.take(length)
        signed = bytes[start..<reader.position]
        signature = try reader.take(RecordFormat.signatureBytes)
        try reader.finish()
        self.message = try ESDK.parse(message, maximumBucket: Payload.maximumBucketForKinds1To3)
        guard Array(self.message.contextValue) == Array(hex(sha256(headerBytes)).utf8) else {
            throw RecordError.malformed
        }
        record = bytes
    }

    /// Signature under the independently supplied author key first; then vault, item,
    /// revision, membership, author field and exact recipient set; then every recipient and
    /// encapsulation key, selected or not.
    public func verify(under authority: RecordAuthority, item: ItemID, revision: RevisionID) throws -> VerifiedRecord {
        guard SignatureProfile.verify(signature: signature, body: signed, author: authority.screenedAuthor) else {
            throw RecordError.badSignature
        }
        guard header.author == authority.screenedAuthor, header.vaultID == authority.vaultID,
              header.itemID == item, header.revisionID == revision,
              header.membershipBodyID == authority.membershipBodyID,
              message.edks.map(\.sortKey) == authority.recipients.members.map(\.sortKey) else {
            throw RecordError.unexpectedAuthority
        }
        for edk in message.edks {
            try validateX25519(edk.recipient)
            try validateX25519(edk.encapsulation)
        }
        return VerifiedRecord(parsed: self, bodyID: RevisionBodyID(unchecked: sha256(RecordFormat.bodyDomain, signed)),
                              transportDigest: TransportDigest(unchecked: sha256(record)))
    }
}

/// Signed by the expected author for the expected vault, membership and recipient set.
/// `open` invokes a synchronous callback after validation. Callers may retain its content.
public struct VerifiedRecord: Sendable {
    let parsed: ParsedRecord
    public let bodyID: RevisionBodyID
    public let transportDigest: TransportDigest

    public var kind: RecordKind { parsed.header.kind }
    public var itemID: ItemID { parsed.header.itemID }
    public var revisionID: RevisionID { parsed.header.revisionID }
    public var parents: [RevisionBodyID] { parsed.header.parents }

    /// Unwraps only `recipient`'s entry, checks commitment, header and frame, then the
    /// canonical padding and schema. `body` runs only after every check has succeeded.
    public func open<Result>(as recipient: RecipientKey, _ body: (RecordContent) throws -> Result) throws -> Result {
        let message = parsed.message
        let sortKey = [recipient.role.rawValue] + Array(recipient.publicKey)
        guard let edk = message.edks.first(where: { $0.sortKey == sortKey }) else { throw RecordError.notRecipient }
        let headerHash = sha256(parsed.headerBytes)
        let dataKey = try ESDK.unwrap(edk, with: recipient, headerHash: headerHash, message: message)
        var padded = try ESDK.decrypt(message, dataKey: dataKey)
        defer { wipe(&padded) }
        let content = try Payload.decode(padded, kind: parsed.header.kind)
        return try body(content)
    }
}
