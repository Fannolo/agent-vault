import Crypto
import Foundation

/// Raw row bytes. Role and capability are interpreted only by semantic policy, after lineage.
struct MembershipRow: Equatable, Sendable {
    var role: UInt8
    var capability: UInt8
    var agreementKey: Data
    var sortKey: Data { Data([role]) + agreementKey }
}

/// The controller-signed AVMEMB01 body. Encoding performs no validation.
struct MembershipBody: Equatable {
    static let magic = Data("AVMEMB01".utf8)
    static let prefixSize = 135
    static let rowSize = 34
    static let signatureSize = 64
    static let memberLimit = 32
    static let minimumRecordSize = prefixSize + rowSize + signatureSize
    static let maximumRecordSize = prefixSize + rowSize * memberLimit + signatureSize

    var vaultID: Data
    var sequence: UInt64
    var parent: Data
    var controllerKey: Data
    var writerKey: Data
    var rows: [MembershipRow]

    var encoded: Data {
        var writer = BinaryWriter()
        writer.bytes(Self.magic)
        writer.bytes(Data([1, 1, 1]))
        writer.bytes(vaultID)
        writer.bytes(Data((0..<8).reversed().map { UInt8(truncatingIfNeeded: sequence >> (8 * UInt64($0))) }))
        writer.bytes(parent)
        writer.bytes(controllerKey)
        writer.bytes(writerKey)
        writer.count(rows.count)
        for row in rows {
            writer.byte(row.role)
            writer.byte(row.capability)
            writer.bytes(row.agreementKey)
        }
        return writer.data
    }
}

struct MembershipRecord {
    let body: MembershipBody
    let bodyBytes: Data
    let signature: Data
    /// Owned zero-based copy of the complete signed input.
    let encoded: Data

    /// Structural grammar only: size, fixed tags, count, widths, strict row order and exact
    /// re-encoding. Bounds are checked before the owned copy and before row allocation.
    static func parse(_ input: Data) throws -> MembershipRecord {
        guard input.count >= MembershipBody.minimumRecordSize,
              input.count <= MembershipBody.maximumRecordSize else { throw MembershipPolicyError.malformed }
        let data = Data(input)
        guard data.prefix(8) == MembershipBody.magic, data[8] == 1, data[9] == 1, data[10] == 1 else {
            throw MembershipPolicyError.malformed
        }
        let count = data[131..<135].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard count >= 1, count <= UInt32(MembershipBody.memberLimit) else { throw MembershipPolicyError.malformed }
        let memberCount = Int(count)
        let bodySize = MembershipBody.prefixSize + MembershipBody.rowSize * memberCount
        guard data.count == bodySize + MembershipBody.signatureSize else { throw MembershipPolicyError.malformed }
        let rows = (0..<memberCount).map { index in
            let offset = MembershipBody.prefixSize + MembershipBody.rowSize * index
            return MembershipRow(role: data[offset], capability: data[offset + 1],
                                 agreementKey: data.subdata(in: (offset + 2)..<(offset + MembershipBody.rowSize)))
        }
        guard strictlySorted(rows.map(\.sortKey)) else { throw MembershipPolicyError.malformed }
        let body = MembershipBody(vaultID: data.subdata(in: 11..<27),
                                  sequence: data[27..<35].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) },
                                  parent: data.subdata(in: 35..<67), controllerKey: data.subdata(in: 67..<99),
                                  writerKey: data.subdata(in: 99..<131), rows: rows)
        let bodyBytes = data.subdata(in: 0..<bodySize)
        guard body.encoded == bodyBytes else { throw MembershipPolicyError.malformed }
        return MembershipRecord(body: body, bodyBytes: bodyBytes,
                                signature: data.subdata(in: bodySize..<data.count), encoded: data)
    }
}

/// Validated decrypting recipients of one snapshot, in AVSEAL01 envelope order.
struct ActiveMembership: Equatable, Sendable {
    let recipients: [Data]
    let writerAgreementKey: Data?
    var writerActive: Bool { writerAgreementKey != nil }
}

enum MembershipPolicy {
    /// 2^255 - 19, little endian. A bounded encoding comparison, not curve arithmetic.
    static let excludedModulus: [UInt8] = [0xed] + Array(repeating: 0xff, count: 30) + [0x7f]

    static func isCanonicalCoordinate(_ key: Data) -> Bool {
        guard key.count == 32 else { return false }
        for (byte, limit) in zip(key.reversed(), excludedModulus.reversed()) where byte != limit {
            return byte < limit
        }
        return false
    }

    static func validateAgreementKey(_ key: Data) throws {
        guard isCanonicalCoordinate(key) else { throw MembershipPolicyError.invalidMemberKey }
        do {
            _ = try RevisionRecipient(role: .device, publicKey: Curve25519.KeyAgreement.PublicKey(rawRepresentation: key))
        } catch {
            throw MembershipPolicyError.invalidMemberKey
        }
    }

    /// Rows semantic policy. A nil pin means genesis, which requires exactly one writer.
    /// Header writer equality is checked by the caller before this.
    static func validate(rows: [MembershipRow], pinnedWriterAgreement: Data?) throws -> ActiveMembership {
        var writers: [Data] = []
        var hasDevice = false
        for row in rows {
            guard let kind = MemberKind(role: row.role, capability: row.capability) else {
                throw MembershipPolicyError.malformed
            }
            if kind == .writer { writers.append(row.agreementKey) }
            if kind != .recovery { hasDevice = true }
        }
        guard (1...MembershipBody.memberLimit).contains(rows.count), hasDevice, writers.count <= 1,
              pinnedWriterAgreement != nil || writers.count == 1,
              Set(rows.map(\.agreementKey)).count == rows.count else { throw MembershipPolicyError.malformed }
        if let pinned = pinnedWriterAgreement, let writer = writers.first, writer != pinned {
            throw MembershipPolicyError.unsupportedAuthorityChange
        }
        for row in rows { try validateAgreementKey(row.agreementKey) }
        return ActiveMembership(recipients: rows.map(\.sortKey), writerAgreementKey: writers.first)
    }
}

enum MembershipSequence {
    static func successor(after sequence: UInt64) throws -> UInt64 {
        let (next, overflow) = sequence.addingReportingOverflow(1)
        guard !overflow else { throw MembershipPolicyError.sequenceExhausted }
        return next
    }

    /// Compares in UInt64 before converting, so an untrusted sequence never becomes an Int index first.
    static func historyIndex(of sequence: UInt64, current: UInt64) -> Int? {
        guard sequence <= current else { return nil }
        return Int(exactly: sequence)
    }
}
