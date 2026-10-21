import Crypto
import Foundation

/// In-memory duplicate/conflict detection only. No persistence, freshness or membership protocol.
/// A trusted caller supplies the fixed author allowlist independently of incoming record bytes.
public struct RevisionLog: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "RevisionLog(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    public enum Acceptance: Equatable, Sendable {
        case inserted, duplicate, conflict, rejected
    }

    private let vaultID: Data
    private let trustedAuthors: [Data: Curve25519.Signing.PublicKey]
    private var records: [Data: Data] = [:]

    public init(vaultID: Data, trustedAuthors: [Curve25519.Signing.PublicKey]) throws {
        guard vaultID.count == 16 else { throw VaultError.malformed }
        self.vaultID = vaultID
        self.trustedAuthors = Dictionary(trustedAuthors.map { ($0.rawRepresentation, $0) },
                                         uniquingKeysWith: { first, _ in first })
    }

    public mutating func accept(_ bytes: Data) -> Acceptance {
        do {
            let record = try SealedRecord.parse(bytes)
            guard record.context.vaultID == vaultID, let author = trustedAuthors[record.author] else {
                return .rejected
            }
            try record.verify(author: author)
            if let previous = records[record.context.revisionID] {
                return previous == bytes ? .duplicate : .conflict
            }
            records[record.context.revisionID] = Data(bytes)
            return .inserted
        } catch {
            return .rejected
        }
    }
}
