import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum CloudError: String, Error, Sendable {
    case invalidConfiguration, invalidObject, unauthorized, conflict, unavailable, invalidResponse, writeUnconfirmed
}

public struct CloudDigest: Sendable, Hashable {
    public let bytes: Data
    public init(_ bytes: Data) throws(CloudError) {
        guard bytes.count == 32 else { throw .invalidObject }
        self.bytes = Data(bytes)
    }
    var hex: String { bytes.map { String(format: "%02x", $0) }.joined() }
}

/// Opaque ciphertext transport. Its construction does not validate a vault format or authority.
public struct CloudObject: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let maximumBytes = 1_048_576
    public let bytes: Data
    public let digest: CloudDigest
    public init(_ bytes: Data) throws(CloudError) {
        guard (1...Self.maximumBytes).contains(bytes.count) else { throw .invalidObject }
        self.bytes = Data(bytes)
        digest = try CloudDigest(Data(SHA256.hash(data: bytes)))
    }
    public var description: String { "CloudObject(opaque)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

public struct CloudChange: Sendable {
    public let sequence: Int64
    public let object: CloudObject
    public init(sequence: Int64, object: CloudObject) throws(CloudError) {
        guard sequence > 0 else { throw .invalidObject }
        self.sequence = sequence; self.object = object
    }
}

public struct CloudHead: Sendable, Equatable {
    public let digest: CloudDigest
    public let revision: Int64
    public init(digest: CloudDigest, revision: Int64) throws(CloudError) {
        guard revision > 0 else { throw .invalidObject }
        self.digest = digest; self.revision = revision
    }
}

/// The sync layer must independently validate signatures, membership and pinned checkpoints.
/// Sequence and conditional head writes are honest-server coordination, not freshness proofs.
public protocol CloudTransport: Sendable {
    func createVault(_ vault: UUID) async throws
    func put(_ object: CloudObject, vault: UUID) async throws
    func changes(vault: UUID, after cursor: Int64) async throws -> [CloudChange]
    func head(vault: UUID) async throws -> CloudHead?
    func compareAndSwap(vault: UUID, expected: CloudDigest?, new: CloudDigest) async throws -> Int64
}

public struct CloudEndpoint: Sendable {
    let origin: URL
    let publishableKey: String
    public init(origin: URL, publishableKey: String) throws(CloudError) {
        guard let parts = URLComponents(url: origin, resolvingAgainstBaseURL: false),
              parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/",
              publishableKey.hasPrefix("sb_publishable_"), (16...256).contains(publishableKey.utf8.count),
              publishableKey.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0)
                  || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { throw .invalidConfiguration }
        self.origin = origin
        self.publishableKey = publishableKey
    }
}
