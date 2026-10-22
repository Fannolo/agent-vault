#if DEBUG
import CryptoKit
import Foundation

/// Generated software P-256 key for tests and the DEBUG preview only. It performs no user-presence
/// check and is compiled out of release builds.
package final class SoftwareFixtureSigner: ApprovalSigning, @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()
    private let lock = NSLock()
    private var _signCount = 0
    private var _reasons: [String] = []
    package var failWith: ApprovalSigningError?

    package init() {}

    package var signCount: Int { lock.withLock { _signCount } }
    package var reasons: [String] { lock.withLock { _reasons } }
    package var publicKey: P256.Signing.PublicKey { key.publicKey }

    package func registration() async throws -> ApprovalKeyRegistration {
        ApprovalKeyRegistration(publicKeyX963: key.publicKey.x963Representation, protection: .softwareFixture)
    }

    package func sign(payload: Data, reason: String) async throws -> Data {
        if let failWith { throw failWith }
        lock.withLock { _signCount += 1; _reasons.append(reason) }
        return try key.signature(for: payload).derRepresentation
    }
}
#endif
