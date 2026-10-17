import AgentVaultContracts
import CryptoKit
import Foundation

/// A signing digest for the operation metadata the human app can verify and display.
/// Credential contents are deliberately excluded: no password/token content hash
/// leaves the broker, even on the private admin channel.
public enum ApprovalIntent {
    private struct Envelope: Encodable {
        let domain = "agent-vault/admin/v1"
        let id: UUID
        let expiresAtMilliseconds: Int64
        let nonce: Data
        let request: AdminRequest
    }

    public static func payload(request: AdminRequest, id: UUID, nonce: Data, expiresAt: Date) throws -> Data {
        let milliseconds = expiresAt.timeIntervalSince1970 * 1000
        guard nonce.count == 32, milliseconds.isFinite, abs(milliseconds) < 9_007_199_254_740_991 else {
            throw IntentError.invalidChallenge
        }
        var metadata = request
        metadata.credential = nil
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(Envelope(id: id, expiresAtMilliseconds: Int64(milliseconds.rounded()), nonce: nonce, request: metadata))
        return Data(SHA256.hash(data: bytes))
    }

    public enum IntentError: Error, Sendable { case invalidChallenge }
}
