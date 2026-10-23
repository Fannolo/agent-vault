internal import CCryptoBoringSSL
import Foundation

/// Proposed version-2 Ed25519 acceptance predicate (root SIGNATURE-PROFILE.md; not yet
/// approved). One effective verifier on every platform: the vendored BoringSSL
/// `ED25519_verify` of swift-crypto 5.0.3 (c2cbadd7263439d8015189668f96ff5b5be565ce),
/// uncofactored, preceded by encoding and small-order screening. The OS verifier is never
/// the authority predicate. Screening is not proof of a curve point, prime-subgroup key,
/// enrolled writer or key possession.
enum SignatureProfile {
    /// Sign-masked small-order y values from libsodium 1.0.20-RELEASE
    /// `ge25519_has_small_order`. The noncanonical p and p+1 aliases fail `y < p` first.
    static let smallOrderY: [[UInt8]] = [
        [UInt8](repeating: 0, count: 32),
        [1] + [UInt8](repeating: 0, count: 31),
        [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
         0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
        [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
         0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
        [0xec] + [UInt8](repeating: 0xff, count: 30) + [0x7f],
    ]

    /// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    static let order: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                                 0xde, 0x14] + [UInt8](repeating: 0, count: 15) + [0x10]

    /// Steps 1–3 for A or R: 32 bytes, sign-masked y < p, y not a small-order value.
    /// Reads a temporary copy; received bytes are never normalized.
    static func screensPoint(_ encoding: some Collection<UInt8>) -> Bool {
        var y = Array(encoding)
        guard y.count == 32 else { return false }
        y[31] &= 0x7f
        return !isAtLeastFieldPrime(y) && !smallOrderY.contains(y)
    }

    /// Step 4: S < L as an unsigned little-endian integer.
    static func scalarIsReduced(_ s: some Collection<UInt8>) -> Bool {
        let bytes = Array(s)
        guard bytes.count == 32 else { return false }
        for index in stride(from: 31, through: 0, by: -1) where bytes[index] != order[index] {
            return bytes[index] < order[index]
        }
        return false
    }

    /// Steps 1–5 on the original bytes. Typed record validation is the only caller.
    static func verify(signature: Data, body: Data, author: Data) -> Bool {
        let signatureBytes = Array(signature)
        let authorBytes = Array(author)
        guard authorBytes.count == 32, signatureBytes.count == 64, screensPoint(authorBytes),
              screensPoint(signatureBytes[0..<32]), scalarIsReduced(signatureBytes[32..<64]) else { return false }
        return pinnedVerify(signature: signatureBytes, body: body, author: authorBytes)
    }

    /// Step 5 alone. Exposed internally so tests can report the raw pinned outcome.
    static func pinnedVerify(signature: [UInt8], body: Data, author: [UInt8]) -> Bool {
        guard signature.count == 64, author.count == 32 else { return false }
        return body.withUnsafeBytes { message in
            signature.withUnsafeBufferPointer { signaturePointer in
                author.withUnsafeBufferPointer { authorPointer in
                    CCryptoBoringSSL_ED25519_verify(message.bindMemory(to: UInt8.self).baseAddress, message.count,
                                                    signaturePointer.baseAddress!, authorPointer.baseAddress!) == 1
                }
            }
        }
    }
}

/// Encoded little-endian value, top bit already masked, is in [p, 2^255 − 1].
func isAtLeastFieldPrime(_ bytes: [UInt8]) -> Bool {
    bytes[31] & 0x7f == 0x7f && bytes[1...30].allSatisfy { $0 == 0xff } && bytes[0] >= 0xed
}
