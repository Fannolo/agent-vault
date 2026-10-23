import Crypto
import VaultPersistence

/// Deterministic opaque bytes standing in for already-encrypted frames and signed objects.
/// They are not ciphertext and carry no secret; separate processes regenerate them by seed.
public enum Synthetic {
    public static func bytes(_ label: String, seed: UInt64, count: Int) -> [UInt8] {
        var out = Array("AV-SYNTHETIC-OPAQUE/\(label)/".utf8)
        var counter: UInt64 = 0
        while out.count < count {
            var block = Array(label.utf8)
            withUnsafeBytes(of: seed.bigEndian) { block += $0 }
            withUnsafeBytes(of: counter.bigEndian) { block += $0 }
            out += SHA256.hash(data: block)
            counter += 1
        }
        return Array(out.prefix(count))
    }

    public static func state(seed: UInt64, count: Int = 512) -> SealedState {
        SealedState(frame: bytes("state", seed: seed, count: count))
    }

    public static func objects(seed: UInt64, count: Int, size: Int) -> [SignedObject] {
        (0..<count).map { SignedObject(bytes: bytes("object-\($0)", seed: seed, count: size)) }
    }
}
