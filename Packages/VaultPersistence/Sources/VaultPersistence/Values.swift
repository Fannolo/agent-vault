import Crypto

/// SHA-256 of the exact stored sealed state frame. Public, nonsecret identifier.
public struct StateID: Hashable, Sendable, CustomStringConvertible {
    public let bytes: [UInt8]

    public init?(bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        self.bytes = bytes
    }

    init(digestOf frame: [UInt8]) { bytes = Array(SHA256.hash(data: frame)) }

    public var description: String { hex(bytes) }
}

/// SHA-256 of an immutable object's exact bytes. Not convertible to or from `StateID`.
public struct ObjectDigest: Hashable, Sendable, CustomStringConvertible {
    public let bytes: [UInt8]

    public init?(bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        self.bytes = bytes
    }

    init(digestOf object: [UInt8]) { bytes = Array(SHA256.hash(data: object)) }

    public var description: String { hex(bytes) }
}

/// One opaque, already-encrypted local state frame. The kernel neither decrypts nor
/// interprets it, and storing it does not make it approved authority.
public struct SealedState: Sendable, Equatable {
    public let frame: [UInt8]
    public let id: StateID

    public init(frame: [UInt8]) {
        self.frame = frame
        id = StateID(digestOf: frame)
    }
}

/// One immutable opaque signed object, addressed by the digest of its bytes.
public struct SignedObject: Sendable, Equatable {
    public let bytes: [UInt8]
    public let digest: ObjectDigest

    public init(bytes: [UInt8]) {
        self.bytes = bytes
        digest = ObjectDigest(digestOf: bytes)
    }

    /// For bytes that arrive with a claimed address (e.g. from a transport).
    public init(bytes: [UInt8], expectedDigest: ObjectDigest) throws(PersistenceError) {
        self.init(bytes: bytes)
        guard digest == expectedDigest else { throw .refused(.digestMismatch) }
    }
}

/// Caller-visible expected state: generation plus exact opaque frame hash. This is not
/// the custody identity: aborted attempts may reuse a Head with different objects.
public struct Head: Hashable, Sendable {
    public let generation: UInt64
    public let state: StateID

    public init(generation: UInt64, state: StateID) {
        self.generation = generation
        self.state = state
    }
}

/// Collision-resistant identity of one verified complete logical kernel image.
/// Used by the custody port; it is neither cryptographic authority nor an attempt ID.
public struct ImageID: Hashable, Sendable {
    public let bytes: [UInt8]

    public init?(bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        self.bytes = bytes
    }
}

/// Custody binds both the caller-visible head and the entire immutable inventory.
/// Equal complete images can have equal identities after an abandoned attempt.
public struct PinnedImage: Hashable, Sendable {
    public let head: Head
    public let image: ImageID

    public init(head: Head, image: ImageID) {
        self.head = head
        self.image = image
    }
}

/// Kernel bounds. `standard` mirrors the current transport cap and is a test/kernel budget,
/// not a product lifetime-capacity or retention decision.
public struct KernelLimits: Sendable, Equatable {
    public let maxObjectBytes: Int
    public let maxStateBytes: Int
    public let maxObjectCount: Int
    public let maxTotalObjectBytes: Int

    public static let standard = KernelLimits(checked: 1 << 20, 16 << 20, 10_000, 512 << 20)

    public init(maxObjectBytes: Int, maxStateBytes: Int, maxObjectCount: Int,
                maxTotalObjectBytes: Int) throws(PersistenceError) {
        // SQLite binds lengths as Int32; keep every single value well inside that.
        let ceiling = 1 << 30
        guard (1...ceiling).contains(maxObjectBytes), (1...ceiling).contains(maxStateBytes),
              (1...1_000_000).contains(maxObjectCount), maxTotalObjectBytes >= 1,
              maxTotalObjectBytes <= Int(Int32.max) * 64 else { throw .refused(.invalidLimits) }
        self.init(checked: maxObjectBytes, maxStateBytes, maxObjectCount, maxTotalObjectBytes)
    }

    private init(checked object: Int, _ state: Int, _ count: Int, _ total: Int) {
        maxObjectBytes = object
        maxStateBytes = state
        maxObjectCount = count
        maxTotalObjectBytes = total
    }
}

func hex(_ bytes: [UInt8]) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out = [UInt8]()
    out.reserveCapacity(bytes.count * 2)
    for byte in bytes {
        out.append(digits[Int(byte >> 4)])
        out.append(digits[Int(byte & 15)])
    }
    return String(decoding: out, as: UTF8.self)
}
