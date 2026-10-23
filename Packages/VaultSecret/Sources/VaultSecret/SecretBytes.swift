internal import CSecretMemory

public enum SecretError: String, Error, Sendable {
    case invalidSize
}

/// A redacted owned byte buffer for trusted service code. No serialization or raw-value API.
/// Scoped reveal is SPI, not protection against malicious trusted code. This buffer's
/// cleanup cannot erase earlier copies, swap, crash dumps or values copied by its caller.
public final class SecretBytes: @unchecked Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let maximumBytes = 16_384

    private let allocation: UnsafeMutableRawPointer
    private let count: Int

    /// On success, copies the input, clears its current mutable buffer and empties it.
    /// Other aliases or hidden runtime copies of the original input are outside this API.
    /// If another array shares its storage, Swift copies before mutation; that alias is unchanged.
    public init(consuming source: inout [UInt8]) throws(SecretError) {
        guard (1...Self.maximumBytes).contains(source.count) else { throw .invalidSize }
        count = source.count
        allocation = .allocate(byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
        source.withUnsafeBytes { bytes in
            allocation.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
        }
        source.withUnsafeMutableBytes { bytes in
            av_secret_clear(bytes.baseAddress!, bytes.count)
        }
        source.removeAll(keepingCapacity: false)
    }

    /// Trusted adapters may borrow bytes for one operation. Do not retain the pointer or
    /// return secret-bearing results through public/agent interfaces.
    @_spi(SecretReveal)
    public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
    ) rethrows -> Result {
        try body(UnsafeRawBufferPointer(start: allocation, count: count))
    }

    deinit {
        av_secret_clear(allocation, count)
        allocation.deallocate()
    }

    /// Content comparison for trusted adapters. Length is not hidden; equal-length reads
    /// visit every byte without a content-dependent early return.
    @_spi(SecretReveal)
    public func matches(_ other: SecretBytes) -> Bool {
        guard count == other.count else { return false }
        return av_secret_equal(allocation, other.allocation, count) != 0
    }

    public var description: String { "SecretBytes(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

public struct LoginSecret: Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let username: SecretBytes
    public let password: SecretBytes

    public init(username: SecretBytes, password: SecretBytes) {
        self.username = username
        self.password = password
    }

    public var description: String { "LoginSecret(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
