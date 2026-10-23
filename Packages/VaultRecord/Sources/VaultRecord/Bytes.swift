import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Fixed refusal codes. Descriptions are the raw value only; no input byte is interpolated.
public enum RecordError: String, Error, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    /// Grammar, length, order or count violation, found before any key operation.
    case malformed
    /// Reserved record kind 4 (encrypted head snapshot) pending the collection protocol.
    case unsupported
    /// Valid bytes for another vault, membership, author or recipient set.
    case unexpectedAuthority
    case badSignature
    /// X25519 or Ed25519 key that is noncanonical or of small order.
    case invalidKey
    case notRecipient
    case wrapAuthentication
    case commitmentMismatch
    case headerAuthentication
    case frameAuthentication
    /// Authenticated plaintext with bad padding, schema, version or kind.
    case invalidPayload
    /// Content that this codec refuses to seal.
    case invalidContent

    public var description: String { rawValue }
    public var debugDescription: String { rawValue }
}

struct ByteWriter {
    var bytes: [UInt8] = []

    init(capacity: Int = 0) { bytes.reserveCapacity(capacity) }

    mutating func u8(_ value: UInt8) { bytes.append(value) }
    mutating func u16(_ value: UInt16) { append(UInt64(value), width: 2) }
    mutating func u32(_ value: UInt32) { append(UInt64(value), width: 4) }
    mutating func u64(_ value: UInt64) { append(value, width: 8) }
    mutating func raw<Bytes: Sequence>(_ value: Bytes) where Bytes.Element == UInt8 { bytes.append(contentsOf: value) }

    mutating func f16(_ value: some Collection<UInt8>) {
        precondition(value.count <= Int(UInt16.max))
        u16(UInt16(value.count))
        raw(value)
    }

    mutating func f32(_ value: some Collection<UInt8>) {
        precondition(value.count <= Int(UInt32.max))
        u32(UInt32(value.count))
        raw(value)
    }

    private mutating func append(_ value: UInt64, width: Int) {
        for shift in stride(from: (width - 1) * 8, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    var data: Data { Data(bytes) }
}

/// Bounded reader over any Data, including slices whose start index is not zero.
/// Every claimed length is checked against the remaining input before a slice is taken.
struct ByteReader {
    private let data: Data
    private var index: Data.Index

    init(_ data: Data) {
        self.data = data
        index = data.startIndex
    }

    var remaining: Int { data.endIndex - index }
    var position: Data.Index { index }

    mutating func take(_ count: Int) throws(RecordError) -> Data {
        guard count >= 0, count <= remaining else { throw .malformed }
        defer { index += count }
        return data[index..<(index + count)]
    }

    mutating func u8() throws(RecordError) -> UInt8 { try take(1).first! }
    mutating func u16() throws(RecordError) -> UInt16 { UInt16(try integer(2)) }
    mutating func u32() throws(RecordError) -> UInt32 { UInt32(try integer(4)) }

    mutating func f16(maximum: Int) throws(RecordError) -> Data {
        let count = Int(try u16())
        guard count <= maximum else { throw .malformed }
        return try take(count)
    }

    mutating func f32(maximum: Int) throws(RecordError) -> Data {
        let count = Int(try u32())
        guard count <= maximum else { throw .malformed }
        return try take(count)
    }

    func finish() throws(RecordError) { guard remaining == 0 else { throw .malformed } }

    private mutating func integer(_ width: Int) throws(RecordError) -> UInt64 {
        try take(width).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
}

func strictlyAscending(_ values: [[UInt8]]) -> Bool {
    zip(values, values.dropFirst()).allSatisfy { $0.lexicographicallyPrecedes($1) }
}

/// Equal-length comparison without a content-dependent early return.
func constantTimeEqual(_ left: some Collection<UInt8>, _ right: some Collection<UInt8>) -> Bool {
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for (a, b) in zip(left, right) { difference |= a ^ b }
    return difference == 0
}

/// RFC 3629 well-formed UTF-8: no overlong forms, surrogates or values above U+10FFFF.
/// Validates bytes in place so secret fields are never converted to String.
func isWellFormedUTF8(_ bytes: UnsafeRawBufferPointer) -> Bool {
    var index = 0
    while index < bytes.count {
        let lead = bytes[index]
        let length: Int
        var lower: UInt8 = 0x80, upper: UInt8 = 0xbf
        switch lead {
        case 0x00...0x7f: index += 1; continue
        case 0xc2...0xdf: length = 2
        case 0xe0: length = 3; lower = 0xa0
        case 0xe1...0xec, 0xee...0xef: length = 3
        case 0xed: length = 3; upper = 0x9f
        case 0xf0: length = 4; lower = 0x90
        case 0xf1...0xf3: length = 4
        case 0xf4: length = 4; upper = 0x8f
        default: return false
        }
        guard index + length <= bytes.count else { return false }
        guard (lower...upper).contains(bytes[index + 1]) else { return false }
        for offset in 2..<length where !(0x80...0xbf).contains(bytes[index + offset]) { return false }
        index += length
    }
    return true
}

/// Best-effort clearing of this one buffer. Earlier copies, swap and crash dumps are not covered.
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buffer in
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        #if canImport(Darwin)
        _ = memset_s(base, buffer.count, 0, buffer.count)
        #else
        explicit_bzero(base, buffer.count)
        #endif
    }
    bytes.removeAll()
}

func wipe(_ data: inout Data) {
    data.withUnsafeMutableBytes { buffer in
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        #if canImport(Darwin)
        _ = memset_s(base, buffer.count, 0, buffer.count)
        #else
        explicit_bzero(base, buffer.count)
        #endif
    }
    data = Data()
}

func hex(_ bytes: some Sequence<UInt8>) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    for byte in bytes {
        out.append(digits[Int(byte >> 4)])
        out.append(digits[Int(byte & 0x0f)])
    }
    return String(decoding: out, as: UTF8.self)
}
