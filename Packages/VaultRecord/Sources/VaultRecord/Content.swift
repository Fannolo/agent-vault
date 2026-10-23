import Foundation
@_spi(SecretReveal) import VaultSecret

/// Record kinds sealed by this unit. Kind 4 (encrypted head snapshot) is reserved and refused.
public enum RecordKind: UInt8, Sendable {
    case login = 1, apiToken = 2, tombstone = 3
}

/// Exact username state. Explicitly empty is distinct from absent; neither is a placeholder.
public enum Username: Sendable {
    case absent
    case empty
    case value(SecretBytes)
}

/// Encrypted UTF-8 text that may be empty, such as a title.
public enum RecordText: Sendable {
    case empty
    case value(SecretBytes)
}

/// Version 2 API-token service registry (root SERVICE-TAGS.md): exactly 0x0001, the GitHub
/// personal access token for the fixed profile adapter. Every other value is refused.
public enum APIService: UInt16, Sendable {
    case github = 0x0001
}

/// Canonical HTTPS origin: lowercase LDH/punycode host, no trailing dot, no userinfo, path,
/// query or fragment; explicit port only when not 443. IP literals are refused. A recorded
/// origin is catalog data, not authorization of a destination.
public struct CanonicalOrigin: Hashable, Sendable, CustomStringConvertible {
    public static let maximumBytes = 256
    public let ascii: String

    public init(_ ascii: String) throws {
        guard Self.isCanonical(Array(ascii.utf8)) else { throw RecordError.invalidContent }
        self.ascii = ascii
    }

    init(validated bytes: Data) throws(RecordError) {
        guard Self.isCanonical(Array(bytes)) else { throw .invalidPayload }
        ascii = String(decoding: bytes, as: UTF8.self)
    }

    public var description: String { ascii }

    static func isCanonical(_ bytes: [UInt8]) -> Bool {
        let scheme = Array("https://".utf8)
        guard bytes.count <= maximumBytes, bytes.starts(with: scheme) else { return false }
        let authority = bytes.dropFirst(scheme.count)
        let parts = authority.split(separator: UInt8(ascii: ":"), omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2, isHost(Array(parts[0])) else { return false }
        if parts.count == 2 {
            let port = Array(parts[1])
            guard (1...5).contains(port.count), port.allSatisfy({ (0x30...0x39).contains($0) }),
                  port[0] != 0x30, let value = Int(String(decoding: port, as: UTF8.self)),
                  value <= 65535, value != 443 else { return false }
        }
        return true
    }

    private static func isHost(_ host: [UInt8]) -> Bool {
        guard (1...253).contains(host.count) else { return false }
        let labels = host.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        // WHATWG sends numeric-ending domains through IPv4 parsing. This DNS-only
        // profile refuses them, including hexadecimal and invalid octal spellings.
        guard let last = labels.last else { return false }
        let decimal = !last.isEmpty && last.allSatisfy { (0x30...0x39).contains($0) }
        let hexadecimal = last.starts(with: [0x30, 0x78]) && last.dropFirst(2).allSatisfy {
            (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
        }
        guard !decimal, !hexadecimal else { return false }
        return labels.allSatisfy { label in
            (1...63).contains(label.count) && label.first != UInt8(ascii: "-") && label.last != UInt8(ascii: "-")
                && label.allSatisfy { (0x61...0x7a).contains($0) || (0x30...0x39).contains($0) || $0 == UInt8(ascii: "-") }
        }
    }
}

public struct LoginContent: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let maximumTitleBytes = 1024
    public static let maximumUsernameBytes = 1024
    public static let maximumOrigins = 32

    public let title: RecordText
    public let username: Username
    public let password: SecretBytes
    /// Strictly ascending by bytes.
    public let origins: [CanonicalOrigin]

    /// Sorts origins; refuses duplicates, invalid UTF-8 and out-of-range lengths.
    public init(title: RecordText, username: Username, password: SecretBytes, origins: [CanonicalOrigin]) throws {
        let sorted = origins.sorted { Array($0.ascii.utf8).lexicographicallyPrecedes(Array($1.ascii.utf8)) }
        guard textIsValid(title, maximum: Self.maximumTitleBytes),
              usernameIsValid(username), sorted.count <= Self.maximumOrigins,
              strictlyAscending(sorted.map { Array($0.ascii.utf8) }) else { throw RecordError.invalidContent }
        self.title = title
        self.username = username
        self.password = password
        self.origins = sorted
    }

    init(trusted title: RecordText, username: Username, password: SecretBytes, origins: [CanonicalOrigin]) {
        self.title = title
        self.username = username
        self.password = password
        self.origins = origins
    }

    public var description: String { "LoginContent(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

public struct APITokenContent: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let title: RecordText
    public let token: SecretBytes
    public let service: APIService

    public init(title: RecordText, token: SecretBytes, service: APIService) throws {
        guard textIsValid(title, maximum: LoginContent.maximumTitleBytes) else { throw RecordError.invalidContent }
        self.title = title
        self.token = token
        self.service = service
    }

    init(trusted title: RecordText, token: SecretBytes, service: APIService) {
        self.title = title
        self.token = token
        self.service = service
    }

    public var description: String { "APITokenContent(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

public enum RecordContent: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case login(LoginContent)
    case apiToken(APITokenContent)
    case tombstone

    public var kind: RecordKind {
        switch self {
        case .login: .login
        case .apiToken: .apiToken
        case .tombstone: .tombstone
        }
    }

    public var description: String { "RecordContent(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

private func textIsValid(_ text: RecordText, maximum: Int) -> Bool {
    guard case .value(let bytes) = text else { return true }
    return bytes.withUnsafeBytes { $0.count <= maximum && isWellFormedUTF8($0) }
}

private func usernameIsValid(_ username: Username) -> Bool {
    guard case .value(let bytes) = username else { return true }
    return bytes.withUnsafeBytes { $0.count <= LoginContent.maximumUsernameBytes && isWellFormedUTF8($0) }
}

// MARK: - Canonical logical payload and padding

enum Payload {
    static let version: UInt8 = 2
    static let buckets = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288]
    /// Largest bucket a kind 1–3 payload can need: login maximum logical length is 26,700.
    static let maximumBucketForKinds1To3 = 32768

    static func bucket(forLogicalCount count: Int) -> Int? {
        buckets.first { $0 >= 4 + count }
    }

    /// Secret-bearing bytes. Callers must `wipe` the result.
    static func logical(_ content: RecordContent) -> [UInt8] {
        var writer = ByteWriter(capacity: 512)
        writer.u8(version)
        writer.u8(content.kind.rawValue)
        switch content {
        case .login(let login):
            writeText(login.title, into: &writer)
            switch login.username {
            case .absent: writer.u8(0)
            case .empty: writer.u8(1); writer.u16(0)
            case .value(let value): writer.u8(1); value.withUnsafeBytes { writer.f16($0) }
            }
            login.password.withUnsafeBytes { writer.f32($0) }
            writer.u8(UInt8(login.origins.count))
            for origin in login.origins { writer.f16(Array(origin.ascii.utf8)) }
        case .apiToken(let token):
            writeText(token.title, into: &writer)
            token.token.withUnsafeBytes { writer.f32($0) }
            writer.u16(token.service.rawValue)
        case .tombstone:
            break
        }
        return writer.bytes
    }

    /// `u32(L) || logical || zeros` in the smallest fitting bucket. Callers must `wipe` it.
    static func pad(_ logical: [UInt8]) -> [UInt8] {
        let size = bucket(forLogicalCount: logical.count)!
        var writer = ByteWriter(capacity: size)
        writer.u32(UInt32(logical.count))
        writer.raw(logical)
        writer.raw(repeatElement(UInt8(0), count: size - 4 - logical.count))
        return writer.bytes
    }

    /// Strict inverse of `pad` and `logical`. Allocates secret storage only after every
    /// structural check of its own field succeeds.
    static func decode(_ padded: Data, kind: RecordKind) throws(RecordError) -> RecordContent {
        var reader = ByteReader(padded)
        let count = Int(try mapped { () throws(RecordError) in try reader.u32() })
        guard count <= padded.count - 4, bucket(forLogicalCount: count) == padded.count else { throw .invalidPayload }
        let logical = try mapped { () throws(RecordError) in try reader.take(count) }
        let padding = try mapped { () throws(RecordError) in try reader.take(reader.remaining) }
        guard padding.allSatisfy({ $0 == 0 }) else { throw .invalidPayload }
        return try mapped { () throws(RecordError) in try decodeLogical(logical, kind: kind) }
    }

    private static func decodeLogical(_ logical: Data, kind: RecordKind) throws(RecordError) -> RecordContent {
        var reader = ByteReader(logical)
        guard try reader.u8() == version, try reader.u8() == kind.rawValue else { throw .invalidPayload }
        let content: RecordContent
        switch kind {
        case .login:
            let title = try readText(&reader)
            let username: Username
            switch try reader.u8() {
            case 0: username = .absent
            case 1:
                let bytes = try reader.f16(maximum: LoginContent.maximumUsernameBytes)
                username = bytes.isEmpty ? .empty : .value(try utf8Secret(bytes))
            default: throw .invalidPayload
            }
            let password = try secret(reader.f32(maximum: SecretBytes.maximumBytes))
            let originCount = Int(try reader.u8())
            guard originCount <= LoginContent.maximumOrigins else { throw .invalidPayload }
            var origins: [CanonicalOrigin] = []
            for _ in 0..<originCount {
                origins.append(try CanonicalOrigin(validated: reader.f16(maximum: CanonicalOrigin.maximumBytes)))
            }
            guard strictlyAscending(origins.map { Array($0.ascii.utf8) }) else { throw .invalidPayload }
            content = .login(LoginContent(trusted: title, username: username, password: password, origins: origins))
        case .apiToken:
            let title = try readText(&reader)
            let token = try secret(reader.f32(maximum: SecretBytes.maximumBytes))
            guard let service = APIService(rawValue: try reader.u16()) else { throw .invalidPayload }
            content = .apiToken(APITokenContent(trusted: title, token: token, service: service))
        case .tombstone:
            content = .tombstone
        }
        try reader.finish()
        return content
    }

    private static func writeText(_ text: RecordText, into writer: inout ByteWriter) {
        switch text {
        case .empty: writer.u16(0)
        case .value(let value): value.withUnsafeBytes { writer.f16($0) }
        }
    }

    private static func readText(_ reader: inout ByteReader) throws(RecordError) -> RecordText {
        let bytes = try reader.f16(maximum: LoginContent.maximumTitleBytes)
        return bytes.isEmpty ? .empty : .value(try utf8Secret(bytes))
    }

    private static func utf8Secret(_ bytes: Data) throws(RecordError) -> SecretBytes {
        guard bytes.withUnsafeBytes({ isWellFormedUTF8($0) }) else { throw .invalidPayload }
        return try secret(bytes)
    }

    private static func secret(_ bytes: Data) throws(RecordError) -> SecretBytes {
        var copy = [UInt8](bytes)
        do {
            return try SecretBytes(consuming: &copy)
        } catch {
            wipe(&copy)
            throw .invalidPayload
        }
    }

    /// Inside authenticated plaintext every grammar failure is an `invalidPayload`.
    private static func mapped<T>(_ body: () throws(RecordError) -> T) throws(RecordError) -> T {
        do {
            return try body()
        } catch .malformed {
            throw .invalidPayload
        } catch {
            throw error
        }
    }
}
