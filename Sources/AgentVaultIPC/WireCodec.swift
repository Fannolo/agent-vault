import AgentVaultContracts
import Foundation

/// Size, count and value bounds applied on both sides of the connection.
public struct IPCLimits: Sendable, Equatable {
    public var maxRequestBytes: Int
    public var maxReplyBytes: Int
    public var maxInFlightPerConnection: Int
    public var maxInFlightTotal: Int
    public var maxConnectionsPerService: Int

    public init(maxRequestBytes: Int, maxReplyBytes: Int, maxInFlightPerConnection: Int,
                maxInFlightTotal: Int, maxConnectionsPerService: Int) {
        self.maxRequestBytes = maxRequestBytes; self.maxReplyBytes = maxReplyBytes
        self.maxInFlightPerConnection = maxInFlightPerConnection; self.maxInFlightTotal = maxInFlightTotal
        self.maxConnectionsPerService = maxConnectionsPerService
    }

    public static let standard = IPCLimits(maxRequestBytes: 16_384, maxReplyBytes: 524_288,
                                           maxInFlightPerConnection: 4, maxInFlightTotal: 32,
                                           maxConnectionsPerService: 16)
}

/// JSON structure parsed by the same decoder that later builds the typed DTO.
enum JSONTree: Decodable {
    case null, scalar
    case array([JSONTree])
    case object([String: JSONTree])

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if (try? container.decode(Bool.self)) != nil { self = .scalar }
        else if (try? container.decode(Double.self)) != nil { self = .scalar }
        else if (try? container.decode(String.self)) != nil { self = .scalar }
        else if let array = try? container.decode([JSONTree].self) { self = .array(array) }
        else { self = .object(try container.decode([String: JSONTree].self)) }
    }
}

/// Closed key layout. Every listed key is required unless optional; unlisted keys and nulls fail.
indirect enum Shape {
    case scalar
    case array(Shape, max: Int)
    case object(required: Set<String>, optional: Set<String> = [], nested: [String: Shape] = [:])

    func admits(_ tree: JSONTree) -> Bool {
        switch (self, tree) {
        case (.scalar, .scalar): return true
        case let (.array(element, max), .array(items)):
            return items.count <= max && items.allSatisfy(element.admits)
        case let (.object(required, optional, nested), .object(fields)):
            let keys = Set(fields.keys)
            guard required.isSubset(of: keys), keys.isSubset(of: required.union(optional)) else { return false }
            return fields.allSatisfy { key, value in (nested[key] ?? .scalar).admits(value) }
        default: return false
        }
    }
}

enum WireCodec {
    static let maxCredentialBytes = 8192
    static let maxGrantSeconds: Double = 86_400
    static let callLimits = 1...10_000
    static let signatureBytes = 8...72
    static let challengePayloadBytes = 16...1024

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = .sortedKeys
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }

    // MARK: Requests

    static func encode(_ request: ReadRequest) throws(IPCError) -> Data {
        guard let data = try? encoder().encode(request) else { throw .invalidRequest }
        _ = try decodeRead(data, limits: .standard)
        return data
    }

    static func encode(_ request: AdminRequest) throws(IPCError) -> Data {
        guard let data = try? encoder().encode(request) else { throw .invalidRequest }
        _ = try decodeAdmin(data, limits: .standard)
        return data
    }

    static func decodeRead(_ data: Data, limits: IPCLimits) throws(IPCError) -> ReadRequest {
        let (keys, request) = try flatObject(data, as: ReadRequest.self, limits: limits)
        let expected: Set<String> = switch request.operation {
        case .accounts: ["operation"]
        case .run: ["operation", "accountID", "action"]
        case .resume, .cancel: ["operation", "requestID"]
        }
        guard keys == expected else { throw .invalidRequest }
        return request
    }

    static func decodeAdmin(_ data: Data, limits: IPCLimits) throws(IPCError) -> AdminRequest {
        let (keys, request) = try flatObject(data, as: AdminRequest.self, limits: limits)
        let expected: Set<String> = switch request.operation {
        case .enroll: ["operation", "service", "credential"]
        case .rotate: ["operation", "accountID", "credential"]
        case .deleteAccount: ["operation", "accountID"]
        case .pairClient: ["operation", "uid"]
        case .grant: ["operation", "clientID", "accountID", "duration", "callLimit", "requiresApproval"]
        case .revokeGrant: ["operation", "grantID"]
        case .revokeClient: ["operation", "clientID"]
        case .approveInvocation, .rejectInvocation: ["operation", "requestID"]
        case .recover, .prune: ["operation"]
        }
        guard keys == expected else { throw .invalidRequest }
        if let credential = request.credential, !(1...maxCredentialBytes).contains(credential.count) {
            throw .invalidRequest
        }
        if let uid = request.uid, uid == 0 || uid >= UInt32.max - 1 { throw .invalidRequest }
        if let duration = request.duration, !(duration.isFinite && duration > 0 && duration <= maxGrantSeconds) {
            throw .invalidRequest
        }
        if let limit = request.callLimit, !callLimits.contains(limit) { throw .invalidRequest }
        return request
    }

    static func decodeAuthorize(id: String, signature: Data) throws(IPCError) -> UUID {
        guard id.utf8.count == 36, let uuid = UUID(uuidString: id),
              signatureBytes.contains(signature.count) else { throw .invalidRequest }
        return uuid
    }

    private static func flatObject<T: Decodable>(_ data: Data, as type: T.Type,
                                                 limits: IPCLimits) throws(IPCError) -> (Set<String>, T) {
        guard data.count <= limits.maxRequestBytes else { throw .requestTooLarge }
        let decoder = decoder()
        guard case .object(let fields)? = try? decoder.decode(JSONTree.self, from: data),
              fields.values.allSatisfy({ if case .scalar = $0 { true } else { false } }),
              let value = try? decoder.decode(T.self, from: data) else { throw .invalidRequest }
        return (Set(fields.keys), value)
    }

    // MARK: Replies

    enum ReplyKind: String, CaseIterable {
        case readReply, snapshot, challenge, adminReply, error
    }

    /// Wraps a handler result, applying the same validation the client applies.
    static func reply(_ value: some Encodable, kind: ReplyKind, limits: IPCLimits) -> Data? {
        guard let data = try? encoder().encode([kind.rawValue: AnyEncodable(value)]),
              case .success = decodeReply(data, allowed: [kind], limits: limits) else { return nil }
        return data
    }

    static func errorReply(_ code: IPCError) -> Data {
        // Encoding a closed string enum cannot fail.
        try! encoder().encode([ReplyKind.error.rawValue: code])
    }

    /// Parses a reply envelope, accepting only the kinds a given call may return.
    static func decodeReply(_ data: Data, allowed: Set<ReplyKind>, limits: IPCLimits) -> Result<Envelope, IPCError> {
        guard data.count <= limits.maxReplyBytes,
              case .object(let fields)? = try? decoder().decode(JSONTree.self, from: data),
              fields.count == 1, let (key, tree) = fields.first,
              let kind = ReplyKind(rawValue: key), allowed.union([.error]).contains(kind),
              shape(kind).admits(tree) else { return .failure(.malformedReply) }
        do {
            return .success(try envelope(kind, data))
        } catch {
            return .failure(.malformedReply)
        }
    }

    enum Envelope {
        case readReply(ReadReply), snapshot(AdminSnapshot), challenge(AdminChallenge), adminReply(AdminReply)
        case error(IPCError)
    }

    private struct Single<T: Decodable>: Decodable {
        let value: T
        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: AnyKey.self)
            guard let key = container.allKeys.first else { throw IPCError.malformedReply }
            value = try container.decode(T.self, forKey: key)
        }
    }

    private static func envelope(_ kind: ReplyKind, _ data: Data) throws -> Envelope {
        let decoder = decoder()
        switch kind {
        case .readReply:
            let reply = try decoder.decode(Single<ReadReply>.self, from: data).value
            guard isValid(reply) else { throw IPCError.malformedReply }
            return .readReply(reply)
        case .snapshot:
            let snapshot = try decoder.decode(Single<AdminSnapshot>.self, from: data).value
            guard isValid(snapshot) else { throw IPCError.malformedReply }
            return .snapshot(snapshot)
        case .challenge:
            let challenge = try decoder.decode(Single<AdminChallenge>.self, from: data).value
            guard challengePayloadBytes.contains(challenge.payload.count),
                  challenge.nonce.count == 32,
                  challenge.expiresAt.timeIntervalSince1970.isFinite else { throw IPCError.malformedReply }
            return .challenge(challenge)
        case .adminReply:
            let reply = try decoder.decode(Single<AdminReply>.self, from: data).value
            guard isStatusToken(reply.status) else { throw IPCError.malformedReply }
            return .adminReply(reply)
        case .error:
            let code = try decoder.decode(Single<IPCError>.self, from: data).value
            guard IPCError.wireCodes.contains(code) else { throw IPCError.malformedReply }
            return .error(code)
        }
    }

    static func isValid(_ reply: ReadReply) -> Bool {
        guard isStatusToken(reply.status),
              (reply.accounts ?? []).allSatisfy({ isStatusToken($0.status) }) else { return false }
        if let login = reply.login {
            guard (1...39).contains(login.utf8.count),
                  login.utf8.allSatisfy({ isLoginByte($0) }) else { return false }
        }
        if let userID = reply.userID, userID < 0 { return false }
        return true
    }

    static let pendingStatuses: Set<String> = ["waiting", "approved"]

    static func isValid(_ snapshot: AdminSnapshot) -> Bool {
        snapshot.accounts.allSatisfy { isStatusToken($0.status) }
            && snapshot.grants.allSatisfy { (0...callLimits.upperBound).contains($0.callsRemaining) }
            && snapshot.clients.allSatisfy { $0.uid != 0 }
            && snapshot.pending.allSatisfy { pendingStatuses.contains($0.status) }
            && snapshot.audit.allSatisfy { isStatusToken($0.outcome) && $0.timestamp.timeIntervalSince1970.isFinite }
    }

    /// Domain status: lowercase ASCII token, 1...64 bytes.
    static func isStatusToken(_ value: String) -> Bool {
        guard (1...64).contains(value.utf8.count), let first = value.utf8.first,
              (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(first) else { return false }
        return value.utf8.allSatisfy {
            (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
                || $0 == UInt8(ascii: "_")
        }
    }

    private static func isLoginByte(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
            || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte) || byte == UInt8(ascii: "-")
    }

    static func shape(_ kind: ReplyKind) -> Shape {
        let account = Shape.object(required: ["id", "service", "status"])
        switch kind {
        case .readReply:
            return .object(required: ["status"], optional: ["accounts", "requestID", "login", "userID"],
                           nested: ["accounts": .array(account, max: 128)])
        case .snapshot:
            return .object(required: ["accounts", "clients", "grants", "pending", "audit"], nested: [
                "accounts": .array(account, max: 128),
                "clients": .array(.object(required: ["id", "uid", "revoked"]), max: 128),
                "grants": .array(.object(required: ["id", "clientID", "accountID", "expiresAt", "callsRemaining",
                                                    "requiresApproval", "revoked"]), max: 512),
                "pending": .array(.object(required: ["id", "clientID", "accountID", "action", "expiresAt", "status"]),
                                  max: 128),
                "audit": .array(.object(required: ["timestamp", "clientID", "outcome"],
                                        optional: ["accountID", "action"]), max: 1000)
            ])
        case .challenge: return .object(required: ["id", "payload", "expiresAt", "nonce"])
        case .adminReply: return .object(required: ["status"], optional: ["id"])
        case .error: return .scalar
        }
    }
}

struct AnyKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

private struct AnyEncodable: Encodable {
    let value: any Encodable
    init(_ value: any Encodable) { self.value = value }
    func encode(to encoder: any Encoder) throws { try value.encode(to: encoder) }
}
