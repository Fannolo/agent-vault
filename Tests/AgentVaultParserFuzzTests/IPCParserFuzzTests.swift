@testable import AgentVaultIPC
import AgentVaultContracts
import Foundation
import Testing

private struct RequestFixture {
    let admin: Bool
    let fields: [(String, String)]
    var text: String { objectText(fields) }
}

private func requestFixtures() -> [RequestFixture] {
    let id = quoted(ParserCorpus.uuid)
    let credential = quoted(Data(repeating: 0x41, count: 32).base64EncodedString())
    return [
        .init(admin: false, fields: [("operation", quoted("accounts"))]),
        .init(admin: false, fields: [("operation", quoted("run")), ("accountID", id), ("action", quoted("demo.status"))]),
        .init(admin: false, fields: [("operation", quoted("resume")), ("requestID", id)]),
        .init(admin: false, fields: [("operation", quoted("cancel")), ("requestID", id)]),
        .init(admin: true, fields: [("operation", quoted("enroll")), ("service", quoted("demo")), ("credential", credential)]),
        .init(admin: true, fields: [("operation", quoted("rotate")), ("accountID", id), ("credential", credential)]),
        .init(admin: true, fields: [("operation", quoted("deleteAccount")), ("accountID", id)]),
        .init(admin: true, fields: [("operation", quoted("pairClient")), ("uid", "501")]),
        .init(admin: true, fields: [("operation", quoted("grant")), ("clientID", id), ("accountID", id),
                                  ("duration", "3600"), ("callLimit", "20"), ("requiresApproval", "true")]),
        .init(admin: true, fields: [("operation", quoted("revokeGrant")), ("grantID", id)]),
        .init(admin: true, fields: [("operation", quoted("revokeClient")), ("clientID", id)]),
        .init(admin: true, fields: [("operation", quoted("approveInvocation")), ("requestID", id)]),
        .init(admin: true, fields: [("operation", quoted("rejectInvocation")), ("requestID", id)]),
        .init(admin: true, fields: [("operation", quoted("recover"))]),
        .init(admin: true, fields: [("operation", quoted("prune"))])
    ]
}

private func inspectRequest(_ data: Data, admin: Bool, context: FuzzCase) throws -> Bool {
    let canonical: Data
    if admin {
        guard let request = try? WireCodec.decodeAdmin(data, limits: .standard) else { return false }
        try check(request.credential.map { (1...8192).contains($0.count) } ?? true, context, "credential bound")
        try check(request.uid.map { $0 > 0 && $0 < 4_294_967_294 } ?? true, context, "UID bound")
        try check(request.duration.map { $0.isFinite && $0 > 0 && $0 <= 86_400 } ?? true, context, "grant duration bound")
        try check(request.callLimit.map { (1...10_000).contains($0) } ?? true, context, "grant call bound")
        canonical = try WireCodec.encode(request)
    } else {
        guard let request = try? WireCodec.decodeRead(data, limits: .standard) else { return false }
        canonical = try WireCodec.encode(request)
    }
    try check(data.count <= 16_384 && canonical.count <= 16_384, context, "request size bound")
    guard let source = jsonObject(data), let result = jsonObject(canonical) else {
        throw CorpusFailure(description: "accepted request was not a JSON object; " + context.description)
    }
    // UUID letter casing is canonicalized by Codable; identity must still be preserved.
    var normalized = source
    for key in ["accountID", "clientID", "grantID", "requestID"] {
        if let text = source[key] as? String, let uuid = UUID(uuidString: text) { normalized[key] = uuid.uuidString }
    }
    try check(NSDictionary(dictionary: normalized).isEqual(to: result), context, "accepted request lost or changed a semantic field")
    return true
}

@Test func seededIPCRequestsRejectPolicyExpansionAndAmbiguity() throws {
    let seed = ParserCorpus.requestSeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        let fixture = random.choose(requestFixtures())
        let good = Data(fixture.text.utf8)
        let control = FuzzCase(seed: seed, index: index, mutation: "known-good", data: good)
        try check(try inspectRequest(good, admin: fixture.admin, context: control), control, "valid control rejected")
        var fields = fixture.fields
        let selected = random.int(fields.count)
        let text: String
        let mutation: String
        switch random.int(10) {
        case 0, 1:
            mutation = "duplicate-escaped-field"
            text = duplicateField(in: fixture.text, key: fields[selected].0, value: fields[selected].1, escaped: true)
        case 2:
            mutation = "duplicate-literal-field"
            text = duplicateField(in: fixture.text, key: fields[selected].0, value: fields[selected].1, escaped: false)
        case 3:
            mutation = "missing-required-field"
            fields.remove(at: selected); text = objectText(fields)
        case 4:
            mutation = "null-field"
            fields[selected].1 = "null"; text = objectText(fields)
        case 5:
            mutation = "nested-field"
            fields[selected].1 = "{\"synthetic\":[true]}"; text = objectText(fields)
        case 6:
            mutation = "caller-controlled-policy-field"
            fields.append((random.choose(["destination", "script", "clientIdentity", "url", "secret", "headers"]), quoted("synthetic")))
            text = objectText(fields)
        case 7:
            mutation = "unknown-operation"
            fields[0].1 = quoted("shell.exec"); text = objectText(fields)
        case 8:
            mutation = "unicode-confusable-key"
            fields.append(("operatiоn", fields[0].1)); text = objectText(fields)
        default:
            mutation = "batch-root"
            text = "[" + fixture.text + "]"
        }
        let data = Data(text.utf8)
        let context = FuzzCase(seed: seed, index: index, mutation: mutation, data: data)
        try check(!(try inspectRequest(data, admin: fixture.admin, context: context)), context, "malformed or policy-expanded request accepted")
    }
}

@Test func seededIPCRequestByteMutationsStayTypedAndBoundedWhenAccepted() throws {
    let seed = ParserCorpus.requestBytesSeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        let fixture = random.choose(requestFixtures())
        let (mutation, data) = random.mutateBytes(Data(fixture.text.utf8))
        _ = try inspectRequest(data, admin: fixture.admin,
                               context: FuzzCase(seed: seed, index: index, mutation: mutation, data: data))
    }
}

private struct ReplyFixture {
    let kind: WireCodec.ReplyKind
    let value: String
    var text: String { objectText([(kind.rawValue, value)]) }
}

private func replyFixtures(login: String, count: Int) -> [ReplyFixture] {
    let id = quoted(ParserCorpus.uuid)
    let account = "{\"id\":\(id),\"service\":\"demo\",\"status\":\"active\"}"
    func array(_ value: String) -> String { "[" + Array(repeating: value, count: count).joined(separator: ",") + "]" }
    let client = "{\"id\":\(id),\"uid\":501,\"revoked\":false}"
    let grant = "{\"id\":\(id),\"clientID\":\(id),\"accountID\":\(id),\"expiresAt\":1234,\"callsRemaining\":20,\"requiresApproval\":true,\"revoked\":false}"
    let pending = "{\"id\":\(id),\"clientID\":\(id),\"accountID\":\(id),\"action\":\"demo.status\",\"expiresAt\":1234,\"status\":\"approved\"}"
    let audit = "{\"timestamp\":1234,\"clientID\":\(id),\"accountID\":\(id),\"action\":\"demo.status\",\"outcome\":\"denied\"}"
    return [
        .init(kind: .readReply, value: "{\"status\":\"ok\",\"login\":\(quoted(login)),\"userID\":42,\"accounts\":\(array(account))}"),
        .init(kind: .snapshot, value: "{\"accounts\":\(array(account)),\"clients\":\(array(client)),\"grants\":\(array(grant)),\"pending\":\(array(pending)),\"audit\":\(array(audit))}"),
        .init(kind: .challenge, value: "{\"id\":\(id),\"payload\":\(quoted(Data(repeating: 0x41, count: 16).base64EncodedString())),\"expiresAt\":1234,\"nonce\":\(quoted(Data(count: 32).base64EncodedString()))}"),
        .init(kind: .adminReply, value: "{\"status\":\"granted\",\"id\":\(id)}"),
        .init(kind: .error, value: quoted("busy"))
    ]
}

private func inspectReply(_ data: Data, kind: WireCodec.ReplyKind, context: FuzzCase) throws -> Bool {
    guard case .success(let value) = WireCodec.decodeReply(data, allowed: [kind], limits: .standard) else { return false }
    try check(data.count <= 524_288, context, "reply size bound")
    switch value {
    case .readReply(let reply):
        try check(statusIsBounded(reply.status), context, "read status bound")
        try check((reply.accounts?.count ?? 0) <= 128, context, "account count bound")
        try check((reply.accounts ?? []).allSatisfy { statusIsBounded($0.status) }, context, "account status bound")
        try check(reply.login.map { profileLoginIsBounded($0, firstMustBeAlphanumeric: false) } ?? true, context, "read login bound")
        try check(reply.userID.map { $0 >= 0 } ?? true, context, "read user ID bound")
    case .snapshot(let snapshot):
        try check(snapshot.accounts.count <= 128 && snapshot.clients.count <= 128 && snapshot.grants.count <= 512
                  && snapshot.pending.count <= 128 && snapshot.audit.count <= 1000, context, "snapshot collection bound")
        try check(snapshot.accounts.allSatisfy { statusIsBounded($0.status) }
                  && snapshot.clients.allSatisfy { $0.uid > 0 }
                  && snapshot.grants.allSatisfy { (0...10_000).contains($0.callsRemaining) }
                  && snapshot.pending.allSatisfy { ["waiting", "approved"].contains($0.status) }
                  && snapshot.audit.allSatisfy { statusIsBounded($0.outcome) && $0.timestamp.timeIntervalSince1970.isFinite },
                  context, "snapshot value bound")
    case .challenge(let challenge):
        try check((16...1024).contains(challenge.payload.count) && challenge.nonce.count == 32
                  && challenge.expiresAt.timeIntervalSince1970.isFinite, context, "challenge bound")
    case .adminReply(let reply):
        try check(statusIsBounded(reply.status), context, "admin status bound")
    case .error(let code):
        try check(["invalid_request", "request_too_large", "busy", "unavailable"].contains(code.rawValue), context, "closed wire error")
    }
    return true
}

@Test func seededIPCRepliesRejectExpandedEnvelopesAndBoundAcceptedMutations() throws {
    let seed = ParserCorpus.replySeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        let login = random.login()
        let count = random.int(5)
        let fixture = random.choose(replyFixtures(login: login, count: count))
        let control = FuzzCase(seed: seed, index: index, mutation: "known-good", data: Data(fixture.text.utf8))
        try check(try inspectReply(control.data, kind: fixture.kind, context: control), control, "valid reply control rejected")
        if index.isMultiple(of: 2) {
            let text: String
            let mutation: String
            switch random.int(5) {
            case 0:
                mutation = "duplicate-escaped-envelope"
                text = duplicateField(in: fixture.text, key: fixture.kind.rawValue, value: fixture.value, escaped: true)
            case 1:
                mutation = "extra-envelope-field"
                text = duplicateField(in: fixture.text, key: "credential", value: quoted("synthetic"), escaped: false)
            case 2:
                mutation = "duplicate-nested-field"
                let key = switch fixture.kind {
                case .readReply, .adminReply: "status"
                case .snapshot: "accounts"
                case .challenge: "nonce"
                case .error: "error"
                }
                if fixture.kind == .error {
                    text = duplicateField(in: fixture.text, key: key, value: fixture.value, escaped: true)
                } else {
                    let object = jsonObject(Data(fixture.value.utf8))!
                    let value = String(decoding: try JSONSerialization.data(withJSONObject: object[key]!, options: [.fragmentsAllowed, .sortedKeys]), as: UTF8.self)
                    text = objectText([(fixture.kind.rawValue, duplicateField(in: fixture.value, key: key, value: value, escaped: true))])
                }
            case 3:
                mutation = "extra-nested-field"
                text = fixture.kind == .error ? objectText([(fixture.kind.rawValue, "null")])
                    : objectText([(fixture.kind.rawValue, duplicateField(in: fixture.value, key: "cookie", value: quoted("synthetic"), escaped: false))])
            default:
                mutation = "null-envelope-value"
                text = objectText([(fixture.kind.rawValue, "null")])
            }
            let context = FuzzCase(seed: seed, index: index, mutation: mutation, data: Data(text.utf8))
            try check(!(try inspectReply(context.data, kind: fixture.kind, context: context)), context, "ambiguous or expanded reply accepted")
        } else {
            let (mutation, data) = random.mutateBytes(control.data)
            _ = try inspectReply(data, kind: fixture.kind, context: FuzzCase(seed: seed, index: index, mutation: mutation, data: data))
        }
    }
}

@Test func ipcAndAdapterLimitsHaveAcceptedBoundaryControls() throws {
    let seed = ParserCorpus.requestSeed
    var index = 0
    func request(_ text: String, admin: Bool, accepted: Bool) throws {
        let context = FuzzCase(seed: seed, index: index, mutation: "explicit-boundary", data: Data(text.utf8)); index += 1
        try check(try inspectRequest(context.data, admin: admin, context: context) == accepted, context, "request boundary outcome")
    }
    let base = #"{"operation":"accounts"}"#
    try request(base + String(repeating: " ", count: 16_384 - base.utf8.count), admin: false, accepted: true)
    try request(base + String(repeating: " ", count: 16_385 - base.utf8.count), admin: false, accepted: false)
    for count in [0, 1, 8192, 8193] {
        try request(objectText([("operation", quoted("enroll")), ("service", quoted("demo")),
                                ("credential", quoted(Data(repeating: 0x41, count: count).base64EncodedString()))]),
                    admin: true, accepted: count == 1 || count == 8192)
    }
    for uid in ["0", "1", "4294967293", "4294967294", "4294967295", "-1", "1.5"] {
        try request("{\"operation\":\"pairClient\",\"uid\":\(uid)}", admin: true, accepted: uid == "1" || uid == "4294967293")
    }
    for (duration, callLimit, accepted) in [("1", "1", true), ("86400", "10000", true),
                                             ("0", "1", false), ("86400.0001", "1", false),
                                             ("1", "0", false), ("1", "10001", false), ("1e999", "1", false)] {
        try request("{\"operation\":\"grant\",\"clientID\":\(quoted(ParserCorpus.uuid)),\"accountID\":\(quoted(ParserCorpus.uuid)),\"duration\":\(duration),\"callLimit\":\(callLimit),\"requiresApproval\":false}",
                    admin: true, accepted: accepted)
    }
    for count in [7, 8, 72, 73] {
        let accepted = (try? WireCodec.decodeAuthorize(id: ParserCorpus.uuid, signature: Data(count: count))) != nil
        let context = FuzzCase(seed: seed, index: index, mutation: "signature-byte-bound", data: Data(count: count)); index += 1
        try check(accepted == (count == 8 || count == 72), context, "signature boundary outcome")
    }
    let replyBase = #"{"readReply":{"status":"ok"}}"#
    for size in [524_288, 524_289] {
        let context = FuzzCase(seed: seed, index: index, mutation: "reply-byte-bound", data: Data((replyBase + String(repeating: " ", count: size - replyBase.utf8.count)).utf8)); index += 1
        try check(try inspectReply(context.data, kind: .readReply, context: context) == (size == 524_288), context, "reply boundary outcome")
    }
    for count in [128, 129] {
        let account = "{\"id\":\(quoted(ParserCorpus.uuid)),\"service\":\"demo\",\"status\":\"active\"}"
        let text = "{\"readReply\":{\"status\":\"ok\",\"accounts\":[\(Array(repeating: account, count: count).joined(separator: ","))]}}"
        let context = FuzzCase(seed: seed, index: index, mutation: "account-count-bound", data: Data(text.utf8)); index += 1
        try check(try inspectReply(context.data, kind: .readReply, context: context) == (count == 128), context, "account boundary outcome")
    }
    let id = quoted(ParserCorpus.uuid)
    let collections: [(String, Int, String)] = [
        ("accounts", 128, "{\"id\":\(id),\"service\":\"demo\",\"status\":\"active\"}"),
        ("clients", 128, "{\"id\":\(id),\"uid\":501,\"revoked\":false}"),
        ("grants", 512, "{\"id\":\(id),\"clientID\":\(id),\"accountID\":\(id),\"expiresAt\":1234,\"callsRemaining\":0,\"requiresApproval\":true,\"revoked\":false}"),
        ("pending", 128, "{\"id\":\(id),\"clientID\":\(id),\"accountID\":\(id),\"action\":\"demo.status\",\"expiresAt\":1234,\"status\":\"waiting\"}"),
        ("audit", 1000, "{\"timestamp\":1234,\"clientID\":\(id),\"outcome\":\"denied\"}")
    ]
    for (name, maximum, element) in collections {
        for count in [maximum, maximum + 1] {
            let fields = collections.map { collection in
                (collection.0, collection.0 == name ? "[" + Array(repeating: element, count: count).joined(separator: ",") + "]" : "[]")
            }
            let context = FuzzCase(seed: seed, index: index, mutation: "\(name)-count-bound", data: Data(objectText([("snapshot", objectText(fields))]).utf8)); index += 1
            try check(try inspectReply(context.data, kind: .snapshot, context: context) == (count == maximum), context, "snapshot collection boundary outcome")
        }
    }
    for (payload, nonce, accepted) in [(15, 32, false), (16, 32, true), (1024, 32, true), (1025, 32, false),
                                      (16, 31, false), (16, 33, false)] {
        let text = objectText([("challenge", objectText([("id", id), ("payload", quoted(Data(count: payload).base64EncodedString())),
                                                           ("nonce", quoted(Data(count: nonce).base64EncodedString())), ("expiresAt", "1234")]))])
        let context = FuzzCase(seed: seed, index: index, mutation: "challenge-payload-or-nonce-bound", data: Data(text.utf8)); index += 1
        try check(try inspectReply(context.data, kind: .challenge, context: context) == accepted, context, "challenge boundary outcome")
    }
}
