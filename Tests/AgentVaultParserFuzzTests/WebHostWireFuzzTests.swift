import AgentVaultContracts
import AgentVaultWebHostProtocol
import Foundation
import Testing

// The broker <-> web host wire: every accepted value is typed, bounded and re-encodes to the
// same semantic object; every structural mutation and caller-supplied policy field is refused.

private func commandFixtures() -> [[(String, String)]] {
    let run = quoted(ParserCorpus.uuid)
    let credential = quoted(Data("synthetic-user\nSYNTHETIC-only".utf8).base64EncodedString())
    let base: [(String, String)] = [("request", "7"), ("run", run)]
    let events = #"[{"type":"pointer","phase":"down","x":10,"y":20},{"type":"key","key":"enter"},{"type":"text","text":"123456"}]"#
    func command(_ op: String, _ extra: [(String, String)] = []) -> [(String, String)] {
        [("op", quoted(op))] + base + extra
    }
    let start: [(String, String)] = [("workflow", quoted("githubWebProfile")), ("credential", credential), ("lifetime", "600")]
    let input: [(String, String)] = [("step", "2"), ("frame", "3"), ("events", events)]
    return [command("start", start), command("classify"), command("end"), command("showHuman", [("step", "2")]),
            command("frame", [("step", "2"), ("after", "0")]), command("input", input)]
}

private func inspectCommand(_ data: Data, context: FuzzCase) throws -> Bool {
    guard let request = try? HostWire.decodeRequest(data) else { return false }
    try check(data.count <= HostWire.maximumCommandBytes, context, "command size bound")
    switch request.command {
    case .start(_, _, let credential, let lifetime):
        try check((1...HostCommand.maximumLifetime).contains(lifetime), context, "lifetime bound")
        try check(WebLoginCredential(credential.bytes) == credential, context, "credential grammar")
    case .input(_, let step, let frame, let batch):
        try check(step >= 1 && frame >= 1 && (1...32).contains(batch.events.count), context, "input bounds")
        try check(batch.events.allSatisfy { $0.fits() }, context, "event bounds")
    case .classify, .end, .showHuman, .frame: break
    }
    let canonical = try HostWire.encode(request)
    guard let source = jsonObject(data), let result = jsonObject(canonical) else {
        throw CorpusFailure(description: "accepted command was not a JSON object; " + context.description)
    }
    var normalized = source
    if let text = source["run"] as? String, let uuid = UUID(uuidString: text) { normalized["run"] = uuid.uuidString }
    try check(NSDictionary(dictionary: normalized).isEqual(to: result), context, "accepted command changed a semantic field")
    return true
}

@Test func seededHostCommandsRejectPolicyExpansionAndAmbiguity() throws {
    let seed = ParserCorpus.hostCommandSeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        var fields = random.choose(commandFixtures())
        let good = Data(objectText(fields).utf8)
        let control = FuzzCase(seed: seed, index: index, mutation: "known-good", data: good)
        try check(try inspectCommand(good, context: control), control, "valid control rejected")
        let selected = random.int(fields.count)
        let text: String, mutation: String
        switch random.int(9) {
        case 0:
            mutation = "duplicate-escaped-field"
            text = duplicateField(in: objectText(fields), key: fields[selected].0, value: fields[selected].1, escaped: true)
        case 1:
            mutation = "missing-required-field"
            fields.remove(at: selected); text = objectText(fields)
        case 2:
            mutation = "null-field"
            fields[selected].1 = "null"; text = objectText(fields)
        case 3:
            mutation = "nested-field"
            fields[selected].1 = "{\"synthetic\":[true]}"; text = objectText(fields)
        case 4:
            mutation = "caller-controlled-policy-field"
            fields.append((random.choose(["url", "script", "expression", "method", "origin", "selector", "cdp", "cookie"]),
                           quoted("synthetic")))
            text = objectText(fields)
        case 5:
            mutation = "unknown-operation"
            fields[0].1 = quoted(random.choose(["evaluate", "navigate", "Runtime.evaluate", "getCookies", "screenshot"]))
            text = objectText(fields)
        case 6:
            mutation = "fractional-or-negative-counter"
            fields[1].1 = random.choose(["7.0", "7e0", "-7", "0", "9007199254740993", "true", "\"7\""]); text = objectText(fields)
        case 7:
            mutation = "unicode-confusable-key"
            fields.append(("оp", fields[0].1)); text = objectText(fields)
        default:
            mutation = "batch-root"
            text = "[" + objectText(fields) + "]"
        }
        let data = Data(text.utf8)
        let context = FuzzCase(seed: seed, index: index, mutation: mutation, data: data)
        try check(!(try inspectCommand(data, context: context)), context, "malformed or policy-expanded command accepted")
    }
}

@Test func seededHostCommandByteMutationsStayTypedAndBoundedWhenAccepted() throws {
    let seed = ParserCorpus.hostBytesSeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        let (mutation, data) = random.mutateBytes(Data(objectText(random.choose(commandFixtures())).utf8))
        _ = try inspectCommand(data, context: FuzzCase(seed: seed, index: index, mutation: mutation, data: data))
    }
}

@Test func seededHostReplyMutationsNeverYieldUntypedOutput() throws {
    let seed = ParserCorpus.hostReplySeed
    var random = SeededGenerator(seed: seed)
    let run = quoted(ParserCorpus.uuid)
    let jpeg = quoted(Data([0xFF, 0xD8, 0x00, 0xFF, 0xD9]).base64EncodedString())
    let fixtures = [
        #"{"reply":"profile","request":1,"run":\#(run),"login":\#(quoted(random.login())),"userID":42}"#,
        #"{"reply":"humanStep","request":1,"run":\#(run),"kind":"mfa"}"#,
        #"{"reply":"failed","request":1,"run":\#(run),"failure":"origin_mismatch"}"#,
        #"{"reply":"frame","request":1,"run":\#(run),"step":1,"sequence":2,"width":3,"height":4,"jpeg":\#(jpeg)}"#,
        #"{"reply":"rejected","request":1,"run":\#(run),"rejection":"stale_step"}"#,
        #"{"error":"busy"}"#
    ]
    for index in 0..<ParserCorpus.iterations {
        let (mutation, data) = random.mutateBytes(Data(random.choose(fixtures).utf8))
        let context = FuzzCase(seed: seed, index: index, mutation: mutation, data: data)
        guard case .response(let response)? = try? HostWire.decodeReply(data) else { continue }
        switch response.reply {
        case .profile(let profile):
            try check(profileLoginIsBounded(profile.login, firstMustBeAlphanumeric: true) && profile.userID > 0, context, "profile bound")
        case .frame(_, let frame):
            try check(frame.jpeg.count <= HumanFrame.maximumJPEGBytes && frame.width <= 1280 && frame.height <= 900, context, "frame bound")
        default: break
        }
        try check(try HostWire.decodeReply(try HostWire.encode(response)) == .response(response), context, "reply round trip")
    }
}
