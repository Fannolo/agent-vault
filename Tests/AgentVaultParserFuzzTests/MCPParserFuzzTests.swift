@testable import AgentVaultMCPTransport
import Foundation
import Testing

private func acceptsMCPJSON(_ data: Data) -> Bool {
    (try? JSONMessageValidator.validate(data)) != nil
}

@Test func seededMCPGeneratedJSONAndByteMutationsAgreeWithFoundationShape() throws {
    let seed = ParserCorpus.mcpBytesSeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        let tree = random.tree()
        let text = " \t" + CorpusJSON.object([("payload", tree), ("id", .literal(String(index)))]).text + "\r\n"
        let data = Data(text.utf8)
        let context = FuzzCase(seed: seed, index: index, mutation: "known-good-generated-object", data: data)
        try check(jsonObject(data) != nil, context, "test generator did not produce a JSON object")
        try check(acceptsMCPJSON(data), context, "valid bounded JSON object rejected")
        let (mutation, mutated) = random.mutateBytes(data)
        if acceptsMCPJSON(mutated) {
            let context = FuzzCase(seed: seed, index: index, mutation: mutation, data: mutated)
            try check(jsonObject(mutated) != nil, context, "validator accepted invalid JSON or a non-object root")
        }
    }
}

@Test func seededMCPRejectsAmbiguousKeysAndExcessDepth() throws {
    let seed = ParserCorpus.mcpStructureSeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        let key = random.choose(["method", "params", "payload", "message"])
        let depth = 1 + random.int(8)
        let value = random.tree().text
        let object = objectText([(key, value)])
        let valid = String(repeating: "{\"nested\":", count: depth - 1) + object + String(repeating: "}", count: depth - 1)
        let control = FuzzCase(seed: seed, index: index, mutation: "known-good-nested-object", data: Data(valid.utf8))
        try check(acceptsMCPJSON(control.data), control, "valid nested control rejected")
        let data: Data
        let mutation: String
        if index.isMultiple(of: 2) {
            mutation = "duplicate-decoded-key-at-depth-\(depth)"
            let duplicate = duplicateField(in: object, key: key, value: "null", escaped: index.isMultiple(of: 4))
            data = Data((String(repeating: "{\"nested\":", count: depth - 1) + duplicate + String(repeating: "}", count: depth - 1)).utf8)
        } else {
            let arrays = 64 + random.int(9)
            mutation = "over-depth-\(arrays + 1)"
            data = Data(("{\"payload\":" + String(repeating: "[", count: arrays) + "0" + String(repeating: "]", count: arrays) + "}").utf8)
        }
        let context = FuzzCase(seed: seed, index: index, mutation: mutation, data: data)
        try check(!acceptsMCPJSON(data), context, "ambiguous or excessively nested JSON accepted")
    }
}

@Test func mcpGrammarUnicodeAndDepthControlsAreExplicit() throws {
    let seed = ParserCorpus.mcpStructureSeed
    let valid = [
        #"{}"#,
        #"{"id":0,"value":[-0,1.5,1e2,-1E-2,true,false,null]}"#,
        #"{"id":"synthetic","text":"\uD83E\uDEB4","escaped":"\"\\\/\b\f\n\r\t"}"#,
        #"{"raw":"é🪴مرحبا","key\u002dname":"value"}"#,
        "{\"x\":" + String(repeating: "[", count: 63) + "0" + String(repeating: "]", count: 63) + "}"
    ]
    let invalid = [
        #"[]"#, #"null"#, #"1"#, #"{"x":1}{}"#, #"{"x":01}"#, #"{"x":+1}"#,
        #"{"x":1.}"#, #"{"x":.1}"#, #"{"x":1e}"#, #"{"x":NaN}"#,
        #"{"x":true,}"#, #"{"x":[1,]}"#, #"{"x":"\x41"}"#, #"{"x":"\uD800"}"#,
        #"{"x":"\uDEAD"}"#, #"{"id":1.0}"#, #"{"id":1e0}"#, #"{"id":-1.2}"#,
        #"{"id":1,"\u0069d":2}"#, #"{"x":{"a":1,"\u0061":2}}"#,
        "{\"x\":" + String(repeating: "[", count: 64) + "0" + String(repeating: "]", count: 64) + "}"
    ]
    for (index, text) in valid.enumerated() {
        let context = FuzzCase(seed: seed, index: index, mutation: "explicit-valid-grammar", data: Data(text.utf8))
        try check(acceptsMCPJSON(context.data) && jsonObject(context.data) != nil, context, "valid grammar control rejected")
    }
    for (index, text) in invalid.enumerated() {
        let context = FuzzCase(seed: seed, index: index, mutation: "explicit-invalid-grammar", data: Data(text.utf8))
        try check(!acceptsMCPJSON(context.data), context, "invalid grammar, ambiguity, or numeric request ID accepted")
    }
    for bytes: [UInt8] in [[0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0xFF, 0x22, 0x7D],
                           [0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0x00, 0x22, 0x7D]] {
        let context = FuzzCase(seed: seed, index: 0, mutation: "invalid-UTF8-or-control-byte", data: Data(bytes))
        try check(!acceptsMCPJSON(context.data), context, "invalid string bytes accepted")
    }
}
