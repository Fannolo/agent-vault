import AgentVaultCore
import Foundation
import Testing

private func inspectProfile(_ data: Data, context: FuzzCase) throws -> Bool {
    guard let profile = try? GitHubAdapter.decodeProfile(data) else { return false }
    try check(data.count <= 65_536, context, "upstream body size bound")
    try check(profile.id > 0 && profileLoginIsBounded(profile.login, firstMustBeAlphanumeric: true),
              context, "accepted upstream profile exceeded its public value contract")
    let publicData = try JSONEncoder().encode(profile)
    try check(Set(jsonObject(publicData)?.keys ?? Dictionary<String, Any>().keys) == ["login", "id"],
              context, "upstream fields escaped the typed profile projection")
    try check(publicData.count <= 100, context, "typed profile output bound")
    return true
}

@Test func seededGitHubProfilesAcceptOnlyBoundedTypedOutput() throws {
    let seed = ParserCorpus.githubSeed
    var random = SeededGenerator(seed: seed)
    for index in 0..<ParserCorpus.iterations {
        let login = random.login()
        let id = String(1 + random.next() % 1_000_000)
        // Unknown upstream fields are deliberately legal; they must be discarded.
        let source = objectText([("login", quoted(login)), ("id", id),
                                 ("token", quoted("synthetic-only")), ("email", quoted("private@example.invalid")),
                                 ("unknown", random.tree().text)])
        let control = FuzzCase(seed: seed, index: index, mutation: "known-good-with-extra-fields", data: Data(source.utf8))
        try check(try inspectProfile(control.data, context: control), control, "valid profile control rejected")
        if index.isMultiple(of: 2) {
            let badLogin = random.choose([login + "\n", login + "\r", login + "\u{0000}", "-" + login,
                                          "", String(repeating: "a", count: 40), "é", "🪴", "a b", "<script>"])
            let data = Data(objectText([("login", quoted(badLogin)), ("id", id)]).utf8)
            let context = FuzzCase(seed: seed, index: index, mutation: "invalid-login", data: data)
            try check(!(try inspectProfile(data, context: context)), context, "invalid profile login accepted")
        } else {
            let (mutation, data) = random.mutateBytes(control.data)
            _ = try inspectProfile(data, context: FuzzCase(seed: seed, index: index, mutation: mutation, data: data))
        }
    }
}

@Test func githubProfileLimitsAndScalarTypesHaveAcceptedControls() throws {
    let seed = ParserCorpus.githubSeed
    let cases: [(String, Bool)] = [
        (#"{"login":"a","id":1}"#, true),
        (#"{"\u006cogin":"a","id":1}"#, true),
        (#"{"login":"a","\u0069d":1}"#, true),
        (objectText([("login", quoted(String(repeating: "a", count: 39))), ("id", String(Int.max))]), true),
        (#"{"login":"a","id":0}"#, false),
        (#"{"login":"a","id":-1}"#, false),
        (#"{"login":"a","id":true}"#, false),
        (#"{"login":"a","id":"1"}"#, false),
        (#"{"login":"a","id":null}"#, false),
        (#"{"login":null,"id":1}"#, false),
        (#"{"login":42,"id":1}"#, false),
        (#"{"login":[],"id":1}"#, false),
        (#"[{"login":"a","id":1}]"#, false),
        (#"{"login":"a"}"#, false),
        (#"{"login":"a","id":9223372036854775808}"#, false),
        (#"{"login":"a","login":"<script>","id":1}"#, false),
        (#"{"login":"a","\u006cogin":"<script>","id":1}"#, false),
        (#"{"login":"a","id":1,"id":-1}"#, false),
        (#"{"login":"a","id":1,"\u0069d":-1}"#, false),
        (#"{"login":"a","id":1,"unknown":{"a":1,"\u0061":2}}"#, false),
        (#"{"login":"a","\u006cogin":"a","id":1}"#, false)
    ]
    for (index, item) in cases.enumerated() {
        let context = FuzzCase(seed: seed, index: index, mutation: "scalar-type-control", data: Data(item.0.utf8))
        try check(try inspectProfile(context.data, context: context) == item.1, context, "profile scalar boundary outcome")
    }
    let base = #"{"login":"a","id":1}"#
    for size in [65_536, 65_537] {
        let context = FuzzCase(seed: seed, index: size, mutation: "body-byte-bound", data: Data((base + String(repeating: " ", count: size - base.utf8.count)).utf8))
        try check(try inspectProfile(context.data, context: context) == (size == 65_536), context, "profile body boundary outcome")
    }
}
