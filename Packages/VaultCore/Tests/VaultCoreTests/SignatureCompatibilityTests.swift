import Crypto
import Foundation
import Testing
@testable import VaultCore

struct WycheproofEd25519Case {
    let tcID: Int
    let group: Int
    let publicKey: Data
    let message: Data
    let signature: Data
    let valid: Bool
    let flags: [String]
}

struct WycheproofEd25519CaseResult: Encodable {
    let tcId: Int
    let expected: String
    let constructed: Bool
    let verified: Bool
}

struct WycheproofEd25519Report: Encodable {
    var schema = "agent-vault-wycheproof-ed25519-v1"
    let platform: String
    let sourceSHA256: String
    let tableSHA256: String
    let cases: [WycheproofEd25519CaseResult]
}

func wycheproofEd25519Cases() throws -> [WycheproofEd25519Case] {
    try WycheproofEd25519Corpus.table.split(separator: "\n", omittingEmptySubsequences: false).map { line in
        let fields = line.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        try #require(fields.count == 7)
        let tcID = try #require(Int(fields[0]))
        let group = try #require(Int(fields[1]))
        try #require(fields[5] == "valid" || fields[5] == "invalid")
        let decoded = fields[2...4].map { MembershipExchangeOracle.hex($0) }
        try #require(zip(decoded, fields[2...4]).allSatisfy { $0.count * 2 == $1.count })
        return WycheproofEd25519Case(tcID: tcID, group: group, publicKey: decoded[0], message: decoded[1],
                                     signature: decoded[2], valid: fields[5] == "valid",
                                     flags: fields[6].split(separator: ",").map(String.init))
    }
}

@Test func wycheproofEd25519TableProvenanceAndCoverage() throws {
    let table = Data(WycheproofEd25519Corpus.table.utf8)
    #expect(MembershipExchangeTrace.hex(Data(SHA256.hash(data: table))) == WycheproofEd25519Corpus.tableSHA256)
    #expect(WycheproofEd25519Corpus.sourceSHA256 == "496a1ecd43c48c74355ee170a498064e4b1c89162b84c0322352450f1fce34e9")
    #expect(WycheproofEd25519Corpus.revision == "c2cbadd7263439d8015189668f96ff5b5be565ce")
    let cases = try wycheproofEd25519Cases()
    #expect(cases.map(\.tcID) == Array(1...150))
    #expect(cases.filter(\.valid).count == 88)
    #expect(cases.filter { !$0.valid }.count == 62)
    #expect(Set(cases.map(\.group)) == Set(0..<77))
    #expect(cases.filter { $0.flags.contains("SignatureMalleability") }.count == 8)
    let keysByGroup = Dictionary(grouping: cases, by: \.group).mapValues { Set($0.map(\.publicKey)) }
    #expect(keysByGroup.values.allSatisfy { $0.count == 1 && $0.first?.count == 32 })
}

/// Blocking gate: the same `isValidSignature` call the membership policy uses, per exact case.
/// The per-case line is public corpus outcome data only.
@Test func wycheproofEd25519ExpectedOutcomes() throws {
    var results: [WycheproofEd25519CaseResult] = []
    for item in try wycheproofEd25519Cases() {
        let key = try? Curve25519.Signing.PublicKey(rawRepresentation: item.publicKey)
        let verified = key?.isValidSignature(item.signature, for: item.message) ?? false
        results.append(WycheproofEd25519CaseResult(tcId: item.tcID, expected: item.valid ? "valid" : "invalid",
                                                    constructed: key != nil, verified: verified))
        if key == nil || verified != item.valid {
            Issue.record("Wycheproof case \(item.tcID) outcome differs from its expected result")
        }
    }
    #expect(results.count == 150)
    let report = WycheproofEd25519Report(platform: MembershipExchangeTrace.platform,
                                         sourceSHA256: WycheproofEd25519Corpus.sourceSHA256,
                                         tableSHA256: WycheproofEd25519Corpus.tableSHA256, cases: results)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let line = "AV_SIGNATURE_CORPUS_V1 " + String(decoding: try encoder.encode(report), as: UTF8.self) + "\n"
    #expect(line.utf8.count <= 64 * 1024)
    MembershipExchangeTrace.emit(line)
}
