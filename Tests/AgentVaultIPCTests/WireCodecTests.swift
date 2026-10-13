@testable import AgentVaultIPC
import AgentVaultContracts
import Foundation
import Testing

private let id = "00000000-0000-4000-8000-000000000001"

@Test func readOperationsAcceptExactlyTheirKeys() throws {
    #expect(try WireCodec.decodeRead(json(#"{"operation":"accounts"}"#), limits: .standard).operation == .accounts)
    let run = try WireCodec.decodeRead(json(#"{"operation":"run","accountID":"\#(id)","action":"demo.status"}"#),
                                       limits: .standard)
    #expect(run.action == .demoStatus)
    _ = try WireCodec.decodeRead(json(#"{"operation":"cancel","requestID":"\#(id)"}"#), limits: .standard)
}

@Test(arguments: [
    #"{"operation":"accounts","clientID":"00000000-0000-4000-8000-000000000001"}"#,
    #"{"operation":"accounts","requestID":"00000000-0000-4000-8000-000000000001"}"#,
    #"{"operation":"run","accountID":"00000000-0000-4000-8000-000000000001"}"#,
    #"{"operation":"run","accountID":null,"action":"demo.status"}"#,
    #"{"operation":"run","accountID":"00000000-0000-4000-8000-000000000001","action":"shell.exec"}"#,
    #"{"operation":"resume"}"#,
    #"{"operation":"export"}"#,
    #"{"operation":"accounts","extra":{"nested":true}}"#,
    #"["accounts"]"#,
    #"not json"#
])
func malformedReadRequestsAreRejected(text: String) {
    #expect(throws: IPCError.invalidRequest) { try WireCodec.decodeRead(json(text), limits: .standard) }
}

@Test func oversizedRequestsAreRejectedBeforeParsing() {
    let padded = Data(repeating: 0x20, count: IPCLimits.standard.maxRequestBytes + 1)
    #expect(throws: IPCError.requestTooLarge) { try WireCodec.decodeRead(padded, limits: .standard) }
    #expect(throws: IPCError.requestTooLarge) { try WireCodec.decodeAdmin(padded, limits: .standard) }
}

@Test func adminOperationsUseOperationSpecificKeysAndBounds() throws {
    let credential = Data(repeating: 1, count: 32).base64EncodedString()
    _ = try WireCodec.decodeAdmin(json(#"{"operation":"enroll","service":"demo","credential":"\#(credential)"}"#),
                                  limits: .standard)
    _ = try WireCodec.decodeAdmin(json(#"""
        {"operation":"grant","clientID":"\#(id)","accountID":"\#(id)","duration":3600,"callLimit":20,"requiresApproval":true}
        """#), limits: .standard)
    _ = try WireCodec.decodeAdmin(json(#"{"operation":"prune"}"#), limits: .standard)

    let rejected = [
        #"{"operation":"enroll","service":"demo","credential":"\#(credential)","clientID":"\#(id)"}"#,
        #"{"operation":"enroll","service":"demo","credential":""}"#,
        #"{"operation":"enroll","service":"demo","credential":"\#(Data(count: 8193).base64EncodedString())"}"#,
        #"{"operation":"grant","clientID":"\#(id)","accountID":"\#(id)","duration":86401,"callLimit":20,"requiresApproval":true}"#,
        #"{"operation":"grant","clientID":"\#(id)","accountID":"\#(id)","duration":0,"callLimit":20,"requiresApproval":true}"#,
        #"{"operation":"grant","clientID":"\#(id)","accountID":"\#(id)","duration":60,"callLimit":10001,"requiresApproval":true}"#,
        #"{"operation":"grant","clientID":"\#(id)","accountID":"\#(id)","duration":60,"callLimit":20}"#,
        #"{"operation":"pairClient","uid":0}"#,
        #"{"operation":"pairClient","uid":4294967295}"#,
        #"{"operation":"prune","accountID":"\#(id)"}"#,
        #"{"operation":"revokeGrant","clientID":"\#(id)"}"#,
        #"{"operation":"installAdapter"}"#
    ]
    for text in rejected {
        #expect(throws: IPCError.invalidRequest) { try WireCodec.decodeAdmin(json(text), limits: .standard) }
    }
}

@Test func clientRefusesToEncodeFieldsOutsideTheOperation() {
    var request = AdminRequest(operation: .deleteAccount)
    request.accountID = UUID()
    request.credential = Data("SYNTHETIC".utf8)
    #expect(throws: IPCError.invalidRequest) { try WireCodec.encode(request) }
    #expect(throws: IPCError.invalidRequest) { try WireCodec.encode(ReadRequest(operation: .accounts, requestID: UUID())) }
}

@Test func authorizeRequiresCanonicalIDAndBoundedSignature() throws {
    _ = try WireCodec.decodeAuthorize(id: id, signature: Data(count: 64))
    #expect(throws: IPCError.invalidRequest) { try WireCodec.decodeAuthorize(id: "{\(id)}", signature: Data(count: 64)) }
    #expect(throws: IPCError.invalidRequest) { try WireCodec.decodeAuthorize(id: id, signature: Data(count: 73)) }
    #expect(throws: IPCError.invalidRequest) { try WireCodec.decodeAuthorize(id: id, signature: Data()) }
}

@Test func validRepliesRoundTrip() throws {
    let reply = ReadReply(status: "ok", accounts: [AccountSummary(id: UUID(), service: .github)], login: "octo-cat",
                          userID: 1)
    let data = try #require(WireCodec.reply(reply, kind: .readReply, limits: .standard))
    guard case .success(.readReply(let decoded)) = WireCodec.decodeReply(data, allowed: [.readReply], limits: .standard)
    else { Issue.record("reply rejected"); return }
    #expect(decoded.login == "octo-cat")
    #expect(WireCodec.errorReply(.busy) == json(#"{"error":"busy"}"#))
}

@Test(arguments: [
    #"{"readReply":{"status":"ok"},"error":"busy"}"#,
    #"{"snapshot":{"accounts":[],"clients":[],"grants":[],"pending":[]}}"#,
    #"{"secret":"x"}"#,
    #"{"error":"broker_rejected"}"#,
    #"{"error":"anything"}"#,
    #"{"readReply":{"status":"OK"}}"#,
    #"{"readReply":{"status":"ok","token":"x"}}"#,
    #"{"readReply":{"status":"ok","login":"a b"}}"#,
    #"{"readReply":{"status":"ok","accounts":[{"id":"00000000-0000-4000-8000-000000000001","service":"demo","status":"active","cookie":"x"}]}}"#,
    #"{"readReply":{"status":"ok","userID":-1}}"#,
    #"{"readReply":null}"#,
    #"[]"#
])
func malformedReadRepliesAreRejected(text: String) {
    guard case .failure(let error) = WireCodec.decodeReply(json(text), allowed: [.readReply], limits: .standard) else {
        Issue.record("accepted \(text)"); return
    }
    #expect(error == .malformedReply)
}

@Test func replyCountAndSizeAreBounded() {
    let accounts = (0...128).map { _ in AccountSummary(id: UUID(), service: .demo) }
    #expect(WireCodec.reply(ReadReply(status: "ok", accounts: accounts), kind: .readReply, limits: .standard) == nil)
    var small = IPCLimits.standard
    small.maxReplyBytes = 8
    #expect(WireCodec.reply(ReadReply(status: "ok"), kind: .readReply, limits: small) == nil)
}

func maximalSnapshot(pendingStatus: String = "approved", outcome: String = "response_suppressed") -> AdminSnapshot {
    let far = Date(timeIntervalSince1970: 4_102_444_800.123456)
    return AdminSnapshot(
        accounts: (0..<128).map { _ in AccountSummary(id: UUID(), service: .githubWeb, status: "active") },
        clients: (0..<128).map { _ in ClientSummary(id: UUID(), uid: 4_294_967_293, revoked: false) },
        grants: (0..<512).map { _ in GrantSummary(id: UUID(), clientID: UUID(), accountID: UUID(), expiresAt: far,
                                                 callsRemaining: 10_000, requiresApproval: true, revoked: false) },
        pending: (0..<128).map { _ in PendingSummary(id: UUID(), clientID: UUID(), accountID: UUID(),
                                                    action: .githubWebProfile, expiresAt: far, status: pendingStatus) },
        audit: (0..<1000).map { _ in AuditSummary(timestamp: far, clientID: UUID(), accountID: UUID(),
                                                 action: .githubWebProfile, outcome: outcome) })
}

@Test func maximalSnapshotFitsTheReplyCapAndRoundTrips() throws {
    let data = try #require(WireCodec.reply(maximalSnapshot(), kind: .snapshot, limits: .standard))
    #expect(data.count < IPCLimits.standard.maxReplyBytes)
    guard case .success(.snapshot(let snapshot)) = WireCodec.decodeReply(data, allowed: [.snapshot], limits: .standard)
    else { Issue.record("maximal snapshot rejected"); return }
    #expect(snapshot.audit.count == 1000 && snapshot.pending.allSatisfy { $0.status == "approved" })
}

@Test func snapshotRejectsUnknownPendingStatusAndBadAudit() {
    #expect(WireCodec.reply(maximalSnapshot(pendingStatus: "rejected"), kind: .snapshot, limits: .standard) == nil)
    #expect(WireCodec.reply(maximalSnapshot(outcome: "Token Leak"), kind: .snapshot, limits: .standard) == nil)
    let base = maximalSnapshot()
    let oversizedAudit = AdminSnapshot(accounts: [], clients: [], grants: [], pending: [],
                                       audit: base.audit + base.audit.prefix(1))
    #expect(WireCodec.reply(oversizedAudit, kind: .snapshot, limits: .standard) == nil)
    let tooManyPending = AdminSnapshot(accounts: [], clients: [], grants: [], pending: base.pending + base.pending.prefix(1))
    #expect(WireCodec.reply(tooManyPending, kind: .snapshot, limits: .standard) == nil)
}

@Test(arguments: [
    #"{"snapshot":{"accounts":[],"clients":[],"grants":[],"pending":[]}}"#,
    #"{"snapshot":{"accounts":[],"clients":[],"grants":[],"pending":[],"audit":[{"timestamp":1,"clientID":"00000000-0000-4000-8000-000000000001","outcome":"denied","detail":"x"}]}}"#,
    #"{"snapshot":{"accounts":[],"clients":[],"grants":[],"pending":[{"id":"00000000-0000-4000-8000-000000000001","clientID":"00000000-0000-4000-8000-000000000001","accountID":"00000000-0000-4000-8000-000000000001","action":"demo.status","expiresAt":1}],"audit":[]}}"#
])
func snapshotKeysAreStrict(text: String) {
    guard case .failure(.malformedReply) = WireCodec.decodeReply(json(text), allowed: [.snapshot], limits: .standard)
    else { Issue.record("accepted \(text)"); return }
}

