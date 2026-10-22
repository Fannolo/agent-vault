import AgentVaultApproval
import AgentVaultContracts
import Foundation
import Testing

@Test func approvalIntentBindsScopeAndRoundTripsWithoutCredentialHash() throws {
    var request = AdminRequest(operation: .grant)
    request.clientID = UUID(); request.accountID = UUID()
    request.duration = 60; request.callLimit = 1; request.requiresApproval = true
    let id = UUID(), nonce = Data(repeating: 0x42, count: 32), expiry = Date().addingTimeInterval(60)
    let payload = try ApprovalIntent.payload(request: request, id: id, nonce: nonce, expiresAt: expiry)
    var edited = request; edited.callLimit = 2
    #expect(try ApprovalIntent.payload(request: edited, id: id, nonce: nonce, expiresAt: expiry) != payload)
    #expect(try ApprovalIntent.payload(request: request, id: UUID(), nonce: nonce, expiresAt: expiry) != payload)
    #expect(try ApprovalIntent.payload(request: request, id: id, nonce: Data(repeating: 0x43, count: 32), expiresAt: expiry) != payload)
    let challenge = AdminChallenge(id: id, payload: payload, expiresAt: expiry, nonce: nonce)
    let received = try JSONDecoder().decode(AdminChallenge.self, from: JSONEncoder().encode(challenge))
    #expect(try ApprovalIntent.payload(request: request, id: received.id, nonce: received.nonce, expiresAt: received.expiresAt) == payload)
    var enroll = AdminRequest(operation: .enroll); enroll.service = .github
    enroll.credential = Data("SYNTHETIC-one".utf8)
    let first = try ApprovalIntent.payload(request: enroll, id: id, nonce: nonce, expiresAt: expiry)
    enroll.credential = Data("SYNTHETIC-two".utf8)
    #expect(try ApprovalIntent.payload(request: enroll, id: id, nonce: nonce, expiresAt: expiry) == first,
            "No credential-content hash is exposed by the challenge; broker freezes original bytes privately")
}
