@testable import AgentVaultAppSupport
import CryptoKit
import Foundation
import Testing

@MainActor
struct ApprovalKeySelfTestTests {
    @Test func localTestVerifiesSignatureAndPromptsAgainForEachAttempt() async throws {
        let auth = CountingAuthenticator()
        let signer = HumanApprovalSigner(backends: [TestKeyBackend()], authenticator: auth)
        let model = AppModel(transport: UnavailableTransport(), signer: signer)
        await model.loadApprovalKey()
        for _ in 0..<2 {
            await model.testApprovalKey()
            #expect(model.approvalKeyTest == .passed)
        }
        #expect(auth.reasons == Array(repeating: "Test Agent Vault approval on this Mac", count: 2))
        #expect(model.snapshot == nil)
    }

    @Test func cancellationIsNotReportedAsSuccess() async throws {
        let auth = CountingAuthenticator()
        auth.failure = .userCancelled
        let signer = HumanApprovalSigner(backends: [TestKeyBackend()], authenticator: auth)
        let model = AppModel(transport: UnavailableTransport(), signer: signer)
        await model.loadApprovalKey()
        await model.testApprovalKey()
        #expect(model.approvalKeyTest == .cancelled)
    }

    @Test func missingAndSoftwareKeysCannotPass() async throws {
        let model = AppModel(transport: UnavailableTransport(), signer: SoftwareFixtureSigner())
        await model.testApprovalKey()
        #expect(model.approvalKeyTest == .failed)
        await model.loadApprovalKey()
        await model.testApprovalKey()
        #expect(model.approvalKeyTest == .failed)
    }

    @Test func signatureFromAnotherKeyIsRefused() async throws {
        let model = AppModel(transport: UnavailableTransport(), signer: WrongKeySigner())
        await model.loadApprovalKey()
        await model.testApprovalKey()
        #expect(model.approvalKeyTest == .failed)
    }

    @Test func overlappingTestsDoNotPromptTwiceOrReloadKey() async throws {
        let signer = PausedTestSigner()
        let model = AppModel(transport: UnavailableTransport(), signer: signer)
        await model.loadApprovalKey()
        let first = Task { await model.testApprovalKey() }
        while await signer.calls == 0 { await Task.yield() }
        await model.loadApprovalKey()
        await model.testApprovalKey()
        #expect(model.approvalKeyTest == .testing)
        #expect(await signer.calls == 1)
        await signer.finish()
        await first.value
        #expect(model.approvalKeyTest == .passed)
    }
}

private struct WrongKeySigner: ApprovalSigning {
    let first = P256.Signing.PrivateKey()
    let second = P256.Signing.PrivateKey()
    func registration() async throws -> ApprovalKeyRegistration {
        .init(publicKeyX963: first.publicKey.x963Representation, protection: .secureEnclave)
    }
    func sign(payload: Data, reason: String) async throws -> Data { try second.signature(for: payload).derRepresentation }
}

private actor PausedTestSigner: ApprovalSigning {
    private let key = P256.Signing.PrivateKey()
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var calls = 0
    func registration() async throws -> ApprovalKeyRegistration {
        .init(publicKeyX963: key.publicKey.x963Representation, protection: .secureEnclave)
    }
    func sign(payload: Data, reason: String) async throws -> Data {
        calls += 1
        await withCheckedContinuation { waiter = $0 }
        return try key.signature(for: payload).derRepresentation
    }
    func finish() { waiter?.resume(); waiter = nil }
}
