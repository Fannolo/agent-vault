@testable import AgentVaultAppSupport
import CryptoKit
import Foundation
import Security
import Testing

/// Non-persistent, unprotected key used only to exercise the signing flow in tests.
struct TestKeyBackend: ApprovalKeyBackend, @unchecked Sendable {
    let protection = ApprovalKeyProtection.secureEnclave
    let key: SecKey

    init() {
        var error: Unmanaged<CFError>?
        key = SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)!
    }
    func lookup(proof: PresenceProof?) -> ApprovalKeyLookup { .found(key) }
    func createKey() throws -> SecKey { key }
}

/// Scripted backend: a fixed lookup answer and a creation counter.
final class ScriptedBackend: ApprovalKeyBackend, @unchecked Sendable {
    let protection: ApprovalKeyProtection
    private let lock = NSLock()
    private var answer: ApprovalKeyLookup
    private var created: SecKey?
    private var _creations = 0
    var creations: Int { lock.withLock { _creations } }
    let creationFailure: ApprovalSigningError?

    init(protection: ApprovalKeyProtection = .keychainUserPresence, answer: ApprovalKeyLookup, creationFailure: ApprovalSigningError? = nil) {
        self.protection = protection; self.answer = answer; self.creationFailure = creationFailure
    }

    func lookup(proof: PresenceProof?) -> ApprovalKeyLookup { lock.withLock { created.map { .found($0) } ?? answer } }

    func createKey() throws -> SecKey {
        try lock.withLock {
            _creations += 1
            if let creationFailure { throw creationFailure }
            var error: Unmanaged<CFError>?
            let key = SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)!
            created = key
            return key
        }
    }
}

func EmptyBackend() -> ScriptedBackend { ScriptedBackend(answer: .notFound, creationFailure: .keyCreationFailed(-34018)) }

final class CountingAuthenticator: UserPresenceAuthenticating, @unchecked Sendable {
    private let lock = NSLock()
    private var _reasons: [String] = []
    var failure: ApprovalSigningError?
    var reasons: [String] { lock.withLock { _reasons } }
    func requirePresence(reason: String) async throws -> PresenceProof {
        if let failure { throw failure }
        lock.withLock { _reasons.append(reason) }
        return PresenceProof(context: nil)
    }
}

struct SignerTests {
    @Test func signatureIsDERECDSAVerifiableWithTheRegisteredPublicKey() async throws {
        let auth = CountingAuthenticator()
        let signer = HumanApprovalSigner(backends: [TestKeyBackend()], authenticator: auth)
        let registration = try await signer.registration()
        #expect(registration.publicKeyX963.count == 65)
        let payload = Data("broker-payload-\(UUID())".utf8)
        let signature = try await signer.sign(payload: payload, reason: "Approve test")
        for key in [try P256.Signing.PublicKey(x963Representation: registration.publicKeyX963),
                    try P256.Signing.PublicKey(derRepresentation: registration.publicKeySPKI)] {
            let der = try P256.Signing.ECDSASignature(derRepresentation: signature)
            #expect(key.isValidSignature(der, for: payload))
            #expect(!key.isValidSignature(der, for: payload + [0]))
        }
        #expect(auth.reasons == ["Approve test"])
    }

    @Test func everySignatureNeedsAFreshPresenceCheck() async throws {
        let auth = CountingAuthenticator()
        let signer = HumanApprovalSigner(backends: [TestKeyBackend()], authenticator: auth)
        for index in 0..<3 { _ = try await signer.sign(payload: Data([UInt8(index + 1)]), reason: "r\(index)") }
        #expect(auth.reasons == ["r0", "r1", "r2"])
    }

    @Test(arguments: [ApprovalSigningError.userCancelled, .unsupported, .authenticationFailed])
    func failedPresenceProducesNoSignature(error: ApprovalSigningError) async throws {
        let auth = CountingAuthenticator()
        auth.failure = error
        let signer = HumanApprovalSigner(backends: [TestKeyBackend()], authenticator: auth)
        await #expect(throws: error) { _ = try await signer.sign(payload: Data([1]), reason: "x") }
    }

    @Test func emptyOrOversizedPayloadsAreRejectedBeforeAnyPrompt() async throws {
        let auth = CountingAuthenticator()
        let signer = HumanApprovalSigner(backends: [TestKeyBackend()], authenticator: auth)
        await #expect(throws: ApprovalSigningError.invalidPayload) { _ = try await signer.sign(payload: Data(), reason: "x") }
        await #expect(throws: ApprovalSigningError.invalidPayload) {
            _ = try await signer.sign(payload: Data(count: HumanApprovalSigner.maxPayload + 1), reason: "x")
        }
        #expect(auth.reasons.isEmpty)
    }

    @Test func missingKeyFailsClosedAndSigningNeverCreatesOne() async throws {
        let signer = HumanApprovalSigner(backends: [EmptyBackend()], authenticator: CountingAuthenticator())
        await #expect(throws: ApprovalSigningError.keyUnavailable) { _ = try await signer.sign(payload: Data([1]), reason: "x") }
        await #expect(throws: ApprovalSigningError.keyCreationFailed(-34018)) { _ = try await signer.registration() }
    }

    // MARK: Lookup failures never create a second key

    @Test(arguments: [errSecInteractionNotAllowed, errSecAuthFailed, errSecNotAvailable, errSecUserCanceled])
    func lockedOrUnreadableKeychainDoesNotCreateAnAlternateKey(status: OSStatus) async throws {
        let backend = ScriptedBackend(answer: .unavailable(status))
        let signer = HumanApprovalSigner(backends: [backend], authenticator: CountingAuthenticator())
        await #expect(throws: ApprovalSigningError.keyLookupFailed(status)) { _ = try await signer.registration() }
        #expect(backend.creations == 0)
    }

    @Test func uncertainLookupInAnyBackendBlocksCreationInAllOfThem() async throws {
        let missing = ScriptedBackend(protection: .secureEnclave, answer: .notFound)
        let locked = ScriptedBackend(answer: .unavailable(errSecInteractionNotAllowed))
        let signer = HumanApprovalSigner(backends: [missing, locked], authenticator: CountingAuthenticator())
        await #expect(throws: ApprovalSigningError.keyLookupFailed(errSecInteractionNotAllowed)) { _ = try await signer.registration() }
        #expect(missing.creations == 0 && locked.creations == 0)
    }

    @Test func onlyAConfirmedNotFoundCreatesExactlyOneKeyAndItIsStable() async throws {
        let backend = ScriptedBackend(answer: .notFound)
        let signer = HumanApprovalSigner(backends: [backend], authenticator: CountingAuthenticator())
        let first = try await signer.registration()
        let second = try await signer.registration()
        #expect(first == second)
        #expect(backend.creations == 1)
    }

    @Test func existingKeyInALaterBackendIsReusedWithoutCreatingAnother() async throws {
        let first = ScriptedBackend(protection: .secureEnclave, answer: .notFound)
        let existing = TestKeyBackend()
        let signer = HumanApprovalSigner(backends: [first, existing], authenticator: CountingAuthenticator())
        let registration = try await signer.registration()
        #expect(first.creations == 0)
        #expect(registration.publicKeyX963.count == 65)
    }

    @Test func unprotectedStoredKeyIsRefusedForRegistrationAndSigning() async throws {
        let backend = ScriptedBackend(answer: .unprotected)
        let signer = HumanApprovalSigner(backends: [backend], authenticator: CountingAuthenticator())
        await #expect(throws: ApprovalSigningError.keyNotProtected) { _ = try await signer.registration() }
        await #expect(throws: ApprovalSigningError.keyNotProtected) { _ = try await signer.sign(payload: Data([1]), reason: "x") }
        #expect(backend.creations == 0)
    }

    @Test func lockedKeychainDuringSigningProducesNoSignature() async throws {
        let signer = HumanApprovalSigner(backends: [ScriptedBackend(answer: .unavailable(errSecInteractionNotAllowed))],
                                         authenticator: CountingAuthenticator())
        await #expect(throws: ApprovalSigningError.keyLookupFailed(errSecInteractionNotAllowed)) {
            _ = try await signer.sign(payload: Data([1]), reason: "x")
        }
    }

    // MARK: Key protection attributes

    @Test func softwareKeychainKeyIsNonExtractableWithUserPresenceACL() throws {
        let tag = Data("t".utf8)
        for protection in [ApprovalKeyProtection.keychainUserPresence, .secureEnclave] {
            var error: Unmanaged<CFError>?
            let flags = KeychainKeyBackend.accessFlags(for: protection)
            #expect(flags.contains(.userPresence))
            #expect(flags.contains(.privateKeyUsage) == (protection == .secureEnclave))
            let access = try #require(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error))
            let attributes = KeychainKeyBackend.creationAttributes(protection: protection, tag: tag, access: access)
            let privateAttributes = try #require(attributes[kSecPrivateKeyAttrs as String] as? [String: Any])
            #expect(privateAttributes[kSecAttrIsExtractable as String] as? Bool == false)
            #expect(privateAttributes[kSecAttrIsPermanent as String] as? Bool == true)
            #expect(privateAttributes[kSecAttrAccessControl as String] != nil)
            #expect(attributes[kSecUseDataProtectionKeychain as String] as? Bool == true)
            #expect((attributes[kSecAttrTokenID as String] != nil) == (protection == .secureEnclave))
        }
    }

    @Test func protectionCheckRequiresACLAndNonExtractability() throws {
        var error: Unmanaged<CFError>?
        let access = try #require(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error))
        let good: [String: Any] = [kSecAttrAccessControl as String: access, kSecAttrIsExtractable as String: false]
        #expect(KeyProtectionCheck.isProtected(good, as: .keychainUserPresence))
        #expect(!KeyProtectionCheck.isProtected(good.merging([kSecAttrIsExtractable as String: true]) { $1 }, as: .keychainUserPresence))
        #expect(!KeyProtectionCheck.isProtected(["e": 1].merging([kSecAttrIsExtractable as String: false]) { $1 }, as: .keychainUserPresence), "no ACL")
        var noExtractableFlag = good; noExtractableFlag[kSecAttrIsExtractable as String] = nil
        #expect(!KeyProtectionCheck.isProtected(noExtractableFlag, as: .keychainUserPresence), "unverifiable is refused")
        #expect(!KeyProtectionCheck.isProtected(good.merging([kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave as String]) { $1 }, as: .keychainUserPresence))
        let enclaveAccess = try #require(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error))
        let enclave: [String: Any] = [kSecAttrAccessControl as String: enclaveAccess, kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave as String]
        #expect(KeyProtectionCheck.isProtected(enclave, as: .secureEnclave))
        let unprotectedAccess = try #require(SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [], &error))
        #expect(!KeyProtectionCheck.isProtected(good.merging([kSecAttrAccessControl as String: unprotectedAccess]) { $1 }, as: .keychainUserPresence))
        #expect(!KeyProtectionCheck.isProtected([kSecAttrAccessControl as String: access], as: .secureEnclave), "no token id")
        #expect(!KeyProtectionCheck.isProtected(good, as: .softwareFixture))
    }

    /// The real Keychain/Secure Enclave path under a unique namespace. An ad hoc signed build cannot
    /// create protected keys (errSecMissingEntitlement); that must fail closed, never fall back.
    @Test func productionBackendsCreateOnlyProtectedKeysOrFailClosed() async throws {
        let namespace = "dev.agentvault.test.\(UUID().uuidString)"
        let signer = HumanApprovalSigner(namespace: namespace, authenticator: CountingAuthenticator())
        defer { signer.deleteOwnKeys() }
        do {
            let registration = try await signer.registration()
            #expect(registration.protection == .secureEnclave || registration.protection == .keychainUserPresence)
            #expect(try await signer.registration() == registration, "idempotent")
        } catch ApprovalSigningError.keyCreationFailed(let status) {
            #expect(status != 0)
            await #expect(throws: ApprovalSigningError.keyUnavailable) { _ = try await signer.sign(payload: Data([1]), reason: "x") }
        }
    }
}

struct ExportTests {
    struct StubSigner: ApprovalSigning {
        let result: Result<ApprovalKeyRegistration, ApprovalSigningError>
        func registration() async throws -> ApprovalKeyRegistration { try result.get() }
        func sign(payload: Data, reason: String) async throws -> Data { Data() }
    }

    @Test func exportEmitsOnlyPublicMaterialForAProtectedKey() async throws {
        let key = P256.Signing.PrivateKey()
        let registration = ApprovalKeyRegistration(publicKeyX963: key.publicKey.x963Representation, protection: .secureEnclave)
        let result = await ApprovalKeyExport.run(arguments: ["--print-approval-public-key"], signer: StubSigner(result: .success(registration)))
        #expect(result.code == 0 && result.stderr.isEmpty)
        let object = try #require(try JSONSerialization.jsonObject(with: Data(result.stdout.utf8)) as? [String: String])
        #expect(Set(object.keys) == ["format", "algorithm", "protection", "publicKeyX963Base64", "publicKeySPKIBase64", "sha256Fingerprint"])
        let spki = try #require(Data(base64Encoded: object["publicKeySPKIBase64"]!))
        #expect(try P256.Signing.PublicKey(derRepresentation: spki).x963Representation == key.publicKey.x963Representation)
        #expect(object["sha256Fingerprint"]?.count == 64)
        #expect(!result.stdout.contains(key.rawRepresentation.base64EncodedString()))
    }

    @Test func exportRefusesUnprotectedKeysAndReportsFailuresWithCodes() async throws {
        let key = P256.Signing.PrivateKey().publicKey
        let fixture = ApprovalKeyRegistration(publicKeyX963: key.x963Representation, protection: .softwareFixture)
        #expect(await ApprovalKeyExport.run(arguments: ["--print-approval-public-key"], signer: StubSigner(result: .success(fixture))).code == 70)
        #expect(await ApprovalKeyExport.run(arguments: ["--print-approval-public-key"], signer: StubSigner(result: .failure(.keyCreationFailed(-34018)))).code == 73)
        #expect(await ApprovalKeyExport.run(arguments: ["--print-approval-public-key"], signer: StubSigner(result: .failure(.unsupported))).code == 75)
        #expect(await ApprovalKeyExport.run(arguments: ["--bogus"], signer: StubSigner(result: .success(fixture))).code == 64)
    }
}

struct InputTests {
    @Test func credentialInputShapesPerService() {
        #expect(CredentialInput.data(service: .github, secret: "ghp_abcdefghij") == Data("ghp_abcdefghij".utf8))
        #expect(CredentialInput.data(service: .github, secret: "has space token") == nil)
        #expect(CredentialInput.data(service: .githubWeb, secret: "pw", username: " octo ") == Data("octo\npw".utf8))
        #expect(CredentialInput.data(service: .browserDemo, secret: "p\nw", username: "u") == nil)
        #expect(CredentialInput.data(service: .demo, secret: "") == nil)
    }
}
