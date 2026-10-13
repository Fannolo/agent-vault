import Foundation
import LocalAuthentication
import Security

/// Proof that the person just passed a fresh user-presence check. The context is bound to
/// that evaluation so protected key use does not prompt a second time.
public final class PresenceProof: @unchecked Sendable {
    let context: LAContext?
    public init(context: LAContext?) { self.context = context }
}

public protocol UserPresenceAuthenticating: Sendable {
    /// Must show a fresh system prompt each call and fail closed when none can be shown.
    func requirePresence(reason: String) async throws -> PresenceProof
}

/// LocalAuthentication: biometrics or device password, never reused, never cached.
public struct LocalAuthenticator: UserPresenceAuthenticating {
    public init() {}

    public func requirePresence(reason: String) async throws -> PresenceProof {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        var availability: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &availability) else {
            throw ApprovalSigningError.unsupported
        }
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
                throw ApprovalSigningError.authenticationFailed
            }
        } catch let error as ApprovalSigningError {
            throw error
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel: throw ApprovalSigningError.userCancelled
            case .passcodeNotSet, .biometryNotAvailable, .biometryNotEnrolled: throw ApprovalSigningError.unsupported
            default: throw ApprovalSigningError.authenticationFailed
            }
        } catch {
            throw ApprovalSigningError.authenticationFailed
        }
        return PresenceProof(context: context)
    }
}

/// Result of looking for the approval key in one backend. Only `.notFound` may lead to creation.
public enum ApprovalKeyLookup {
    case found(SecKey)
    /// The Keychain definitively reported no such item (errSecItemNotFound).
    case notFound
    /// Lookup failed for another reason; the key may exist. Carries the Security status.
    case unavailable(Int32)
    /// Found, but the stored attributes do not prove the expected protection.
    case unprotected
}

/// Pure check of Keychain item attributes against the protection this build requires.
/// This verifies what the Keychain reports; it is not hardware attestation and does not
/// prove anything to the broker about where the public key came from.
enum KeyProtectionCheck {
    static func isProtected(_ attributes: [String: Any], as protection: ApprovalKeyProtection) -> Bool {
        guard let access = attributes[kSecAttrAccessControl as String],
              CFGetTypeID(access as CFTypeRef) == SecAccessControlGetTypeID(),
              let expected = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                  protection == .secureEnclave ? [.privateKeyUsage, .userPresence] : [.userPresence], nil),
              CFEqual(access as CFTypeRef, expected) else { return false }
        let tokenID = attributes[kSecAttrTokenID as String] as? String
        let extractable = (attributes[kSecAttrIsExtractable as String] as? NSNumber)?.boolValue
        switch protection {
        case .secureEnclave:
            return tokenID == (kSecAttrTokenIDSecureEnclave as String) && extractable != true
        case .keychainUserPresence:
            return tokenID == nil && extractable == false
        case .softwareFixture:
            return false
        }
    }
}

/// One place a protected P-256 key can live. There is deliberately no unprotected implementation
/// in production code.
public protocol ApprovalKeyBackend: Sendable {
    var protection: ApprovalKeyProtection { get }
    /// Looks up the key without prompting. `proof` is attached for private-key use only.
    func lookup(proof: PresenceProof?) -> ApprovalKeyLookup
    func createKey() throws -> SecKey
}

struct KeychainKeyBackend: ApprovalKeyBackend {
    let protection: ApprovalKeyProtection
    let tag: Data

    init(protection: ApprovalKeyProtection, namespace: String) {
        self.protection = protection
        tag = Data("\(namespace).\(protection.rawValue)".utf8)
    }

    private var isSecureEnclave: Bool { protection == .secureEnclave }

    private func query(proof: PresenceProof?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag,
            kSecUseDataProtectionKeychain as String: true
        ]
        if isSecureEnclave { query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave }
        if let context = proof?.context {
            query[kSecUseAuthenticationContext as String] = context
        } else {
            let silent = LAContext()
            silent.interactionNotAllowed = true
            query[kSecUseAuthenticationContext as String] = silent
        }
        return query
    }

    func lookup(proof: PresenceProof?) -> ApprovalKeyLookup {
        var search = query(proof: proof)
        search[kSecReturnRef as String] = true
        search[kSecReturnAttributes as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitAll
        var item: CFTypeRef?
        let status = SecItemCopyMatching(search as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let rows = item as? [[String: Any]], rows.count == 1,
                  let ref = rows[0][kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecKeyGetTypeID()
            else { return .unavailable(errSecDuplicateItem) }
            guard KeyProtectionCheck.isProtected(rows[0], as: protection) else { return .unprotected }
            return .found(ref as! SecKey)
        case errSecItemNotFound:
            return .notFound
        default:
            return .unavailable(status)
        }
    }

    /// Attributes for `SecKeyCreateRandomKey`. The software key is explicitly non-extractable.
    static func creationAttributes(protection: ApprovalKeyProtection, tag: Data, access: SecAccessControl) -> [String: Any] {
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrIsExtractable as String: false,
                kSecAttrApplicationTag as String: tag,
                kSecAttrLabel as String: "Agent Vault approval key",
                kSecAttrAccessControl as String: access
            ] as [String: Any]
        ]
        if protection == .secureEnclave { attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave }
        return attributes
    }

    static func accessFlags(for protection: ApprovalKeyProtection) -> SecAccessControlCreateFlags {
        protection == .secureEnclave ? [.privateKeyUsage, .userPresence] : [.userPresence]
    }

    func createKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, Self.accessFlags(for: protection), &error) else {
            throw ApprovalSigningError.keyCreationFailed(Int32(error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? -1))
        }
        var failure: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(
            Self.creationAttributes(protection: protection, tag: tag, access: access) as CFDictionary, &failure) != nil else {
            throw ApprovalSigningError.keyCreationFailed(Int32(failure.map { CFErrorGetCode($0.takeRetainedValue()) } ?? -1))
        }
        // Re-read what the Keychain stored; a key whose protection cannot be proven is removed and refused.
        guard case .found(let stored) = lookup(proof: nil) else {
            deleteOwnKey()
            throw ApprovalSigningError.keyNotProtected
        }
        return stored
    }

    /// Deletes only the item with this backend's own tag.
    func deleteOwnKey() {
        SecItemDelete(query(proof: nil) as CFDictionary)
    }
}

/// Signs broker challenges with a key that requires fresh user presence for every use.
///
/// Production order: Secure Enclave, then a user-presence-protected Keychain key. If neither
/// can be created (for example an ad hoc signed build without Keychain entitlements) every
/// operation fails closed; there is no unprotected fallback.
public final class HumanApprovalSigner: ApprovalSigning, @unchecked Sendable {
    public static let productionNamespace = "dev.agentvault.human-approval.v1"
    static let maxPayload = 65_536

    private let backends: [ApprovalKeyBackend]
    private let authenticator: UserPresenceAuthenticating
    private let lock = NSLock()

    public init(namespace: String = HumanApprovalSigner.productionNamespace,
                authenticator: UserPresenceAuthenticating = LocalAuthenticator()) {
        backends = [KeychainKeyBackend(protection: .secureEnclave, namespace: namespace),
                    KeychainKeyBackend(protection: .keychainUserPresence, namespace: namespace)]
        self.authenticator = authenticator
    }

    /// Injection point for tests of the signing flow with a non-persistent test key.
    package init(backends: [ApprovalKeyBackend], authenticator: UserPresenceAuthenticating) {
        self.backends = backends
        self.authenticator = authenticator
    }

    public func registration() async throws -> ApprovalKeyRegistration {
        try lock.withLock {
            var uncertain: Int32?
            for backend in backends {
                switch backend.lookup(proof: nil) {
                case .found(let key): return try Self.registration(key, backend.protection)
                case .notFound: break
                case .unprotected: throw ApprovalSigningError.keyNotProtected
                case .unavailable(let status): uncertain = uncertain ?? status
                }
            }
            // A key might exist that we could not see (locked Keychain, interaction not allowed).
            // Creating another would silently change the public key the broker trusts.
            if let uncertain { throw ApprovalSigningError.keyLookupFailed(uncertain) }
            var lastStatus: Int32 = -1
            for backend in backends {
                do { return try Self.registration(try backend.createKey(), backend.protection) }
                catch ApprovalSigningError.keyCreationFailed(let status) { lastStatus = status }
            }
            throw ApprovalSigningError.keyCreationFailed(lastStatus)
        }
    }

    public func sign(payload: Data, reason: String) async throws -> Data {
        guard !payload.isEmpty, payload.count <= Self.maxPayload else { throw ApprovalSigningError.invalidPayload }
        let proof = try await authenticator.requirePresence(reason: reason)
        return try lock.withLock {
            var failure: ApprovalSigningError = .keyUnavailable
            for backend in backends {
                switch backend.lookup(proof: proof) {
                case .notFound: continue
                case .unprotected: throw ApprovalSigningError.keyNotProtected
                case .unavailable(let status): failure = .keyLookupFailed(status); continue
                case .found(let key):
                    guard let publicKey = SecKeyCopyPublicKey(key) else { throw ApprovalSigningError.keyUnavailable }
                    var error: Unmanaged<CFError>?
                    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                                payload as CFData, &error) as Data? else {
                        _ = error?.takeRetainedValue()
                        throw ApprovalSigningError.signingFailed
                    }
                    guard SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256,
                                                payload as CFData, signature as CFData, nil) else {
                        throw ApprovalSigningError.signingFailed
                    }
                    return signature
                }
            }
            throw failure
        }
    }

    private static func registration(_ key: SecKey, _ protection: ApprovalKeyProtection) throws -> ApprovalKeyRegistration {
        guard let publicKey = SecKeyCopyPublicKey(key),
              let raw = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?, raw.count == 65, raw.first == 0x04
        else { throw ApprovalSigningError.keyUnavailable }
        return ApprovalKeyRegistration(publicKeyX963: raw, protection: protection)
    }

    /// Removes only this signer's own keys. Used by tests with a unique namespace.
    package func deleteOwnKeys() {
        for backend in backends { (backend as? KeychainKeyBackend)?.deleteOwnKey() }
    }
}
