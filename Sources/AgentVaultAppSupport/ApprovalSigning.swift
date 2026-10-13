import Foundation

public enum ApprovalKeyProtection: String, Sendable, Equatable {
    /// Private key generated and used inside the Secure Enclave, gated by user presence.
    case secureEnclave = "secure_enclave"
    /// Private key in the data-protection Keychain with a user-presence access control.
    case keychainUserPresence = "keychain_user_presence"
    /// Unprotected in-memory key. Exists only for DEBUG previews and automated tests; no
    /// production code path constructs a signer that reports this.
    case softwareFixture = "software_fixture"
}

public enum ApprovalSigningError: Error, Equatable, Sendable {
    /// No user-presence authentication (biometrics or device password) is available.
    case unsupported
    case userCancelled
    case authenticationFailed
    /// A protected key could not be created. The code is the Security framework status.
    case keyCreationFailed(Int32)
    /// No key exists where one is required (signing never creates keys).
    case keyUnavailable
    /// The key could not be looked up for a reason other than "not found" (locked Keychain,
    /// interaction not allowed, authentication failure, duplicates). Nothing was created.
    case keyLookupFailed(Int32)
    /// A key exists but its attributes do not prove the expected protection; it is not used.
    case keyNotProtected
    case invalidPayload
    case signingFailed
}

/// Everything an installer needs to register the app's approval key with the broker.
/// Contains no secret: the private key never leaves the Keychain / Secure Enclave.
public struct ApprovalKeyRegistration: Sendable, Equatable {
    /// ANSI X9.63 uncompressed P-256 point (65 bytes). Matches `P256.Signing.PublicKey(x963Representation:)`.
    public let publicKeyX963: Data
    public let protection: ApprovalKeyProtection

    public init(publicKeyX963: Data, protection: ApprovalKeyProtection) {
        self.publicKeyX963 = publicKeyX963; self.protection = protection
    }

    /// SubjectPublicKeyInfo DER. Matches `P256.Signing.PublicKey(derRepresentation:)`.
    public var publicKeySPKI: Data {
        Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
              0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]) + publicKeyX963
    }

    public var publicKeyBase64: String { publicKeyX963.base64EncodedString() }
}

public protocol ApprovalSigning: Sendable {
    /// Loads the existing approval key or creates a protected one; never a software fallback.
    func registration() async throws -> ApprovalKeyRegistration
    /// Signs the broker payload with ECDSA P-256/SHA-256 and returns the ASN.1 DER signature,
    /// after a fresh user-presence check that names `reason`. The payload is opaque bytes.
    func sign(payload: Data, reason: String) async throws -> Data
}
