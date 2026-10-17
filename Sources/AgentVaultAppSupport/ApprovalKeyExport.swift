import CryptoKit
import Foundation

/// Public half of the approval key, in the form an installer needs to register it with the broker.
/// Contains nothing secret.
public enum ApprovalKeyExport {
    public static func fingerprint(_ registration: ApprovalKeyRegistration) -> String {
        SHA256.hash(data: registration.publicKeyX963).map { String(format: "%02x", $0) }.joined()
    }

    public static func json(_ registration: ApprovalKeyRegistration) throws -> Data {
        let object: [String: Any] = [
            "format": "agent-vault-approval-public-key-v1",
            "algorithm": "ecdsa-p256-sha256-der",
            "protection": registration.protection.rawValue,
            "publicKeyX963Base64": registration.publicKeyBase64,
            "publicKeySPKIBase64": registration.publicKeySPKI.base64EncodedString(),
            "sha256Fingerprint": fingerprint(registration)
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    }

    /// Process exit codes for `--print-approval-public-key`. Zero means a protected key was exported.
    public static func run(arguments: [String], signer: ApprovalSigning) async -> (code: Int32, stdout: String, stderr: String) {
        guard arguments == ["--print-approval-public-key"] else {
            return (64, "", "usage: AgentVault --print-approval-public-key\n")
        }
        do {
            let registration = try await signer.registration()
            guard registration.protection != .softwareFixture else { return (70, "", "approval key is not protected\n") }
            return (0, String(decoding: try json(registration), as: UTF8.self) + "\n", "")
        } catch let error as ApprovalSigningError {
            switch error {
            case .keyCreationFailed(let status): return (73, "", "cannot create a protected approval key (keychain status \(status))\n")
            case .unsupported: return (75, "", "user-presence authentication is unavailable\n")
            case .keyLookupFailed(let status): return (74, "", "approval key could not be read (keychain status \(status)); nothing was created\n")
            case .keyNotProtected: return (76, "", "stored approval key lacks required protection\n")
            default: return (70, "", "approval key unavailable\n")
            }
        } catch {
            return (70, "", "approval key unavailable\n")
        }
    }
}

public enum ApprovalCommand {
    /// Runs the export command to completion for a process entry point that is not async.
    public static func runBlocking(arguments: [String]) -> (code: Int32, stdout: String, stderr: String) {
        final class Box: @unchecked Sendable { var value: (code: Int32, stdout: String, stderr: String) = (70, "", "") }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            box.value = await ApprovalKeyExport.run(arguments: arguments, signer: HumanApprovalSigner())
            done.signal()
        }
        done.wait()
        return box.value
    }
}
