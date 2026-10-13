import Foundation
import Security

public struct KeychainStore: SecretStore {
    private let namespace: String
    public init(namespace: String = "io.agent-vault.credentials.v1") { self.namespace = namespace }

    private func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: namespace,
         kSecAttrAccount as String: id.uuidString.lowercased(),
         kSecAttrSynchronizable as String: false,
         kSecUseDataProtectionKeychain as String: false]
    }

    public func save(_ value: Data, for accountID: UUID) throws {
        guard !value.isEmpty, value.count <= 8192 else { throw VaultError.invalidInput }
        var item = query(accountID)
        item[kSecValueData as String] = value
        let status = SecItemAdd(item as CFDictionary, nil)
        // Never overwrite a pre-existing item silently.
        guard status == errSecSuccess else { throw VaultError.secretUnavailable }
    }

    public func load(for accountID: UUID) throws -> Data {
        var item = query(accountID)
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(item as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data, !data.isEmpty else { throw VaultError.secretUnavailable }
        return data
    }

    public func delete(for accountID: UUID) throws {
        let status = SecItemDelete(query(accountID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultError.secretUnavailable
        }
    }
}
