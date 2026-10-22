import Darwin
import Foundation
import Security

/// An explicit Keychain database for the dedicated broker user. Never changes the
/// user's default Keychain or search list and never queries existing credentials.
public final class PrivateKeychainStore: SecretStore, @unchecked Sendable {
    private let keychain: SecKeychain
    private let access: SecAccess
    private let password: Data
    private let namespace = "io.agent-vault.broker.credentials.v2"

    public init(path: URL, password: Data) throws {
        guard password.count == 32 else { throw VaultError.invalidInput }
        // Security.framework documents a canonical UTF-8 password. Keep the
        // installer seed binary, and use one deterministic ASCII encoding here.
        let password = Data(password.base64EncodedString().utf8)
        self.password = password
        let directory = path.deletingLastPathComponent()
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw VaultError.secretUnavailable }
        var trusted: SecTrustedApplication?
        guard SecTrustedApplicationCreateFromPath(nil, &trusted) == errSecSuccess, let trusted else {
            throw VaultError.secretUnavailable
        }
        var access: SecAccess?
        guard SecAccessCreate("Agent Vault broker" as CFString, [trusted] as CFArray, &access) == errSecSuccess,
              let access else { throw VaultError.secretUnavailable }
        self.access = access
        var keychain: SecKeychain?
        let status: OSStatus
        if lstat(path.path, &info) == 0 {
            guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
                  info.st_mode & 0o077 == 0, info.st_nlink == 1 else { throw VaultError.secretUnavailable }
            status = SecKeychainOpen(path.path, &keychain)
        } else {
            guard errno == ENOENT else { throw VaultError.secretUnavailable }
            status = password.withUnsafeBytes {
                SecKeychainCreate(path.path, UInt32($0.count), $0.baseAddress, false, access, &keychain)
            }
            if status == errSecSuccess {
                let fd = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw VaultError.secretUnavailable }
                defer { close(fd) }
                guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                      info.st_uid == geteuid(), info.st_nlink == 1, fchmod(fd, 0o600) == 0 else {
                    throw VaultError.secretUnavailable
                }
            }
        }
        guard status == errSecSuccess, let keychain else { throw VaultError.secretUnavailable }
        self.keychain = keychain
        try unlock()
        // Keep this database's lock policy. Changing it can require a GUI owner-
        // authorization prompt even after unlocking, which a LaunchDaemon cannot
        // answer. Every operation explicitly unlocks with the private seed instead.
    }

    private func unlock() throws {
        guard password.withUnsafeBytes({ SecKeychainUnlock(keychain, UInt32($0.count), $0.baseAddress, true) }) == errSecSuccess
        else { throw VaultError.secretUnavailable }
    }

    package func lockForSyntheticTest() throws {
        guard SecKeychainLock(keychain) == errSecSuccess else { throw VaultError.secretUnavailable }
    }

    private func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: namespace, kSecAttrAccount as String: id.uuidString.lowercased(),
         kSecAttrSynchronizable as String: false, kSecUseDataProtectionKeychain as String: false,
         kSecMatchSearchList as String: [keychain]]
    }
    public func save(_ value: Data, for accountID: UUID) throws {
        guard !value.isEmpty, value.count <= 8192 else { throw VaultError.invalidInput }
        try unlock()
        var item = query(accountID)
        item.removeValue(forKey: kSecMatchSearchList as String)
        item[kSecUseKeychain as String] = keychain
        item[kSecAttrAccess as String] = access
        item[kSecValueData as String] = value
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw VaultError.secretUnavailable }
    }
    public func load(for accountID: UUID) throws -> Data {
        try unlock()
        var item = query(accountID)
        item[kSecReturnData as String] = true; item[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(item as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data, !data.isEmpty else { throw VaultError.secretUnavailable }
        return data
    }
    public func delete(for accountID: UUID) throws {
        try unlock()
        let status = SecItemDelete(query(accountID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.secretUnavailable }
    }
}
