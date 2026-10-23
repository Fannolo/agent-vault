import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A locked, private metadata store. It never contains credential values.
public final class FileStateStore: StateStore, @unchecked Sendable {
    // Serialize threads across independent store instances as well as cooperating
    // processes. Keep the in-process lock outside the file-lock lifecycle.
    private static let processLock = NSLock()
    private let directory: URL
    private let maxBytes = 1_048_576
    private let integrityKey: SymmetricKey?

    public init(directory: URL, integrityKey: Data? = nil) throws {
        guard integrityKey == nil || integrityKey?.count == 32 else { throw VaultError.invalidInput }
        self.integrityKey = integrityKey.map { SymmetricKey(data: $0) }
        self.directory = directory.standardizedFileURL
        var info = stat()
        if lstat(self.directory.path, &info) != 0 {
            guard errno == ENOENT else { throw VaultError.stateUnavailable }
            do {
                try FileManager.default.createDirectory(at: self.directory, withIntermediateDirectories: true,
                                                         attributes: [.posixPermissions: 0o700])
            } catch { throw VaultError.stateUnavailable }
        }
        guard lstat(self.directory.path, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0 else { throw VaultError.stateUnavailable }
    }

    public func transaction<T>(_ body: (inout VaultState) throws -> T) throws -> T {
        try withDirectoryLock { dir in
            var state = try readState(dir)
            let result = try body(&state)
            try writeState(state, directoryFD: dir)
            return result
        }
    }

    public func snapshot() throws -> VaultState {
        try withDirectoryLock { try readState($0) }
    }

    private func withDirectoryLock<T>(_ body: (Int32) throws -> T) throws -> T {
        Self.processLock.lock()
        defer { Self.processLock.unlock() }
        let dir = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dir >= 0 else { throw VaultError.stateUnavailable }
        defer { close(dir) }
        var directoryInfo = stat()
        guard fstat(dir, &directoryInfo) == 0, directoryInfo.st_uid == geteuid(),
              directoryInfo.st_mode & 0o077 == 0 else { throw VaultError.stateUnavailable }
        let lock = openat(dir, "state.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lock >= 0 else { throw VaultError.stateUnavailable }
        defer { close(lock) }
        try validateFile(lock)
        guard flock(lock, LOCK_EX) == 0 else { throw VaultError.stateUnavailable }
        defer { flock(lock, LOCK_UN) }
        return try body(dir)
    }

    private func validateFile(_ fd: Int32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0,
              info.st_nlink == 1 else { throw VaultError.stateUnavailable }
    }

    private func readState(_ directoryFD: Int32) throws -> VaultState {
        let fd = openat(directoryFD, "state.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return VaultState() }
            throw VaultError.stateUnavailable
        }
        defer { close(fd) }
        try validateFile(fd)
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count < 0 { if errno == EINTR { continue }; throw VaultError.stateUnavailable }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count <= maxBytes else { throw VaultError.stateUnavailable }
        }
        do {
            if let integrityKey {
                let envelope = try JSONDecoder().decode(AuthenticatedState.self, from: data)
                guard HMAC<SHA256>.isValidAuthenticationCode(envelope.tag, authenticating: envelope.payload,
                                                           using: integrityKey) else { throw VaultError.stateUnavailable }
                data = envelope.payload
            }
            let state = try JSONDecoder().decode(VaultState.self, from: data)
            try validateState(state)
            return state
        } catch { throw VaultError.stateUnavailable }
    }

    private func validateState(_ state: VaultState) throws {
        guard state.version == 3,
                  state.accounts.count <= VaultState.maxAccounts,
                  state.clients.count <= VaultState.maxClients,
                  state.grants.count <= VaultState.maxGrants,
                  state.pending.count <= 128,
                  state.audit.count <= VaultState.maxInvocationAudit,
                  state.adminAudit.count <= VaultState.maxAdministrationAudit,
                  (state.audit + state.adminAudit).allSatisfy({
                      $0.timestamp.timeIntervalSince1970.isFinite && $0.outcome.utf8.count <= 64
                  }),
                  Set(state.accounts.map(\.id)).count == state.accounts.count,
                  Set(state.clients.map(\.id)).count == state.clients.count,
                  Set(state.grants.map(\.id)).count == state.grants.count,
                  Set(state.pending.map(\.id)).count == state.pending.count,
                  state.grants.allSatisfy({ $0.callLimit > 0 && $0.callLimit <= 10_000 && $0.callsUsed >= 0 &&
                                           $0.callsUsed <= $0.callLimit }) else {
                throw VaultError.stateUnavailable
            }
        let accounts = Dictionary(uniqueKeysWithValues: state.accounts.map { ($0.id, $0) })
        let clients = Set(state.clients.map(\.id))
        let grants = Dictionary(uniqueKeysWithValues: state.grants.map { ($0.id, $0) })
        let uids = state.clients.filter { !$0.revoked }.compactMap(\.uid)
        let credentials = state.accounts.flatMap { [$0.credentialID, $0.stagedCredentialID, $0.retiredCredentialID].compactMap { $0 } }
        guard !uids.contains(0), Set(uids).count == uids.count,
              Set(credentials).count == credentials.count,
              state.accounts.allSatisfy({ account in
                  switch account.lifecycle {
                  case .enrolling: account.stagedCredentialID == nil && account.retiredCredentialID == nil
                  case .active: account.stagedCredentialID == nil
                  case .rotating: account.stagedCredentialID != nil && account.retiredCredentialID == nil
                  case .deleting: true
                  }
              }),
              state.grants.allSatisfy({ clients.contains($0.clientID) && accounts[$0.accountID]?.service.action == $0.action &&
                  $0.expiresAt.timeIntervalSince1970.isFinite }),
              state.pending.allSatisfy({ pending in
                  guard let grant = grants[pending.grantID] else { return false }
                  return grant.requiresApproval && grant.clientID == pending.clientID && grant.accountID == pending.accountID &&
                      grant.action == pending.action && pending.expiresAt.timeIntervalSince1970.isFinite &&
                      pending.expiresAt <= grant.expiresAt
              }) else { throw VaultError.stateUnavailable }
    }

    private func writeState(_ state: VaultState, directoryFD: Int32) throws {
        try validateState(state)
        var data: Data
        do {
            data = try JSONEncoder().encode(state)
            if let integrityKey {
                let envelope = AuthenticatedState(payload: data,
                    tag: Data(HMAC<SHA256>.authenticationCode(for: data, using: integrityKey)))
                data = try JSONEncoder().encode(envelope)
            }
        } catch { throw VaultError.stateUnavailable }
        guard data.count <= maxBytes else { throw VaultError.stateUnavailable }
        let name = ".state-\(UUID().uuidString).tmp"
        let fd = openat(directoryFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw VaultError.stateUnavailable }
        defer { close(fd); unlinkat(directoryFD, name, 0) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 { if errno == EINTR { continue }; throw VaultError.stateUnavailable }
                guard count > 0 else { throw VaultError.stateUnavailable }
                offset += count
            }
        }
        guard fsync(fd) == 0, renameat(directoryFD, name, directoryFD, "state.json") == 0,
              fsync(directoryFD) == 0 else { throw VaultError.stateUnavailable }
    }

    private struct AuthenticatedState: Codable { let payload: Data; let tag: Data }
}
