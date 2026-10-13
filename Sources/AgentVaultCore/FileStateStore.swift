import Foundation
import Darwin

/// A locked, private metadata store. It never contains credential values.
public final class FileStateStore: StateStore, @unchecked Sendable {
    // Serialize threads across independent store instances as well as cooperating
    // processes. Keep the in-process lock outside the file-lock lifecycle.
    private static let processLock = NSLock()
    private let directory: URL
    private let maxBytes = 1_048_576

    public init(directory: URL) throws {
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
            let state = try JSONDecoder().decode(VaultState.self, from: data)
            guard state.version == 1,
                  state.accounts.count <= VaultState.maxAccounts,
                  state.clients.count <= VaultState.maxClients,
                  state.grants.count <= VaultState.maxGrants,
                  Set(state.accounts.map(\.id)).count == state.accounts.count,
                  Set(state.clients.map(\.id)).count == state.clients.count,
                  Set(state.grants.map(\.id)).count == state.grants.count,
                  state.grants.allSatisfy({ $0.callLimit > 0 && $0.callsUsed >= 0 &&
                                           $0.callsUsed <= $0.callLimit }) else {
                throw VaultError.stateUnavailable
            }
            return state
        } catch { throw VaultError.stateUnavailable }
    }

    private func writeState(_ state: VaultState, directoryFD: Int32) throws {
        let data: Data
        do { data = try JSONEncoder().encode(state) } catch { throw VaultError.stateUnavailable }
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
}
