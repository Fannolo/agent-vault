import AgentVaultIPC
import Darwin
import Foundation

public enum DeploymentError: String, Error, Sendable {
    case invalidInstallation = "invalid_installation"
    case alreadyRunning = "broker_already_running"
}

public struct DeploymentConfiguration: Codable, Sendable {
    public static let configPath = "/Library/Application Support/AgentVault/config.json"
    public static let dataPath = "/private/var/db/agent-vault"
    public let ipc: IPCConfiguration
    public let approvalPublicKey: Data

    public init(ipc: IPCConfiguration, approvalPublicKey: Data) {
        self.ipc = ipc; self.approvalPublicKey = approvalPublicKey
    }

    public static func load(for role: IPCConfiguration.Role) throws -> DeploymentConfiguration {
        let url = URL(fileURLWithPath: configPath)
        try ProtectedFiles.checkParents(url, permittedOwners: [0])
        let data = try ProtectedFiles.read(url, owner: 0, maximum: 16_384, privateMode: false)
        guard let config = try? JSONDecoder().decode(Self.self, from: data),
              !config.ipc.development, config.approvalPublicKey.count == 65 else {
            throw DeploymentError.invalidInstallation
        }
        try config.ipc.validate(for: role)
        return config
    }

    public func brokerMaterial() throws -> (password: Data, integrityKey: Data) {
        guard geteuid() == ipc.brokerUID, ipc.brokerUID != ipc.allowedUID, ipc.brokerUID != 0 else {
            throw DeploymentError.invalidInstallation
        }
        let root = URL(fileURLWithPath: Self.dataPath, isDirectory: true)
        try ProtectedFiles.checkParents(root.appendingPathComponent("keychain.password"), permittedOwners: [0, ipc.brokerUID])
        let password = try ProtectedFiles.read(root.appendingPathComponent("keychain.password"), owner: ipc.brokerUID, maximum: 32)
        let key = try ProtectedFiles.read(root.appendingPathComponent("state-integrity.key"), owner: ipc.brokerUID, maximum: 32)
        guard password.count == 32, key.count == 32 else { throw DeploymentError.invalidInstallation }
        return (password, key)
    }
}

public enum ProtectedFiles {
    public static func checkParents(_ url: URL, permittedOwners: Set<UInt32>) throws {
        var parent = url.deletingLastPathComponent()
        while true {
            var info = stat()
            guard lstat(parent.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  permittedOwners.contains(info.st_uid), info.st_mode & 0o022 == 0 else {
                throw DeploymentError.invalidInstallation
            }
            if parent.path == "/" { return }
            parent = parent.deletingLastPathComponent()
        }
    }

    public static func read(_ url: URL, owner: UInt32, maximum: Int, privateMode: Bool = true) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw DeploymentError.invalidInstallation }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == owner,
              info.st_nlink == 1, info.st_size <= maximum,
              info.st_mode & (privateMode ? 0o077 : 0o022) == 0 else { throw DeploymentError.invalidInstallation }
        var data = Data(), buffer = [UInt8](repeating: 0, count: min(4096, maximum + 1))
        while true {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 { if errno == EINTR { continue }; throw DeploymentError.invalidInstallation }
            if count == 0 { return data }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count <= maximum else { throw DeploymentError.invalidInstallation }
        }
    }
}

/// Held for the daemon lifetime, preventing two brokers from recovering or mutating
/// one credential journal concurrently. Per-transaction locks remain separate.
public final class BrokerLease: @unchecked Sendable {
    private let fd: Int32
    public init(directory: URL) throws {
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw DeploymentError.invalidInstallation }
        let dir = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dir >= 0 else { throw DeploymentError.invalidInstallation }
        defer { close(dir) }
        let descriptor = openat(dir, "broker.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw DeploymentError.invalidInstallation }
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0 else {
            close(descriptor); throw DeploymentError.invalidInstallation
        }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { close(descriptor); throw DeploymentError.alreadyRunning }
        self.fd = descriptor
    }
    deinit { flock(fd, LOCK_UN); close(fd) }
}
