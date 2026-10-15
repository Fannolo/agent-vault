import AgentVaultIPC
import AgentVaultJSON
import Darwin
import Foundation

/// Identity policy for the broker <-> web host channel, read from protected configuration.
///
/// The host accepts only `brokerUID` running code that satisfies `brokerRequirement`. The broker
/// sends nothing but an empty probe until a reply proves `hostUID` and `hostRequirement`.
/// Production needs three distinct UIDs: the web host, the broker and the agent's.
public struct WebHostConfiguration: Codable, Sendable, Equatable {
    public var serviceName: String
    public var hostRequirement: String
    public var brokerRequirement: String
    public var hostUID: UInt32
    public var brokerUID: UInt32
    /// The paired agent's UID. Neither service may run as it.
    public var agentUID: UInt32
    /// Fixture rules: cdhash-only pins, the per-user bootstrap and one shared test UID.
    public var development: Bool

    public init(serviceName: String, hostRequirement: String, brokerRequirement: String, hostUID: UInt32,
                brokerUID: UInt32, agentUID: UInt32, development: Bool) {
        self.serviceName = serviceName; self.hostRequirement = hostRequirement
        self.brokerRequirement = brokerRequirement; self.hostUID = hostUID; self.brokerUID = brokerUID
        self.agentUID = agentUID; self.development = development
    }

    public enum Role: Sendable { case broker, host }

    public func validate(for role: Role, effectiveUID: UInt32 = UInt32(geteuid())) throws(IPCError) {
        guard IPCConfiguration.isServiceName(serviceName), hostRequirement != brokerRequirement,
              IPCConfiguration.isPinnedRequirement(hostRequirement, development: development),
              IPCConfiguration.isPinnedRequirement(brokerRequirement, development: development) else {
            throw .invalidConfiguration
        }
        let uids = [hostUID, brokerUID, agentUID]
        guard effectiveUID != 0, uids.allSatisfy({ $0 != 0 && $0 != UInt32.max }) else { throw .invalidConfiguration }
        if !development && Set(uids).count != uids.count { throw .invalidConfiguration }
        guard effectiveUID == (role == .broker ? brokerUID : hostUID) else { throw .invalidConfiguration }
    }

    /// The broker side must agree with the broker's own IPC identity policy.
    public func validate(brokerIPC ipc: IPCConfiguration) throws(IPCError) {
        guard development == ipc.development, brokerUID == ipc.brokerUID, agentUID == ipc.allowedUID,
              brokerRequirement == ipc.brokerRequirement,
              ![ipc.readServiceName, ipc.adminServiceName].contains(serviceName),
              ![ipc.readRequirement, ipc.adminRequirement].contains(hostRequirement) else {
            throw .invalidConfiguration
        }
    }

    static let keys: Set<String> = ["serviceName", "hostRequirement", "brokerRequirement", "hostUID", "brokerUID",
                                    "agentUID", "development"]

    /// Parses exactly these keys. A production configuration must also come from a root-owned
    /// file that group and others cannot write, so a same-user process cannot repoint the link.
    public static func load(contentsOf path: String) throws(IPCError) -> WebHostConfiguration {
        let data = try readUnprotected(path)
        let configuration = try decode(data)
        if !configuration.development {
            // The protected read must return the very bytes that were decoded.
            guard try IPCConfiguration.readProtectedFile(atPath: path, maxBytes: 16_384) == data else {
                throw .invalidConfiguration
            }
        }
        return configuration
    }

    static func decode(_ data: Data) throws(IPCError) -> WebHostConfiguration {
        do { try JSONObjectGuard.validate(data) } catch { throw .invalidConfiguration }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys, !object.values.contains(where: { $0 is NSNull }),
              let value = try? JSONDecoder().decode(WebHostConfiguration.self, from: data) else {
            throw .invalidConfiguration
        }
        return value
    }

    private static func readUnprotected(_ path: String) throws(IPCError) -> Data {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw .invalidConfiguration }
        defer { close(descriptor) }
        var file = stat()
        guard fstat(descriptor, &file) == 0, (file.st_mode & S_IFMT) == S_IFREG,
              (1...16_384).contains(file.st_size) else { throw .invalidConfiguration }
        var data = Data(count: Int(file.st_size))
        let count = data.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
        guard count == Int(file.st_size) else { throw .invalidConfiguration }
        return data
    }
}
