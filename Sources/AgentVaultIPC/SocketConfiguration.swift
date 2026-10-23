#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation

/// Identity policy for the native Unix-socket broker transport.
///
/// There is no code signature on this path. The kernel-recorded peer UID is the whole client
/// identity: the read endpoint accepts only `read.clientUID`, the admin endpoint only
/// `admin.clientUID`, and every client accepts only a broker whose socket peer is `brokerUID`.
/// Admin mutations additionally need the pinned controller's signature, checked by the broker.
public struct SocketConfiguration: Codable, Sendable, Equatable {
    public struct Endpoint: Codable, Sendable, Equatable {
        /// Absolute socket path. Its directory must already exist and be protected.
        public var path: String
        /// The only kernel effective UID this endpoint serves.
        public var clientUID: UInt32
        /// Group given to the socket file, which is mode 0660. Defense in depth only.
        public var group: UInt32

        public init(path: String, clientUID: UInt32, group: UInt32) {
            self.path = path; self.clientUID = clientUID; self.group = group
        }
    }

    public var read: Endpoint
    public var admin: Endpoint
    public var brokerUID: UInt32
    public var development: Bool

    public init(read: Endpoint, admin: Endpoint, brokerUID: UInt32, development: Bool) {
        self.read = read; self.admin = admin; self.brokerUID = brokerUID; self.development = development
    }

    public enum Role: Sendable { case broker, readClient, adminClient }

    /// Installed location of the production configuration on Linux.
    public static let installedPath = "/etc/agent-vault/sockets.json"

    /// Reads a configuration with exactly the known keys. A production configuration must be a
    /// root-owned file that group and others cannot write, in such a directory.
    public static func load(contentsOf path: String) throws(IPCError) -> SocketConfiguration {
        let (data, file) = try ProtectedFile.contents(atPath: path, maxBytes: 16_384)
        let endpoint = Shape.object(required: ["path", "clientUID", "group"])
        let shape = Shape.object(required: ["read", "admin", "brokerUID", "development"],
                                 nested: ["read": endpoint, "admin": endpoint])
        let decoder = JSONDecoder()
        guard let tree = try? decoder.decode(JSONTree.self, from: data), shape.admits(tree),
              let configuration = try? decoder.decode(SocketConfiguration.self, from: data) else {
            throw .invalidConfiguration
        }
        if !configuration.development { try ProtectedFile.requireProtected(file, path: path) }
        return configuration
    }

    /// Validates the policy for the process that will use it.
    ///
    /// Root is refused in every mode. Production also requires three distinct UIDs: an agent
    /// sharing the controller's UID could otherwise read administrative state.
    public func validate(for role: Role, effectiveUID: UInt32 = UInt32(geteuid())) throws(IPCError) {
        guard Self.isSocketPath(read.path), Self.isSocketPath(admin.path), read.path != admin.path else {
            throw .invalidConfiguration
        }
        for uid in [brokerUID, read.clientUID, admin.clientUID, effectiveUID] {
            guard uid != 0, uid < UInt32.max - 1 else { throw .invalidConfiguration }
        }
        for group in [read.group, admin.group] {
            guard group < UInt32.max - 1, development || group != 0 else { throw .invalidConfiguration }
        }
        if !development {
            guard Set([brokerUID, read.clientUID, admin.clientUID]).count == 3 else { throw .invalidConfiguration }
        }
        let expected = switch role {
        case .broker: brokerUID
        case .readClient: read.clientUID
        case .adminClient: admin.clientUID
        }
        guard effectiveUID == expected else { throw .invalidConfiguration }
    }

    /// An absolute, normalized path of portable characters that fits every `sun_path`.
    static func isSocketPath(_ path: String) -> Bool {
        guard (2...103).contains(path.utf8.count), path.hasPrefix("/") else { return false }
        let components = path.utf8.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false).dropFirst()
        return components.allSatisfy { component in
            !component.isEmpty && !component.allSatisfy { $0 == UInt8(ascii: ".") }
                && component.allSatisfy {
                    (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0)
                        || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
                        || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: "_")
                }
        }
    }
}

/// Configuration files that name peers or keys.
enum ProtectedFile {
    /// Bytes and status of a regular file, opened without following a final symlink.
    static func contents(atPath path: String, maxBytes: Int) throws(IPCError) -> (Data, stat) {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw .invalidConfiguration }
        defer { close(descriptor) }
        var file = stat()
        guard fstat(descriptor, &file) == 0, (file.st_mode & S_IFMT) == S_IFREG,
              (1...Int64(maxBytes)).contains(Int64(file.st_size)) else { throw .invalidConfiguration }
        var data = Data(count: Int(file.st_size))
        let count = data.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
        guard count == Int(file.st_size) else { throw .invalidConfiguration }
        return (data, file)
    }

    /// Root-owned and not group/other writable, in a root-owned directory with the same property.
    static func requireProtected(_ file: stat, path: String) throws(IPCError) {
        var directory = stat()
        guard file.st_uid == 0, file.st_mode & 0o022 == 0,
              lstat(parent(of: path), &directory) == 0, (directory.st_mode & S_IFMT) == S_IFDIR,
              directory.st_uid == 0, directory.st_mode & 0o022 == 0 else {
            throw .invalidConfiguration
        }
    }

    /// The directory part of `path`, as `dirname(3)` computes it for the paths used here.
    static func parent(of path: String) -> String {
        guard let slash = path.lastIndex(of: "/") else { return "." }
        return slash == path.startIndex ? "/" : String(path[..<slash])
    }
}
