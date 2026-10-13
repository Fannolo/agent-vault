import Foundation
import Security

/// Identity policy shared by the broker and its two client roles.
///
/// The broker enforces `readRequirement` on the read service and `adminRequirement` on the
/// admin service, and accepts only peers whose kernel effective UID is `allowedUID`.
/// Clients enforce `brokerRequirement` and `brokerUID` on every reply.
public struct IPCConfiguration: Codable, Sendable, Equatable {
    public var readServiceName: String
    public var adminServiceName: String
    public var brokerRequirement: String
    public var readRequirement: String
    public var adminRequirement: String
    public var brokerUID: UInt32
    public var allowedUID: UInt32
    public var development: Bool

    public init(readServiceName: String, adminServiceName: String, brokerRequirement: String,
                readRequirement: String, adminRequirement: String, brokerUID: UInt32,
                allowedUID: UInt32, development: Bool) {
        self.readServiceName = readServiceName; self.adminServiceName = adminServiceName
        self.brokerRequirement = brokerRequirement; self.readRequirement = readRequirement
        self.adminRequirement = adminRequirement; self.brokerUID = brokerUID
        self.allowedUID = allowedUID; self.development = development
    }

    public enum Role: Sendable { case broker, readClient, adminClient }

    /// Reads a configuration file without following a final symlink and rejects unknown keys.
    ///
    /// A production configuration must be a root-owned regular file that group and others
    /// cannot write, in a root-owned directory that group and others cannot write. Otherwise a
    /// same-user process could repoint a client at its own service or requirement.
    public static func load(contentsOf path: String) throws(IPCError) -> IPCConfiguration {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw .invalidConfiguration }
        defer { close(descriptor) }
        var file = stat()
        guard fstat(descriptor, &file) == 0, (file.st_mode & S_IFMT) == S_IFREG,
              (1...16_384).contains(file.st_size) else { throw .invalidConfiguration }
        var data = Data(count: Int(file.st_size))
        let count = data.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
        guard count == Int(file.st_size) else { throw .invalidConfiguration }

        let keys: Set<String> = ["readServiceName", "adminServiceName", "brokerRequirement", "readRequirement",
                                 "adminRequirement", "brokerUID", "allowedUID", "development"]
        let decoder = JSONDecoder()
        guard let tree = try? decoder.decode(JSONTree.self, from: data),
              Shape.object(required: keys).admits(tree),
              let configuration = try? decoder.decode(IPCConfiguration.self, from: data) else {
            throw .invalidConfiguration
        }
        if !configuration.development {
            var directory = stat()
            let parent = (path as NSString).deletingLastPathComponent
            guard file.st_uid == 0, file.st_mode & (S_IWGRP | S_IWOTH) == 0,
                  lstat(parent.isEmpty ? "." : parent, &directory) == 0, (directory.st_mode & S_IFMT) == S_IFDIR,
                  directory.st_uid == 0, directory.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
                throw .invalidConfiguration
            }
        }
        return configuration
    }

    /// Validates the policy for the process that will use it.
    ///
    /// Root is refused in every mode. Production also refuses a broker UID equal to the client
    /// UID. Development requirements must pin a cdhash; production requirements must be
    /// Apple-anchored and bound to an identifier and a team. Requirements are pure conjunctions.
    public func validate(for role: Role, effectiveUID: UInt32 = UInt32(geteuid())) throws(IPCError) {
        guard Self.isServiceName(readServiceName), Self.isServiceName(adminServiceName),
              readServiceName != adminServiceName else { throw .invalidConfiguration }
        let requirements = [brokerRequirement, readRequirement, adminRequirement]
        guard Set(requirements).count == 3 else { throw .invalidConfiguration }
        for text in requirements {
            guard let canonical = Self.canonicalRequirement(text),
                  Self.isConjunction(canonical), satisfiesModePin(canonical) else {
                throw .invalidConfiguration
            }
        }
        guard brokerUID != 0, allowedUID != 0, effectiveUID != 0,
              brokerUID != UInt32.max, allowedUID != UInt32.max else { throw .invalidConfiguration }
        if !development && brokerUID == allowedUID { throw .invalidConfiguration }
        let expected = role == .broker ? brokerUID : allowedUID
        guard effectiveUID == expected else { throw .invalidConfiguration }
    }

    private func satisfiesModePin(_ canonical: String) -> Bool {
        if development { return canonical.contains("cdhash H\"") }
        return canonical.contains("anchor apple generic") && canonical.contains("identifier \"")
            && canonical.contains("certificate leaf[subject.OU] = ")
    }

    private static func isServiceName(_ name: String) -> Bool {
        guard (3...128).contains(name.utf8.count), name.contains("."),
              let first = name.utf8.first, isAlphanumeric(first) else { return false }
        return name.utf8.allSatisfy { isAlphanumeric($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") }
    }

    private static func isAlphanumeric(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
            || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }

    /// Compiles the requirement with Security.framework and returns its canonical text.
    static func canonicalRequirement(_ text: String) -> String? {
        guard !text.isEmpty, text.utf8.count <= 2048 else { return nil }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return nil }
        var canonical: CFString?
        guard SecRequirementCopyString(requirement, [], &canonical) == errSecSuccess,
              let canonical else { return nil }
        return canonical as String
    }

    /// Rejects disjunctions, negations and constant clauses, which could weaken a pin.
    static func isConjunction(_ canonical: String) -> Bool {
        let tokens = canonical.split(whereSeparator: { $0 == " " || $0 == "(" || $0 == ")" })
        return !tokens.contains { $0 == "or" || $0 == "always" || $0 == "never" || $0.hasPrefix("!") }
            && !canonical.contains("||")
    }
}
