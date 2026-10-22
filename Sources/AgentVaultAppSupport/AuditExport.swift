import Foundation
import Darwin

public enum AuditExport {
    private struct Row: Encodable {
        let timestamp: Date
        let clientID: UUID
        let accountID: UUID?
        let action: String?
        let outcome: String
    }

    /// JSON array of the five safe metadata fields, oldest first, with ISO 8601 timestamps.
    public static func json(_ entries: [AuditEntry]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let rows = entries.sorted { $0.timestamp < $1.timestamp }.map {
            Row(timestamp: $0.timestamp, clientID: $0.clientID, accountID: $0.accountID, action: $0.action, outcome: $0.outcome)
        }
        return try encoder.encode(rows)
    }

    /// Writes with owner-only permissions; replaces an existing file atomically.
    public static func write(_ entries: [AuditEntry], to url: URL) throws {
        let data = try json(entries)
        guard url.isFileURL else { throw CocoaError(.fileWriteInvalidFileName) }
        let parent = url.deletingLastPathComponent()
        let dir = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dir >= 0 else { throw CocoaError(.fileWriteNoPermission) }
        defer { close(dir) }
        let name = ".agent-vault-audit-\(UUID()).tmp"
        let fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteNoPermission) }
        defer { close(fd); unlinkat(dir, name, 0) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw CocoaError(.fileWriteUnknown) }
                offset += count
            }
        }
        guard fsync(fd) == 0, renameat(dir, name, dir, url.lastPathComponent) == 0, fsync(dir) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
    }
}
