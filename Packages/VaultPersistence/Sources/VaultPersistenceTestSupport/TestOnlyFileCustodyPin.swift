import Crypto
import VaultPersistence
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// TEST-ONLY custody pin: one checksummed file in a separate private directory, replaced by
/// write → fsync → rename → directory fsync.
///
/// It is not installed macOS or Linux custody. It assumes, and cannot provide, that its
/// directory lies outside every backup/restore of the vault data (the non-rollback
/// assumption). Crash points and faults exist only so tests can cut a real process.
public final class TestOnlyFileCustodyPin: VaultCustodyPin {
    public enum CrashPoint: String, Sendable, CaseIterable {
        case beforePrepare, afterPrepare, beforeFinish, afterFinish
    }

    public enum Fault: String, Sendable, CaseIterable {
        case prepareBeforeWrite, prepareAfterPersist, prepareFsync, finishBeforeWrite, finishAfterPersist, finishFsync
    }

    public struct Failure: Error, Equatable {
        public let code: String
    }

    public static let fileName = "pin"
    static let magic = Array("AVTPIN02".utf8)
    static let encodedLength = 8 + 1 + 40 + 40 + 32

    private let directory: String
    public var crashAt: CrashPoint?
    public var fault: Fault?

    public init(directory: String, crashAt: CrashPoint? = nil, fault: Fault? = nil) {
        self.directory = directory
        self.crashAt = crashAt
        self.fault = fault
    }

    /// Stands in for the enrollment ceremony that provisions an empty custody slot.
    public static func provision(directory: String) throws {
        var status = stat()
        guard lstat(directory + "/" + fileName, &status) != 0, errno == ENOENT else {
            throw Failure(code: "already-provisioned")
        }
        try write(.unenrolled, directory: directory)
    }

    /// Raw record, for test assertions about the artifact itself.
    public static func load(directory: String) throws -> PinRecord {
        var status = stat()
        guard lstat(directory, &status) == 0, UInt32(status.st_mode) & 0o170000 == 0o040000,
              status.st_uid == geteuid(), UInt32(status.st_mode) & 0o7777 == 0o700 else {
            throw Failure(code: "unsafe-directory")
        }
        let descriptor = open(directory + "/" + fileName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Failure(code: "missing") }
        defer { close(descriptor) }
        guard fstat(descriptor, &status) == 0, UInt32(status.st_mode) & 0o170000 == 0o100000,
              status.st_uid == geteuid(), UInt32(status.st_mode) & 0o7777 == 0o600, status.st_nlink == 1 else {
            throw Failure(code: "unsafe-file")
        }
        var bytes = [UInt8](repeating: 0, count: encodedLength + 1)
        let count = bytes.withUnsafeMutableBytes { Glue.read(descriptor, $0.baseAddress, $0.count) }
        guard count == encodedLength else { throw Failure(code: "corrupt") }
        return try decode(Array(bytes.prefix(encodedLength)))
    }

    /// Writes an arbitrary record, bypassing transition checks: tamper tests only.
    public static func overwrite(directory: String, with record: PinRecord) throws {
        try write(record, directory: directory)
    }

    public func read() throws -> PinRecord { try Self.load(directory: directory) }

    public func beginEnrollment(_ first: Head) throws {
        guard try read() == .unenrolled else { throw Failure(code: "enroll-precondition") }
        try Self.write(.enrolling(first), directory: directory)
    }

    public func prepare(from: Head, to: Head) throws {
        crash(.beforePrepare)
        guard try read() == .stable(from) else { throw Failure(code: "prepare-precondition") }
        if fault == .prepareBeforeWrite { throw Failure(code: "injected") }
        try Self.write(.pending(stable: from, next: to), directory: directory, failSync: fault == .prepareFsync)
        if fault == .prepareAfterPersist { throw Failure(code: "injected") }
        crash(.afterPrepare)
    }

    public func finish(_ next: Head) throws {
        crash(.beforeFinish)
        switch try read() {
        case .enrolling(next), .pending(_, next): break
        default: throw Failure(code: "finish-precondition")
        }
        if fault == .finishBeforeWrite { throw Failure(code: "injected") }
        try Self.write(.stable(next), directory: directory, failSync: fault == .finishFsync)
        if fault == .finishAfterPersist { throw Failure(code: "injected") }
        crash(.afterFinish)
    }

    public func abort(retaining: Head) throws {
        guard case .pending(retaining, _) = try read() else { throw Failure(code: "abort-precondition") }
        try Self.write(.stable(retaining), directory: directory)
    }

    private func crash(_ point: CrashPoint) {
        guard crashAt == point else { return }
        kill(getpid(), SIGKILL)
        while true { pause() }
    }

    private static func encodeHead(_ head: Head) -> [UInt8] {
        (0..<8).reversed().map { UInt8(truncatingIfNeeded: head.generation >> ($0 * 8)) } + head.state.bytes
    }

    static func encode(_ record: PinRecord) -> [UInt8] {
        let zero = [UInt8](repeating: 0, count: 40)
        let (tag, first, second): (UInt8, [UInt8], [UInt8]) = switch record {
        case .unenrolled: (0, zero, zero)
        case .enrolling(let head): (1, zero, encodeHead(head))
        case .stable(let head): (2, encodeHead(head), zero)
        case .pending(let stable, let next): (3, encodeHead(stable), encodeHead(next))
        }
        let body = magic + [tag] + first + second
        return body + Array(SHA256.hash(data: body))
    }

    static func decode(_ bytes: [UInt8]) throws -> PinRecord {
        guard bytes.count == encodedLength else { throw Failure(code: "corrupt") }
        let body = Array(bytes.prefix(encodedLength - 32))
        guard Array(body.prefix(8)) == magic,
              Array(SHA256.hash(data: body)) == Array(bytes.suffix(32)) else {
            throw Failure(code: "corrupt")
        }
        func head(_ start: Int) -> Head {
            let generation = body[start..<(start + 8)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            return Head(generation: generation, state: StateID(bytes: Array(body[(start + 8)..<(start + 40)]))!)
        }
        let first = head(9), second = head(49)
        let zero = [UInt8](repeating: 0, count: 40)
        switch body[8] {
        case 0 where Array(body[9..<89]) == zero + zero: return .unenrolled
        case 1 where Array(body[9..<49]) == zero: return .enrolling(second)
        case 2 where Array(body[49..<89]) == zero: return .stable(first)
        case 3: return .pending(stable: first, next: second)
        default: throw Failure(code: "corrupt")
        }
    }

    private static func write(_ record: PinRecord, directory: String, failSync: Bool = false) throws {
        let temporary = directory + "/" + fileName + ".tmp"
        guard unlink(temporary) == 0 || errno == ENOENT else { throw Failure(code: "unlink") }
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw Failure(code: "create") }
        let bytes = encode(record)
        let written = bytes.withUnsafeBytes { Glue.write(descriptor, $0.baseAddress, $0.count) }
        let synced = fchmod(descriptor, 0o600) == 0 && written == bytes.count
            // Real failing fsync(-1), EBADF, in this test-only adapter. This is not a
            // SQLite/disk-fsync or power-loss simulation.
            && fullSync(failSync ? -1 : descriptor)
        close(descriptor)
        guard synced else { throw Failure(code: "write") }
        guard rename(temporary, directory + "/" + fileName) == 0 else { throw Failure(code: "rename") }
        let parent = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { throw Failure(code: "directory") }
        defer { close(parent) }
        guard fullSync(parent) else { throw Failure(code: "directory-sync") }
    }

    private static func fullSync(_ descriptor: Int32) -> Bool {
        #if canImport(Darwin)
        if fcntl(descriptor, F_FULLFSYNC) == 0 { return true }
        #endif
        return fsync(descriptor) == 0
    }
}

private enum Glue {
    static func write(_ descriptor: Int32, _ base: UnsafeRawPointer?, _ count: Int) -> Int {
        #if canImport(Darwin)
        Darwin.write(descriptor, base, count)
        #else
        Glibc.write(descriptor, base, count)
        #endif
    }

    static func read(_ descriptor: Int32, _ base: UnsafeMutableRawPointer?, _ count: Int) -> Int {
        #if canImport(Darwin)
        Darwin.read(descriptor, base, count)
        #else
        Glibc.read(descriptor, base, count)
        #endif
    }
}
