import CPrivateFiles

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct FileIdentity: Equatable {
    let device: UInt64
    let inode: UInt64

    init(_ status: stat) {
        device = UInt64(truncatingIfNeeded: status.st_dev)
        inode = UInt64(truncatingIfNeeded: status.st_ino)
    }
}

/// Owner, mode, type, ACL and link checks for the private root and its files. These checks
/// protect against other UIDs; a same-UID process can always defeat them.
enum PrivateFiles {
    static let typeMask: UInt32 = 0o170000
    static let directoryType: UInt32 = 0o040000
    static let regularType: UInt32 = 0o100000
    static let symlinkType: UInt32 = 0o120000

    /// The root must be canonical, a directory owned by this effective UID with mode 0700,
    /// ACL-free; ancestors must be root- or self-owned, with no ACL write grants and no
    /// mode write access for others unless sticky. Unsupported ACL inspection locks.
    static func validateRoot(_ path: String) throws(PersistenceError) {
        var status = stat()
        guard lstat(path, &status) == 0 else { throw .system(.root, errno: errno) }
        let mode = UInt32(status.st_mode)
        if mode & typeMask == symlinkType { throw .locked(.unsafeFile(.root, .symlink)) }
        guard mode & typeMask == directoryType else { throw .locked(.unsafeFile(.root, .wrongType)) }
        guard canonical(path) == path else { throw .locked(.unsafeFile(.root, .notCanonical)) }
        guard status.st_uid == geteuid() else { throw .locked(.unsafeFile(.root, .owner)) }
        guard mode & 0o7777 == 0o700 else { throw .locked(.unsafeFile(.root, .mode)) }
        try validateDirectoryACL(path, status: status, role: .root)
        var ancestor = parent(of: path)
        while true {
            guard lstat(ancestor, &status) == 0 else { throw .system(.root, errno: errno) }
            let mode = UInt32(status.st_mode)
            guard mode & typeMask == directoryType else { throw .locked(.unsafeFile(.ancestor, .wrongType)) }
            guard status.st_uid == 0 || status.st_uid == geteuid() else {
                throw .locked(.unsafeFile(.ancestor, .owner))
            }
            guard mode & 0o022 == 0 || mode & 0o1000 != 0 else {
                throw .locked(.unsafeFile(.ancestor, .writableByOthers))
            }
            try validateDirectoryACL(ancestor, status: status, role: .ancestor)
            if ancestor == "/" { return }
            ancestor = parent(of: ancestor)
        }
    }

    /// `nil` when absent. Present files must be single-link 0600 regular files of this UID.
    static func validateFile(_ path: String, role: FileRole) throws(PersistenceError) -> FileIdentity? {
        var status = stat()
        guard lstat(path, &status) == 0 else {
            if errno == ENOENT { return nil }
            throw .system(.root, errno: errno)
        }
        try validate(status, role: role)
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw .locked(.unsafeFile(role, .aclUnavailable)) }
        defer { close(descriptor) }
        let identity = try validateDescriptor(descriptor, role: role)
        var named = stat()
        guard identity == FileIdentity(status), lstat(path, &named) == 0,
              FileIdentity(named) == identity else { throw .locked(.unsafeFile(role, .replaced)) }
        return identity
    }

    static func validateDescriptor(_ descriptor: Int32, role: FileRole) throws(PersistenceError) -> FileIdentity {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else { throw .locked(.unsafeFile(role, .replaced)) }
        try validate(status, role: role)
        try validateACL(descriptor, role: role)
        return FileIdentity(status)
    }

    private static func validateDirectoryACL(_ path: String, status: stat, role: FileRole) throws(PersistenceError) {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw .locked(.unsafeFile(role, .aclUnavailable)) }
        defer { close(descriptor) }
        var opened = stat(), named = stat()
        guard fstat(descriptor, &opened) == 0, FileIdentity(opened) == FileIdentity(status),
              opened.st_mode == status.st_mode, opened.st_uid == status.st_uid,
              lstat(path, &named) == 0, FileIdentity(named) == FileIdentity(opened), named.st_mode == opened.st_mode,
              named.st_uid == opened.st_uid else {
            throw .locked(.unsafeFile(role, .replaced))
        }
        try validateACL(descriptor, role: role)
    }

    private static func validateACL(_ descriptor: Int32, role: FileRole) throws(PersistenceError) {
        switch av_check_acl(descriptor, role == .ancestor ? 1 : 0) {
        case 0: return
        case 1: throw .locked(.unsafeFile(role, .acl))
        default: throw .locked(.unsafeFile(role, .aclUnavailable))
        }
    }

    private static func validate(_ status: stat, role: FileRole) throws(PersistenceError) {
        let mode = UInt32(status.st_mode)
        if mode & typeMask == symlinkType { throw .locked(.unsafeFile(role, .symlink)) }
        guard mode & typeMask == regularType else { throw .locked(.unsafeFile(role, .wrongType)) }
        guard status.st_uid == geteuid() else { throw .locked(.unsafeFile(role, .owner)) }
        guard mode & 0o7777 == 0o600 else { throw .locked(.unsafeFile(role, .mode)) }
        guard status.st_nlink == 1 else { throw .locked(.unsafeFile(role, .linkCount)) }
    }

    /// Creates an empty 0600 file that must not already exist, and makes it durable.
    static func createExclusive(_ path: String) throws(PersistenceError) {
        let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else {
            if errno == EEXIST { throw .refused(.rootNotEmpty) }
            throw .system(.createFile, errno: errno)
        }
        defer { close(descriptor) }
        guard fchmod(descriptor, 0o600) == 0 else { throw .system(.createFile, errno: errno) }
        guard fullSync(descriptor) else { throw .system(.sync, errno: errno) }
    }

    static func syncDirectory(_ path: String) throws(PersistenceError) {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw .system(.sync, errno: errno) }
        defer { close(descriptor) }
        guard fullSync(descriptor) else { throw .system(.sync, errno: errno) }
    }

    /// macOS `fsync` does not flush the drive cache; use F_FULLFSYNC as SQLite does, falling
    /// back to `fsync` where the filesystem does not support it.
    static func fullSync(_ descriptor: Int32) -> Bool {
        #if canImport(Darwin)
        if fcntl(descriptor, F_FULLFSYNC) == 0 { return true }
        #endif
        return fsync(descriptor) == 0
    }

    static func canonical(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    static func parent(of path: String) -> String {
        guard let slash = path.lastIndex(of: "/"), slash != path.startIndex else { return "/" }
        return String(path[..<slash])
    }
}

/// One process-lifetime exclusive lease on a stable lock inode inside the private root.
/// The file is never renamed or deleted; closing the descriptor (or process death) releases it.
final class ProcessLease {
    private let descriptor: Int32
    private let path: String
    private let identity: FileIdentity

    private init(descriptor: Int32, path: String, identity: FileIdentity) {
        self.descriptor = descriptor
        self.path = path
        self.identity = identity
    }

    deinit { close(descriptor) }

    static func acquire(path: String, creating: Bool) throws(PersistenceError) -> ProcessLease {
        var flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC
        if creating { flags |= O_CREAT | O_EXCL }
        let descriptor = open(path, flags, mode_t(0o600))
        guard descriptor >= 0 else {
            switch errno {
            case ENOENT: throw .locked(.missingLease)
            case ELOOP: throw .locked(.unsafeFile(.lease, .symlink))
            case EEXIST where creating: throw .refused(.rootNotEmpty)
            case let code: throw .system(.lease, errno: code)
            }
        }
        do throws(PersistenceError) {
            if creating {
                guard fchmod(descriptor, 0o600) == 0 else { throw .system(.lease, errno: errno) }
                guard PrivateFiles.fullSync(descriptor) else { throw .system(.sync, errno: errno) }
            }
            let identity = try PrivateFiles.validateDescriptor(descriptor, role: .lease)
            guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
                if errno == EWOULDBLOCK { throw .busy }
                throw .system(.lease, errno: errno)
            }
            var named = stat()
            guard lstat(path, &named) == 0, FileIdentity(named) == identity else {
                throw .locked(.leaseReplaced)
            }
            return ProcessLease(descriptor: descriptor, path: path, identity: identity)
        } catch {
            close(descriptor)
            throw error
        }
    }

    /// True while the lease path still names the locked inode as a valid lease file.
    func stillNamesLockedInode() -> Bool {
        guard (try? PrivateFiles.validateDescriptor(descriptor, role: .lease)) == identity,
              (try? PrivateFiles.validateFile(path, role: .lease)) == identity else { return false }
        return true
    }
}
