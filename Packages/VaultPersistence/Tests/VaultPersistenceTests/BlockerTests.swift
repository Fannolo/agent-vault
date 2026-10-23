import Foundation
import Crypto
import Testing
@testable import VaultPersistence
import VaultPersistenceTestSupport
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

@Test func reusedFrameCannotHideAcknowledgedObjects() throws {
    let box = try Sandbox()
    _ = try box.create()
    let oldDatabase = box.bytes(box.database)
    let object = SignedObject(bytes: [41, 42, 43])
    do {
        let kernel = try box.open()
        _ = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: [object])
        _ = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 1), adding: [])
        #expect(kernel.head.generation == 2 && kernel.head.state == Synthetic.state(seed: 1).id)
        #expect(try kernel.object(object.digest) == object)
    }
    let currentPin = box.bytes(box.pinDirectory + "/pin")
    box.overwrite(box.database, oldDatabase)
    #expect(failure { try box.open() } == .locked(.pinMismatch),
            "NAMED: reused frame cannot hide acknowledged objects")
    #expect(box.bytes(box.pinDirectory + "/pin") == currentPin)
}

@Test func sqliteObjectReadCorruptionBlocksOwner() throws {
    let box = try Sandbox()
    let kernel = try box.create()
    let object = SignedObject(bytes: [31, 32, 33])
    _ = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: [object])
    let head = kernel.head
    let pin = box.bytes(box.pinDirectory + "/pin")
    let offset = try RawDatabase.objectPageOffset(box.database)
    let fd = open(box.database, O_WRONLY | O_NOFOLLOW)
    defer { close(fd) }
    #expect(fd >= 0)
    var invalidPageType: UInt8 = 0
    #expect(pwrite(fd, &invalidPageType, 1, off_t(offset)) == 1)
    #expect(fsync(fd) == 0)
    // Change SQLite's file change counter via a separate connection so the live owner
    // discards its cached object page. Head values stay identical. No fake digest fault.
    try RawDatabase.execute(box.database, "PRAGMA user_version = 1")
    #expect(failure { try kernel.object(object.digest) } == .locked(.corruptDatabase),
            "NAMED: physical object page reaches SQLite read corruption")
    #expect(failure { try kernel.state() } == .recoveryRequired(.integrity),
            "NAMED: caught SQLite corruption blocks state")
    #expect(failure { try kernel.object(object.digest) } == .recoveryRequired(.integrity),
            "NAMED: caught SQLite corruption blocks object")
    #expect(failure { try kernel.commit(expecting: head, next: Synthetic.state(seed: 3), adding: []) }
            == .recoveryRequired(.integrity), "NAMED: caught SQLite corruption cannot acknowledge")
    #expect(kernel.head == head && box.bytes(box.pinDirectory + "/pin") == pin,
            "NAMED: corrupt read preserves acknowledged head and pin")
}

@Test func pendingCannotMatchOnlyFrameHash() throws {
    let box = try Sandbox()
    _ = try box.create()
    let original = box.bytes(box.database)
    var latest: Head
    do {
        let kernel = try box.open()
        _ = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: [SignedObject(bytes: [7])])
        latest = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 1), adding: [])
    }
    let future = Head(generation: 3, state: Synthetic.state(seed: 2).id)
    box.overwrite(box.database, original)
    for record: PinRecord in [.pending(stable: latest, next: future),
                              .pending(stable: future, next: latest)] {
        try TestOnlyFileCustodyPin.overwrite(directory: box.pinDirectory, with: record)
        #expect(failure { try box.open() } == .locked(.pinMismatch),
                "NAMED: pending compares generation and frame hash")
        #expect(try box.pinRecord() == record, "NAMED: mismatched pending stays untouched")
    }
}

@Test func pinSerializationBindsGenerationAndRejectsLegacy() throws {
    let box = try Sandbox()
    let state = Synthetic.state(seed: 1).id
    let a = Head(generation: 0, state: state)
    let b = Head(generation: 0x0102030405060708, state: state)
    for record: PinRecord in [.unenrolled, .enrolling(a), .stable(b), .pending(stable: a, next: b)] {
        try TestOnlyFileCustodyPin.overwrite(directory: box.pinDirectory, with: record)
        #expect(try box.pinRecord() == record, "NAMED: pin full-head round trip")
    }
    let raw = box.bytes(box.pinDirectory + "/pin")
    #expect(raw.count == 121 && Array(raw.prefix(8)) == Array("AVTPIN02".utf8))
    #expect(Array(raw[49..<57]) == [1, 2, 3, 4, 5, 6, 7, 8], "NAMED: pin encodes all generation bytes")
    #expect(Array(raw[17..<49]) == Array(raw[57..<89]), "NAMED: reused frame retains same opaque hash")
    let legacy = Array("AVTPIN01".utf8) + [2] + state.bytes + [UInt8](repeating: 0, count: 32)
    box.overwrite(box.pinDirectory + "/pin", legacy + Array(SHA256.hash(data: legacy)))
    #expect(throws: TestOnlyFileCustodyPin.Failure.self) { try box.pinRecord() }
}

@Test func unavailableACLInspectionFailsClosed() throws {
    #expect(failure { try PrivateFiles.validateDescriptor(-1, role: .lease) }
            == .locked(.unsafeFile(.lease, .replaced)), "NAMED: invalid descriptor cannot verify privacy")
}

#if canImport(Darwin)
/// Only writes ACLs on this test's newly created owned paths. No shell/chmod subprocess.
private func setFixtureACL(_ path: String, allow: Bool, permissions: [acl_perm_t]) throws {
    var acl = acl_init(1)
    defer { acl_free(acl.map(UnsafeMutableRawPointer.init)) }
    var entry: acl_entry_t?
    guard acl != nil, acl_create_entry(&acl, &entry) == 0, let entry,
          acl_set_tag_type(entry, allow ? ACL_EXTENDED_ALLOW : ACL_EXTENDED_DENY) == 0 else {
        throw POSIXError(.EIO)
    }
    // Darwin membership.h's documented UID UUID prefix, for a different non-root
    // numeric UID. No account lookup, creation, UID switch or credential access.
    let uid: UInt32 = geteuid() == 12345 ? 12346 : 12345
    var other = uuid_t(0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc,
                       0xbb, 0xbb, 0xaa, 0xaa, UInt8(truncatingIfNeeded: uid >> 24),
                       UInt8(truncatingIfNeeded: uid >> 16), UInt8(truncatingIfNeeded: uid >> 8),
                       UInt8(truncatingIfNeeded: uid))
    guard acl_set_qualifier(entry, &other) == 0 else { throw POSIXError(.EIO) }
    var set: acl_permset_t?
    guard acl_get_permset(entry, &set) == 0, let set else { throw POSIXError(.EIO) }
    for permission in permissions {
        guard acl_add_perm(set, permission) == 0 else { throw POSIXError(.EIO) }
    }
    guard acl_set_file(path, ACL_TYPE_EXTENDED, acl) == 0 else { throw POSIXError(.EIO) }
}

private func removeFixtureACL(_ path: String) {
    let empty = acl_init(0)
    defer { acl_free(empty.map(UnsafeMutableRawPointer.init)) }
    #expect(acl_set_file(path, ACL_TYPE_EXTENDED, empty) == 0)
}

@Test(arguments: ["root", "database", "lease", "journal"])
func darwinPrivateACLsRejected(role: String) throws {
    let box = try Sandbox()
    _ = try box.create()
    let path = role == "root" ? box.root : role == "database" ? box.database : role == "lease" ? box.lease : box.journal
    if role == "journal" {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        #expect(fd >= 0)
        close(fd)
    }
    try setFixtureACL(path, allow: true, permissions: [ACL_READ_DATA, ACL_WRITE_DATA, ACL_EXECUTE, ACL_DELETE_CHILD])
    defer { removeFixtureACL(path) }
    #expect(box.mode(path) == (role == "root" ? 0o700 : 0o600), "NAMED: ACL bypass retains private mode")
    let error = failure { try box.open() }
    let fileRole: FileRole = role == "root" ? .root : role == "database" ? .database : role == "lease" ? .lease : .journal
    #expect(error == .locked(.unsafeFile(fileRole, .acl)), "NAMED: private boundary rejects native extended ACL")
}

@Test func darwinAncestorACLWriteRejected() throws {
    let box = try Sandbox()
    _ = try box.create()
    try setFixtureACL(box.base, allow: true, permissions: [ACL_ADD_FILE, ACL_DELETE_CHILD, ACL_WRITE_SECURITY])
    defer { removeFixtureACL(box.base) }
    #expect(box.mode(box.base) == 0o700)
    let error = failure { try box.open() }
    #expect(error == .locked(.unsafeFile(.ancestor, .acl)), "NAMED: ancestor rejects native ACL write grant")
}

@Test func darwinLeaseACLChangeBlocksCommit() throws {
    let box = try Sandbox()
    let kernel = try box.create()
    try setFixtureACL(box.lease, allow: true, permissions: [ACL_WRITE_DATA])
    defer { removeFixtureACL(box.lease) }
    let fd = open(box.lease, O_RDONLY | O_NOFOLLOW)
    defer { close(fd) }
    #expect(failure { try PrivateFiles.validateDescriptor(fd, role: .lease) }
            == .locked(.unsafeFile(.lease, .acl)), "NAMED: descriptor rejects native ACL")
    #expect(failure { try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: []) }
            == .locked(.leaseReplaced), "NAMED: lease ACL change blocks commit")
    #expect(failure { try kernel.state() } == .recoveryRequired(.integrity))
}

@Test func darwinPrivateDenyACLRejected() throws {
    let box = try Sandbox()
    _ = try box.create()
    try setFixtureACL(box.root, allow: false, permissions: [ACL_DELETE])
    defer { removeFixtureACL(box.root) }
    #expect(failure { try box.open() } == .locked(.unsafeFile(.root, .acl)),
            "NAMED: private boundary requires ACL-free root")
}

@Test func darwinAncestorDenyDeleteAllowed() throws {
    let box = try Sandbox()
    _ = try box.create()
    try setFixtureACL(box.base, allow: false, permissions: [ACL_DELETE])
    defer { removeFixtureACL(box.base) }
    let kernel = try box.open()
    _ = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: [])
    #expect(kernel.head.generation == 1, "NAMED: ancestor deny-delete is not an access grant")
}
#endif
