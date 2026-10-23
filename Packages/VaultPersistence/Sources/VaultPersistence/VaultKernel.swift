#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// The single local owner of one vault's durable bytes: an opaque sealed state frame and
/// immutable opaque objects, committed together and acknowledged only after the custody
/// pin names the new state.
///
/// This kernel does not decrypt, validate history or decide authority. A trusted caller
/// validates before calling `commit`; a committed state is not thereby approved.
///
/// Synchronous by design: no call suspends, waits on the network, or holds a transaction
/// open across calls. The type is not `Sendable`; it belongs to one isolation domain.
public final class VaultKernel {
    public static let leaseName = "lease"
    public static let databaseName = "vault.sqlite"

    public let limits: KernelLimits
    public let settings: SQLiteSettings
    /// The last acknowledged commit.
    public private(set) var head: Head

    private var row: HeadRow
    private var current: SealedState
    private var blocked: AmbiguousStep?
    private let lease: ProcessLease
    private let database: SQLiteConnection
    private let custody: any VaultCustodyPin

    private init(limits: KernelLimits, settings: SQLiteSettings, row: HeadRow, current: SealedState,
                 lease: ProcessLease, database: SQLiteConnection, custody: any VaultCustodyPin) {
        self.limits = limits
        self.settings = settings
        self.row = row
        head = row.head
        self.current = current
        self.lease = lease
        self.database = database
        self.custody = custody
    }

    /// First installation only. Requires an empty private root and custody provisioned as
    /// `.unenrolled`. An interrupted create is left locked for the enrollment flow.
    public static func create(root: String, initial: SealedState, custody: any VaultCustodyPin,
                              limits: KernelLimits = .standard) throws(PersistenceError) -> VaultKernel {
        try validate(initial, limits)
        try PrivateFiles.validateRoot(root)
        let paths = Paths(root)
        for path in [paths.lease, paths.database, paths.journal] {
            var status = stat()
            guard lstat(path, &status) != 0, errno == ENOENT else { throw .refused(.rootNotEmpty) }
        }
        let record: PinRecord
        do { record = try custody.read() } catch { throw .locked(.custodyUnavailable) }
        guard record == .unenrolled else { throw .refused(.custodyNotUnenrolled) }

        let lease = try ProcessLease.acquire(path: paths.lease, creating: true)
        let database = try SQLiteConnection.open(path: paths.database, mode: .create)
        try PrivateFiles.syncDirectory(root)
        let settings = try database.configure(limits: limits)
        try database.beginImmediate()
        do throws(PersistenceError) {
            try database.createSchema(initial: initial)
        } catch {
            _ = database.rollbackIfOpen()
            throw error
        }
        do { try custody.beginEnrollment(initial.id) } catch {
            _ = database.rollbackIfOpen()
            throw .recoveryRequired(.custodyPrepare)
        }
        do throws(PersistenceError) { try database.commitTransaction() } catch {
            _ = database.rollbackIfOpen()
            throw .recoveryRequired(.databaseCommit)
        }
        do { try custody.finish(initial.id) } catch { throw .recoveryRequired(.custodyFinish) }
        let row = HeadRow(head: Head(generation: 0, state: initial.id), objectCount: 0, objectBytes: 0)
        return VaultKernel(limits: limits, settings: settings, row: row, current: initial,
                           lease: lease, database: database, custody: custody)
    }

    /// Opens an enrolled installation and applies the restart rules. Never creates a lease,
    /// database, schema, state or pin; anything missing or inconsistent is `.locked`.
    public static func openExisting(root: String, custody: any VaultCustodyPin,
                                    limits: KernelLimits = .standard) throws(PersistenceError) -> VaultKernel {
        try PrivateFiles.validateRoot(root)
        let paths = Paths(root)
        let lease = try ProcessLease.acquire(path: paths.lease, creating: false)
        let record: PinRecord
        do { record = try custody.read() } catch { throw .locked(.custodyUnavailable) }
        switch record {
        case .unenrolled: throw .locked(.notEnrolled)
        case .enrolling: throw .locked(.incompleteEnrollment)
        case .stable, .pending: break
        }
        let database = try SQLiteConnection.open(path: paths.database, mode: .existing)
        let settings = try database.configure(limits: limits)
        let (row, state) = try database.loadImage(limits: limits)
        let found = row.head.state
        switch record {
        case .stable(let pinned) where pinned == found:
            break
        case .pending(_, let next) where next == found:
            // The commit reached the database but was never acknowledged: finish it.
            do { try custody.finish(next) } catch { throw .locked(.custodyUnavailable) }
        case .pending(let stable, _) where stable == found:
            // The commit never reached the database: abandon it, never replay it.
            do { try custody.abort(retaining: stable) } catch { throw .locked(.custodyUnavailable) }
        default:
            throw .locked(.pinMismatch)
        }
        return VaultKernel(limits: limits, settings: settings, row: row, current: state,
                           lease: lease, database: database, custody: custody)
    }

    /// The current sealed frame. Unavailable once admission is blocked.
    public func state() throws(PersistenceError) -> SealedState {
        if let blocked { throw .recoveryRequired(blocked) }
        return current
    }

    /// The stored bytes for `digest`, rehashed on every read.
    public func object(_ digest: ObjectDigest) throws(PersistenceError) -> SignedObject? {
        if let blocked { throw .recoveryRequired(blocked) }
        guard let bytes = try database.storedObject(digest) else { return nil }
        let object = SignedObject(bytes: bytes)
        guard object.digest == digest else {
            blocked = .integrity
            throw .locked(.objectCorrupt)
        }
        return object
    }

    /// Atomically replaces the state and admits `objects`, then moves the pin. Returning is
    /// the acknowledgment; any thrown error means the commit was not acknowledged.
    public func commit(expecting expected: Head, next: SealedState,
                       adding objects: [SignedObject]) throws(PersistenceError) -> Head {
        if let blocked { throw .recoveryRequired(blocked) }
        guard expected == head else { throw .refused(.staleHead) }
        try Self.validate(next, limits)
        guard next.id != head.state else { throw .refused(.stateUnchanged) }
        var seen = Set<ObjectDigest>()
        var batch = [SignedObject]()
        for object in objects {
            guard !object.bytes.isEmpty else { throw .refused(.emptyObject) }
            guard object.bytes.count <= limits.maxObjectBytes else { throw .refused(.objectTooLarge) }
            if seen.insert(object.digest).inserted { batch.append(object) }
        }
        guard batch.count <= limits.maxObjectCount else { throw .refused(.objectCountExhausted) }
        guard head.generation < UInt64(Int64.max) else { throw .locked(.exceedsLimits) }
        let generation = head.generation + 1

        do throws(PersistenceError) { try database.beginImmediate() } catch {
            blocked = .databaseWrite
            throw .recoveryRequired(.databaseWrite)
        }
        let staged: HeadRow
        do throws(PersistenceError) {
            guard lease.stillNamesLockedInode() else { throw .locked(.leaseReplaced) }
            guard try database.readHead() == row else { throw .locked(.databaseChangedOutsideOwner) }
            var added = [SignedObject]()
            for object in batch {
                switch try database.storedObject(object.digest) {
                case nil: added.append(object)
                case let stored? where stored == object.bytes: continue  // exact duplicate
                default: throw .locked(.objectCorrupt)                    // substituted row
                }
            }
            let count = row.objectCount + added.count
            let bytes = added.reduce(row.objectBytes) { $0 + $1.bytes.count }
            guard count <= limits.maxObjectCount else { throw .refused(.objectCountExhausted) }
            guard bytes <= limits.maxTotalObjectBytes else { throw .refused(.objectBytesExhausted) }
            for object in added { try database.insert(object, generation: generation) }
            staged = HeadRow(head: Head(generation: generation, state: next.id), objectCount: count, objectBytes: bytes)
            try database.replaceHead(from: row, to: staged, state: next)
        } catch {
            let rolledBack = database.rollbackIfOpen()
            if case .locked = error { blocked = .integrity }
            else if case .sqlite = error { blocked = .databaseWrite }
            else if !rolledBack { blocked = .databaseRollback }
            if let blocked, blocked != .integrity { throw .recoveryRequired(blocked) }
            throw error
        }
        do { try custody.prepare(from: head.state, to: next.id) } catch {
            blocked = .custodyPrepare
            _ = database.rollbackIfOpen()
            throw .recoveryRequired(.custodyPrepare)
        }
        do throws(PersistenceError) { try database.commitTransaction() } catch {
            blocked = .databaseCommit
            _ = database.rollbackIfOpen()
            throw .recoveryRequired(.databaseCommit)
        }
        do { try custody.finish(next.id) } catch {
            blocked = .custodyFinish
            throw .recoveryRequired(.custodyFinish)
        }
        row = staged
        head = staged.head
        current = next
        return head
    }

    private static func validate(_ state: SealedState, _ limits: KernelLimits) throws(PersistenceError) {
        guard !state.frame.isEmpty else { throw .refused(.emptyState) }
        guard state.frame.count <= limits.maxStateBytes else { throw .refused(.stateTooLarge) }
    }
}

private struct Paths {
    let lease: String
    let database: String
    let journal: String

    init(_ root: String) {
        lease = root + "/" + VaultKernel.leaseName
        database = root + "/" + VaultKernel.databaseName
        journal = database + "-journal"
    }
}
