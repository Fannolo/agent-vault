/// Every failure the kernel reports. Values are fixed codes: no SQL text, paths, errno
/// strings or caller bytes are ever carried.
public enum PersistenceError: Error, Equatable, Sendable, CustomStringConvertible {
    /// Another owner holds the process lease. Nothing was read from custody or state.
    case busy
    /// The installation cannot be used as found. Never repaired, created or emptied here.
    case locked(LockReason)
    /// A deterministic refusal before anything durable changed; admission stays open.
    case refused(Refusal)
    /// The outcome of a durable step is unknown or custody is uncertain. This kernel admits
    /// nothing further; drop it and run `openExisting` to apply the restart rules.
    case recoveryRequired(AmbiguousStep)
    /// A SQLite failure outside the cases above, as its extended result code.
    case sqlite(SQLiteStep, code: Int32)
    /// An operating-system failure outside the cases above, as its errno value.
    case system(SystemStep, errno: Int32)

    public var description: String {
        switch self {
        case .busy: "busy"
        case .locked(let reason): "locked(\(reason))"
        case .refused(let refusal): "refused(\(refusal.rawValue))"
        case .recoveryRequired(let step): "recoveryRequired(\(step.rawValue))"
        case .sqlite(let step, let code): "sqlite(\(step.rawValue),\(code))"
        case .system(let step, let errno): "system(\(step.rawValue),\(errno))"
        }
    }
}

public enum LockReason: Equatable, Sendable, CustomStringConvertible {
    case missingLease
    case missingDatabase
    case leaseReplaced
    case unsafeFile(FileRole, FileProblem)
    /// Custody is missing, unreadable or corrupt, or a restart transition failed.
    case custodyUnavailable
    case notEnrolled
    case incompleteEnrollment
    /// The pinned identity does not match the database: rollback, substitution or a third state.
    case pinMismatch
    case corruptDatabase
    case schemaMismatch
    case configurationRejected
    case stateCorrupt
    case objectCorrupt
    case inventoryMismatch
    case exceedsLimits
    /// The database changed underneath its single owner.
    case databaseChangedOutsideOwner

    public var description: String {
        switch self {
        case .unsafeFile(let role, let problem): "unsafeFile(\(role.rawValue),\(problem.rawValue))"
        case .missingLease: "missingLease"
        case .missingDatabase: "missingDatabase"
        case .leaseReplaced: "leaseReplaced"
        case .custodyUnavailable: "custodyUnavailable"
        case .notEnrolled: "notEnrolled"
        case .incompleteEnrollment: "incompleteEnrollment"
        case .pinMismatch: "pinMismatch"
        case .corruptDatabase: "corruptDatabase"
        case .schemaMismatch: "schemaMismatch"
        case .configurationRejected: "configurationRejected"
        case .stateCorrupt: "stateCorrupt"
        case .objectCorrupt: "objectCorrupt"
        case .inventoryMismatch: "inventoryMismatch"
        case .exceedsLimits: "exceedsLimits"
        case .databaseChangedOutsideOwner: "databaseChangedOutsideOwner"
        }
    }
}

public enum FileRole: String, Sendable {
    case root, ancestor, lease, database, journal
}

public enum FileProblem: String, Sendable {
    case notCanonical, symlink, wrongType, owner, mode, linkCount, writableByOthers, replaced
}

public enum Refusal: String, Sendable {
    case invalidLimits
    case staleHead
    case emptyState
    case stateTooLarge
    case stateUnchanged
    case emptyObject
    case objectTooLarge
    case objectCountExhausted
    case objectBytesExhausted
    case digestMismatch
    case rootNotEmpty
    case custodyNotUnenrolled
}

public enum AmbiguousStep: String, Sendable {
    case custodyPrepare, databaseWrite, databaseCommit, custodyFinish, databaseRollback, integrity
}

public enum SQLiteStep: String, Sendable {
    case open, configure, begin, read, write
}

public enum SystemStep: String, Sendable {
    case root, lease, createFile, sync
}
