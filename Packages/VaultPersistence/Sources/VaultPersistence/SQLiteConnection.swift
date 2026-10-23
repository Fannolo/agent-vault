import CSQLite
import Crypto

/// Durability and safety settings, as read back from the open connection.
public struct SQLiteSettings: Sendable, Equatable {
    public let journalMode: String
    public let synchronous: Int64
    public let fullFsync: Int64
    public let foreignKeys: Int64
    public let trustedSchema: Int64
    public let tempStore: Int64
    public let loadExtension: Int32
    public let defensive: Int32

    /// DELETE journal, synchronous=EXTRA(3), fullfsync on (effective on Apple platforms),
    /// foreign keys on, untrusted schema, temp_store=MEMORY(2), extensions off, defensive on.
    public static let required = SQLiteSettings(journalMode: "delete", synchronous: 3, fullFsync: 1,
                                                foreignKeys: 1, trustedSchema: 0, tempStore: 2,
                                                loadExtension: 0, defensive: 1)
}

/// Identity of the system SQLite actually linked. A platform dependency, not a pinned source.
public struct SQLiteRuntime: Sendable {
    public let libraryVersion: String
    public let librarySourceID: String
    public let headerVersion: String
    public let headerSourceID: String
    public let compileOptions: [String]

    public static func current() -> SQLiteRuntime {
        var options = [String]()
        var index: Int32 = 0
        while let option = sqlite3_compileoption_get(index) {
            options.append(String(cString: option))
            index += 1
        }
        return SQLiteRuntime(libraryVersion: String(cString: sqlite3_libversion()),
                             librarySourceID: String(cString: sqlite3_sourceid()),
                             headerVersion: String(cString: av_sqlite_header_version()),
                             headerSourceID: String(cString: av_sqlite_header_source_id()),
                             compileOptions: options)
    }
}

enum DatabaseMode {
    case existing
    case create
}

struct HeadRow: Equatable {
    let head: Head
    let objectCount: Int
    let objectBytes: Int
}

/// The kernel's one private connection. Never handed out; no statement outlives a call.
final class SQLiteConnection {
    static let applicationID: Int64 = 0x4156_5031  // "AVP1"
    static let headTable = """
        CREATE TABLE head(singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1), \
        generation INTEGER NOT NULL CHECK (generation >= 0), \
        state_id BLOB NOT NULL CHECK (length(state_id) = 32), state BLOB NOT NULL, \
        object_count INTEGER NOT NULL CHECK (object_count >= 0), \
        object_bytes INTEGER NOT NULL CHECK (object_bytes >= 0)) STRICT
        """
    static let objectsTable = """
        CREATE TABLE objects(digest BLOB PRIMARY KEY NOT NULL CHECK (length(digest) = 32), \
        generation INTEGER NOT NULL CHECK (generation > 0), bytes BLOB NOT NULL) STRICT
        """
    static let schema: [[String?]] = [
        ["table", "head", "head", headTable],
        ["table", "objects", "objects", objectsTable],
        ["index", "sqlite_autoindex_objects_1", "objects", nil],
    ]

    private let handle: OpaquePointer

    private init(handle: OpaquePointer) { self.handle = handle }

    deinit { sqlite3_close_v2(handle) }

    static func open(path: String, mode: DatabaseMode) throws(PersistenceError) -> SQLiteConnection {
        switch mode {
        case .existing:
            guard try PrivateFiles.validateFile(path, role: .database) != nil else {
                throw .locked(.missingDatabase)
            }
        case .create:
            try PrivateFiles.createExclusive(path)
        }
        guard let before = try PrivateFiles.validateFile(path, role: .database) else {
            throw .locked(.missingDatabase)
        }
        // A hot journal is replayed by SQLite; it must be as private as the database.
        _ = try PrivateFiles.validateFile(path + "-journal", role: .journal)
        var opened: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE
            | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_PRIVATECACHE
        let code = sqlite3_open_v2(path, &opened, flags, nil)
        guard let opened else { throw failure(.open, code) }
        let connection = SQLiteConnection(handle: opened)
        guard code == SQLITE_OK else { throw failure(.open, code) }
        guard try PrivateFiles.validateFile(path, role: .database) == before else {
            throw .locked(.unsafeFile(.database, .replaced))
        }
        return connection
    }

    static func failure(_ step: SQLiteStep, _ code: Int32) -> PersistenceError {
        switch code & 0xff {
        case SQLITE_NOTADB, SQLITE_CORRUPT: .locked(.corruptDatabase)
        default: .sqlite(step, code: code)
        }
    }

    func configure(limits: KernelLimits) throws(PersistenceError) -> SQLiteSettings {
        let loadExtension = try databaseConfig(SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0)
        let defensive = try databaseConfig(SQLITE_DBCONFIG_DEFENSIVE, 1)
        _ = try databaseConfig(SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0)
        _ = try databaseConfig(SQLITE_DBCONFIG_ENABLE_TRIGGER, 0)
        _ = try databaseConfig(SQLITE_DBCONFIG_ENABLE_VIEW, 0)
        sqlite3_limit(handle, SQLITE_LIMIT_ATTACHED, 0)
        sqlite3_limit(handle, SQLITE_LIMIT_LENGTH, Int32(max(limits.maxStateBytes, limits.maxObjectBytes) + 4096))
        for pragma in ["PRAGMA journal_mode = DELETE", "PRAGMA synchronous = EXTRA", "PRAGMA fullfsync = ON",
                       "PRAGMA foreign_keys = ON", "PRAGMA trusted_schema = OFF", "PRAGMA temp_store = MEMORY"] {
            try execute(pragma, .configure)
        }
        let settings = SQLiteSettings(
            journalMode: try text("PRAGMA journal_mode", .configure) ?? "",
            synchronous: try integer("PRAGMA synchronous", .configure),
            fullFsync: try integer("PRAGMA fullfsync", .configure),
            foreignKeys: try integer("PRAGMA foreign_keys", .configure),
            trustedSchema: try integer("PRAGMA trusted_schema", .configure),
            tempStore: try integer("PRAGMA temp_store", .configure),
            loadExtension: try databaseConfig(SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, -1),
            defensive: try databaseConfig(SQLITE_DBCONFIG_DEFENSIVE, -1))
        guard settings == .required, loadExtension == 0, defensive == 1 else {
            throw .locked(.configurationRejected)
        }
        return settings
    }

    /// Writes the schema and generation-0 head inside the caller's open transaction.
    func createSchema(initial: SealedState) throws(PersistenceError) {
        try execute(Self.headTable, .write)
        try execute(Self.objectsTable, .write)
        try execute("PRAGMA application_id = \(Self.applicationID)", .write)
        try execute("PRAGMA user_version = 1", .write)
        let insert = try Statement(self, """
            INSERT INTO head(singleton, generation, state_id, state, object_count, object_bytes) \
            VALUES (1, 0, ?1, ?2, 0, 0)
            """, .write)
        try insert.bind(1, initial.id.bytes)
        try insert.bind(2, initial.frame)
        try insert.run()
    }

    /// Verifies the whole image against its own digests, totals and bounds.
    func loadImage(limits: KernelLimits) throws(PersistenceError) -> (HeadRow, SealedState) {
        guard try integer("PRAGMA application_id", .read) == Self.applicationID,
              try integer("PRAGMA user_version", .read) == 1 else { throw .locked(.schemaMismatch) }
        let schema = try Statement(self, "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name", .read)
        var rows = [[String?]]()
        while try schema.step() { rows.append((0..<4).map { schema.text(Int32($0)) }) }
        guard rows == Self.schema else { throw .locked(.schemaMismatch) }
        guard try text("PRAGMA quick_check", .read) == "ok" else { throw .locked(.corruptDatabase) }
        guard try integer("SELECT count(*) FROM head", .read) == 1 else { throw .locked(.stateCorrupt) }
        guard try integer("SELECT length(state) FROM head", .read) <= Int64(limits.maxStateBytes) else {
            throw .locked(.exceedsLimits)
        }
        let row = try readHead()
        let frame = try Statement(self, "SELECT state FROM head", .read)
        guard try frame.step() else { throw .locked(.stateCorrupt) }
        let state = SealedState(frame: frame.blob(0))
        guard !state.frame.isEmpty, state.id == row.head.state else { throw .locked(.stateCorrupt) }

        let totals = try Statement(self, """
            SELECT count(*), coalesce(sum(length(bytes)), 0), coalesce(max(length(bytes)), 0), \
            coalesce(min(length(bytes)), 1), coalesce(max(generation), 0) FROM objects
            """, .read)
        guard try totals.step() else { throw .locked(.inventoryMismatch) }
        guard totals.integer(0) == Int64(row.objectCount), totals.integer(1) == Int64(row.objectBytes),
              totals.integer(3) >= 1, totals.integer(4) <= Int64(row.head.generation) else {
            throw .locked(.inventoryMismatch)
        }
        guard row.objectCount <= limits.maxObjectCount, row.objectBytes <= limits.maxTotalObjectBytes,
              totals.integer(2) <= Int64(limits.maxObjectBytes) else { throw .locked(.exceedsLimits) }
        let objects = try Statement(self, "SELECT digest, bytes FROM objects", .read)
        while try objects.step() {
            guard ObjectDigest(digestOf: objects.blob(1)).bytes == objects.blob(0) else {
                throw .locked(.objectCorrupt)
            }
        }
        return (row, state)
    }

    func readHead() throws(PersistenceError) -> HeadRow {
        let statement = try Statement(self, """
            SELECT generation, state_id, object_count, object_bytes FROM head WHERE singleton = 1
            """, .read)
        guard try statement.step(), let state = StateID(bytes: statement.blob(1)),
              let generation = UInt64(exactly: statement.integer(0)),
              let count = Int(exactly: statement.integer(2)), count >= 0,
              let bytes = Int(exactly: statement.integer(3)), bytes >= 0 else {
            throw .locked(.stateCorrupt)
        }
        return HeadRow(head: Head(generation: generation, state: state), objectCount: count, objectBytes: bytes)
    }

    func storedObject(_ digest: ObjectDigest) throws(PersistenceError) -> [UInt8]? {
        let statement = try Statement(self, "SELECT bytes FROM objects WHERE digest = ?1", .read)
        try statement.bind(1, digest.bytes)
        return try statement.step() ? statement.blob(0) : nil
    }

    func insert(_ object: SignedObject, generation: UInt64) throws(PersistenceError) {
        let statement = try Statement(self, "INSERT INTO objects(digest, generation, bytes) VALUES (?1, ?2, ?3)", .write)
        try statement.bind(1, object.digest.bytes)
        try statement.bind(2, Int64(generation))
        try statement.bind(3, object.bytes)
        try statement.run()
    }

    func replaceHead(from previous: HeadRow, to next: HeadRow, state: SealedState) throws(PersistenceError) {
        let statement = try Statement(self, """
            UPDATE head SET generation = ?1, state_id = ?2, state = ?3, object_count = ?4, object_bytes = ?5 \
            WHERE singleton = 1 AND generation = ?6 AND state_id = ?7
            """, .write)
        try statement.bind(1, Int64(next.head.generation))
        try statement.bind(2, next.head.state.bytes)
        try statement.bind(3, state.frame)
        try statement.bind(4, Int64(next.objectCount))
        try statement.bind(5, Int64(next.objectBytes))
        try statement.bind(6, Int64(previous.head.generation))
        try statement.bind(7, previous.head.state.bytes)
        try statement.run()
        guard sqlite3_changes(handle) == 1 else { throw .locked(.databaseChangedOutsideOwner) }
    }

    func beginImmediate() throws(PersistenceError) { try execute("BEGIN IMMEDIATE", .begin) }

    func commitTransaction() throws(PersistenceError) { try execute("COMMIT", .write) }

    /// True when no transaction remains open afterwards.
    func rollbackIfOpen() -> Bool {
        if sqlite3_get_autocommit(handle) != 0 { return true }
        _ = try? execute("ROLLBACK", .write)
        return sqlite3_get_autocommit(handle) != 0
    }

    func execute(_ sql: String, _ step: SQLiteStep) throws(PersistenceError) {
        let statement = try Statement(self, sql, step)
        while try statement.step() {}
    }

    private func integer(_ sql: String, _ step: SQLiteStep) throws(PersistenceError) -> Int64 {
        let statement = try Statement(self, sql, step)
        guard try statement.step() else { throw .locked(.schemaMismatch) }
        return statement.integer(0)
    }

    private func text(_ sql: String, _ step: SQLiteStep) throws(PersistenceError) -> String? {
        let statement = try Statement(self, sql, step)
        guard try statement.step() else { return nil }
        return statement.text(0)
    }

    private func databaseConfig(_ option: Int32, _ value: Int32) throws(PersistenceError) -> Int32 {
        // Apple's system SQLite compiles extension loading out. In that build this
        // db_config opcode itself returns SQLITE_MISUSE; the compile option is the
        // stronger, read-back evidence that loading cannot be enabled at all.
        if option == SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
           sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1,
           value == 0 || value == -1 { return 0 }
        var current: Int32 = -1
        let code = av_sqlite_db_config_int(handle, option, value, &current)
        guard code == SQLITE_OK else { throw .sqlite(.configure, code: code) }
        return current
    }

    fileprivate func prepare(_ sql: String, _ step: SQLiteStep) throws(PersistenceError) -> OpaquePointer {
        var statement: OpaquePointer?
        let code = sqlite3_prepare_v3(handle, sql, -1, 0, &statement, nil)
        guard code == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            throw Self.failure(step, code)
        }
        return statement
    }
}

private final class Statement {
    private let pointer: OpaquePointer
    private let phase: SQLiteStep

    init(_ connection: SQLiteConnection, _ sql: String, _ step: SQLiteStep) throws(PersistenceError) {
        pointer = try connection.prepare(sql, step)
        phase = step
    }

    deinit { sqlite3_finalize(pointer) }

    /// Binds a nonempty blob; empty arrays would bind NULL, which the schema refuses.
    func bind(_ index: Int32, _ bytes: [UInt8]) throws(PersistenceError) {
        let code = bytes.withUnsafeBytes {
            sqlite3_bind_blob(pointer, index, $0.baseAddress, Int32($0.count), av_sqlite_transient())
        }
        guard code == SQLITE_OK else { throw SQLiteConnection.failure(phase, code) }
    }

    func bind(_ index: Int32, _ value: Int64) throws(PersistenceError) {
        let code = sqlite3_bind_int64(pointer, index, value)
        guard code == SQLITE_OK else { throw SQLiteConnection.failure(phase, code) }
    }

    func step() throws(PersistenceError) -> Bool {
        let code = sqlite3_step(pointer)
        if code == SQLITE_ROW { return true }
        if code == SQLITE_DONE { return false }
        throw SQLiteConnection.failure(phase, code)
    }

    func run() throws(PersistenceError) {
        guard try !step() else { throw .sqlite(phase, code: SQLITE_MISUSE) }
    }

    func integer(_ column: Int32) -> Int64 { sqlite3_column_int64(pointer, column) }

    func blob(_ column: Int32) -> [UInt8] {
        let count = Int(sqlite3_column_bytes(pointer, column))
        guard count > 0, let base = sqlite3_column_blob(pointer, column) else { return [] }
        return Array(UnsafeRawBufferPointer(start: base, count: count))
    }

    func text(_ column: Int32) -> String? {
        guard let value = sqlite3_column_text(pointer, column) else { return nil }
        return String(cString: value)
    }
}
