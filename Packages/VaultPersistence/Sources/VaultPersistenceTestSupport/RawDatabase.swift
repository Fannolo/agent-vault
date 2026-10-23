import CSQLite

/// TEST-ONLY raw access to the kernel's file, bypassing the kernel: artifact inspection after
/// recovery, and deliberate tampering. Never opens with CREATE.
public enum RawDatabase {
    public struct Failure: Error, Equatable {
        public let code: Int32
    }

    public struct Image: Equatable {
        public let generation: Int64
        public let stateID: [UInt8]
        public let state: [UInt8]
        public let objectCount: Int64
        public let objectBytes: Int64
        /// digest → (admitted generation, bytes)
        public let objects: [[UInt8]: Row]
    }

    public struct Row: Equatable {
        public let generation: Int64
        public let bytes: [UInt8]
    }

    public static func read(_ path: String) throws -> Image {
        try withConnection(path, flags: SQLITE_OPEN_READONLY) { handle in
            let head = try rows(handle, "SELECT generation, state_id, state, object_count, object_bytes FROM head")
            guard head.count == 1 else { throw Failure(code: -1) }
            var objects = [[UInt8]: Row]()
            for row in try rows(handle, "SELECT digest, generation, bytes FROM objects") {
                objects[row[0].blob] = Row(generation: row[1].integer, bytes: row[2].blob)
            }
            let value = head[0]
            return Image(generation: value[0].integer, stateID: value[1].blob, state: value[2].blob,
                         objectCount: value[3].integer, objectBytes: value[4].integer, objects: objects)
        }
    }

    public static func execute(_ path: String, _ sql: String, blobs: [[UInt8]] = []) throws {
        try withConnection(path, flags: SQLITE_OPEN_READWRITE) { handle in
            _ = try rows(handle, sql, blobs: blobs)
        }
    }

    private enum Value {
        case integer(Int64)
        case blob([UInt8])

        var integer: Int64 { if case .integer(let value) = self { value } else { -1 } }
        var blob: [UInt8] { if case .blob(let value) = self { value } else { [] } }
    }

    private static func withConnection<T>(_ path: String, flags: Int32,
                                          _ body: (OpaquePointer) throws -> T) throws -> T {
        var handle: OpaquePointer?
        let code = sqlite3_open_v2(path, &handle, flags | SQLITE_OPEN_NOFOLLOW, nil)
        defer { sqlite3_close_v2(handle) }
        guard code == SQLITE_OK, let handle else { throw Failure(code: code) }
        return try body(handle)
    }

    private static func rows(_ handle: OpaquePointer, _ sql: String, blobs: [[UInt8]] = []) throws -> [[Value]] {
        var statement: OpaquePointer?
        var code = sqlite3_prepare_v2(handle, sql, -1, &statement, nil)
        defer { sqlite3_finalize(statement) }
        guard code == SQLITE_OK, let statement else { throw Failure(code: code) }
        for (index, blob) in blobs.enumerated() {
            code = blob.withUnsafeBytes {
                sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress, Int32($0.count), av_sqlite_transient())
            }
            guard code == SQLITE_OK else { throw Failure(code: code) }
        }
        var result = [[Value]]()
        while true {
            code = sqlite3_step(statement)
            if code == SQLITE_DONE { return result }
            guard code == SQLITE_ROW else { throw Failure(code: code) }
            result.append((0..<sqlite3_column_count(statement)).map { column in
                if sqlite3_column_type(statement, column) == SQLITE_INTEGER {
                    return .integer(sqlite3_column_int64(statement, column))
                }
                let count = Int(sqlite3_column_bytes(statement, column))
                guard count > 0, let base = sqlite3_column_blob(statement, column) else { return .blob([]) }
                return .blob(Array(UnsafeRawBufferPointer(start: base, count: count)))
            })
        }
    }
}
