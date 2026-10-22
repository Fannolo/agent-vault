import Foundation

struct BinaryWriter {
    var data = Data()
    mutating func byte(_ value: UInt8) { data.append(value) }
    mutating func bytes(_ value: Data) { data.append(value) }
    mutating func count(_ value: Int) {
        let value = UInt32(value)
        data.append(contentsOf: [UInt8(value >> 24), UInt8(truncatingIfNeeded: value >> 16),
                                UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
    }
    mutating func field(_ value: Data) { count(value.count); bytes(value) }
}

struct BinaryReader {
    let data: Data
    private(set) var offset = 0
    var remaining: Int { data.count - offset }

    init(_ data: Data) { self.data = Data(data) }

    mutating func bytes(_ count: Int) throws -> Data {
        guard count >= 0, count <= remaining else { throw VaultError.malformed }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }
    mutating func byte() throws -> UInt8 { try bytes(1)[0] }
    mutating func count(maximum: Int) throws -> Int {
        let value = try bytes(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard value <= maximum else { throw VaultError.malformed }
        return Int(value)
    }
    mutating func field(maximum: Int) throws -> Data {
        try bytes(count(maximum: maximum))
    }
    func finish() throws { guard remaining == 0 else { throw VaultError.malformed } }
}

func strictlySorted(_ values: [Data]) -> Bool {
    zip(values, values.dropFirst()).allSatisfy { $0.lexicographicallyPrecedes($1) }
}

extension LoginItem {
    func encode() throws -> Data {
        guard username.utf8.count <= 1024, password.count <= 4096, origins.count <= 32,
              origins.allSatisfy({ $0.utf8.count <= 256 && $0.utf8.allSatisfy { $0 < 128 } }) else {
            throw VaultError.malformed
        }
        let usernameBytes = Data(username.utf8)
        let originBytes = origins.map { Data($0.utf8) }.sorted { $0.lexicographicallyPrecedes($1) }
        guard strictlySorted(originBytes) else { throw VaultError.malformed }
        var writer = BinaryWriter()
        writer.byte(1)
        writer.byte(1)
        writer.field(usernameBytes)
        writer.field(password)
        writer.count(originBytes.count)
        for origin in originBytes { writer.field(origin) }
        guard writer.data.count <= 262144 else { throw VaultError.malformed }
        return writer.data
    }

    static func decode(_ data: Data) throws -> LoginItem {
        guard data.count <= 262144 else { throw VaultError.malformed }
        var reader = BinaryReader(data)
        guard try reader.byte() == 1, try reader.byte() == 1 else { throw VaultError.malformed }
        let usernameBytes = try reader.field(maximum: 1024)
        // Exact round-trip rejects repaired UTF-8 and preserves BOM, including on macOS 14.
        let username = String(decoding: usernameBytes, as: UTF8.self)
        guard Data(username.utf8) == usernameBytes else {
            throw VaultError.malformed
        }
        let password = try reader.field(maximum: 4096)
        let count = try reader.count(maximum: 32)
        var origins: [Data] = []
        for _ in 0..<count {
            let origin = try reader.field(maximum: 256)
            guard origin.allSatisfy({ $0 < 128 }) else { throw VaultError.malformed }
            origins.append(origin)
        }
        try reader.finish()
        guard strictlySorted(origins) else { throw VaultError.malformed }
        return LoginItem(username: username, password: password,
                         origins: origins.map { String(decoding: $0, as: UTF8.self) })
    }
}
