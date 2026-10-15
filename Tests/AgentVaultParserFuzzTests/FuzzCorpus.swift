import Foundation

// Fixed seeds and counts make every failure replayable without environment flags.
enum ParserCorpus {
    static let iterations = 512
    static let requestSeed: UInt64 = 0x4950_435F_5348_4150
    static let requestBytesSeed: UInt64 = 0x4950_435F_4259_5445
    static let replySeed: UInt64 = 0x5245_504C_595F_465A
    static let githubSeed: UInt64 = 0x4749_5448_5542_465A
    static let mcpBytesSeed: UInt64 = 0x4D43_505F_4259_5445
    static let mcpStructureSeed: UInt64 = 0x4D43_505F_5348_4150
    static let hostCommandSeed: UInt64 = 0x484F_5354_5F43_4D44
    static let hostBytesSeed: UInt64 = 0x484F_5354_5F42_5954
    static let hostReplySeed: UInt64 = 0x484F_5354_5F52_504C
    static let uuid = "00000000-0000-4000-8000-000000000001"
}

struct SeededGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed }

    // SplitMix64; wrapping arithmetic is intentional and stable across platforms.
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }

    mutating func int(_ upperBound: Int) -> Int { Int(next() % UInt64(upperBound)) }
    mutating func choose<T>(_ values: [T]) -> T { values[int(values.count)] }
    mutating func login() -> String {
        let first = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        let rest = first + ["-"]
        return String([choose(first)] + (0..<int(39)).map { _ in choose(rest) })
    }

    mutating func mutateBytes(_ original: Data) -> (String, Data) {
        var bytes = Array(original)
        let position = int(bytes.count)
        switch int(7) {
        case 0:
            bytes.remove(at: position)
            return ("delete-byte", Data(bytes))
        case 1:
            bytes.insert(choose([0, 0x22, 0x5C, 0x7B, 0x5D, 0x20, 0xFF]), at: position)
            return ("insert-byte", Data(bytes))
        case 2:
            bytes[position] ^= 1 << int(8)
            return ("flip-bit", Data(bytes))
        case 3:
            return ("truncate", Data(bytes.prefix(position)))
        case 4:
            let end = min(bytes.count, position + 1 + int(8))
            bytes.insert(contentsOf: Array(bytes[position..<end]), at: position)
            return ("duplicate-slice", Data(bytes))
        case 5:
            bytes[position] = choose(Array("\"{}[],:0129efnrtu ".utf8))
            return ("replace-byte", Data(bytes))
        default:
            bytes.append(contentsOf: choose([Array("{}".utf8), [0], [0x20, 0x09], [0xEF, 0xBB, 0xBF]]))
            return ("append-tail", Data(bytes))
        }
    }

    mutating func tree(depth: Int = 0) -> CorpusJSON {
        switch int(depth < 4 ? 7 : 4) {
        case 0: return .null
        case 1: return .literal(choose(["true", "false"]))
        case 2: return .literal(String(Int(next() % 100_000) - 50_000))
        case 3:
            return .string(choose(["", "synthetic", "é", "e\u{301}", "🪴", "\"\\\n\t", "مرحبا", "\u{0000}"]))
        case 4, 5:
            return .array((0..<int(5)).map { _ in tree(depth: depth + 1) })
        default:
            return .object((0..<int(5)).map { index in
                ("key-\(index)-\(choose(["ascii", "é", "🪴"]))", tree(depth: depth + 1))
            })
        }
    }
}

indirect enum CorpusJSON {
    case null, literal(String), string(String), array([CorpusJSON]), object([(String, CorpusJSON)])
    var text: String {
        switch self {
        case .null: return "null"
        case .literal(let value): return value
        case .string(let value): return quoted(value)
        case .array(let values): return "[" + values.map(\.text).joined(separator: ",") + "]"
        case .object(let fields): return objectText(fields.map { ($0.0, $0.1.text) })
        }
    }
}

func quoted(_ string: String) -> String {
    String(decoding: try! JSONEncoder().encode(string), as: UTF8.self)
}

func objectText(_ fields: [(String, String)]) -> String {
    "{" + fields.map { quoted($0.0) + ":" + $0.1 }.joined(separator: ",") + "}"
}

func escapedKey(_ key: String) -> String {
    let first = key.utf8.first!
    return "\"\\u" + String(format: "%04x", first) + String(key.dropFirst()) + "\""
}

func duplicateField(in object: String, key: String, value: String, escaped: Bool) -> String {
    String(object.dropLast()) + "," + (escaped ? escapedKey(key) : quoted(key)) + ":" + value + "}"
}

func jsonObject(_ data: Data) -> [String: Any]? {
    (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) as? [String: Any]
}

func statusIsBounded(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    return (1...64).contains(bytes.count) && (97...122).contains(bytes[0])
        && bytes.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }
}

func profileLoginIsBounded(_ value: String, firstMustBeAlphanumeric: Bool) -> Bool {
    let bytes = Array(value.utf8)
    func alphanumeric(_ byte: UInt8) -> Bool {
        (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte)
    }
    return (1...39).contains(bytes.count)
        && (!firstMustBeAlphanumeric || alphanumeric(bytes[0]))
        && bytes.allSatisfy { alphanumeric($0) || $0 == 45 }
}

struct FuzzCase {
    let seed: UInt64
    let index: Int
    let mutation: String
    let data: Data
    var description: String {
        "seed=0x\(String(seed, radix: 16)) case=\(index) mutation=\(mutation) bytes=\(data.count) "
            + "input=\(quoted(String(decoding: data.prefix(300), as: UTF8.self))) "
            + "base64Prefix=\(data.prefix(300).base64EncodedString())"
    }
}

struct CorpusFailure: Error, CustomStringConvertible {
    let description: String
}

func check(_ condition: Bool, _ context: FuzzCase, _ property: String) throws {
    guard condition else { throw CorpusFailure(description: property + "; " + context.description) }
}
