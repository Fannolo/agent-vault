import Foundation

enum JSONMessageValidator {
    static func validate(_ data: Data) throws {
        var parser = Parser(bytes: Array(data))
        try parser.message()
    }

    private struct Parser {
        let bytes: [UInt8]
        var offset = 0

        mutating func message() throws {
            whitespace()
            guard current == 0x7B else { throw StdioTransportError.invalidJSON }
            try object(depth: 1)
            whitespace()
            guard offset == bytes.count else { throw StdioTransportError.invalidJSON }
        }

        var current: UInt8? { offset < bytes.count ? bytes[offset] : nil }

        mutating func whitespace() {
            while let byte = current, [0x20, 0x09, 0x0A, 0x0D].contains(byte) { offset += 1 }
        }

        mutating func take(_ byte: UInt8) throws {
            guard current == byte else { throw StdioTransportError.invalidJSON }
            offset += 1
        }

        mutating func value(depth: Int) throws {
            whitespace()
            guard let byte = current else { throw StdioTransportError.invalidJSON }
            switch byte {
            case 0x7B: try object(depth: depth)
            case 0x5B: try array(depth: depth)
            case 0x22: _ = try string()
            case 0x74: try literal([0x74, 0x72, 0x75, 0x65])
            case 0x66: try literal([0x66, 0x61, 0x6C, 0x73, 0x65])
            case 0x6E: try literal([0x6E, 0x75, 0x6C, 0x6C])
            case 0x2D, 0x30...0x39: try number()
            default: throw StdioTransportError.invalidJSON
            }
        }

        mutating func object(depth: Int) throws {
            guard depth <= 64 else { throw StdioTransportError.tooDeep }
            try take(0x7B)
            whitespace()
            if current == 0x7D { offset += 1; return }
            var keys = Set<String>()
            while true {
                whitespace()
                let key = try string()
                guard keys.insert(key).inserted else { throw StdioTransportError.duplicateKey }
                whitespace()
                try take(0x3A)
                whitespace()
                let start = offset
                try value(depth: depth + 1)
                if depth == 1, key == "id", start < bytes.count,
                   bytes[start] == 0x2D || (0x30...0x39).contains(bytes[start]),
                   bytes[start..<offset].contains(where: { [0x2E, 0x65, 0x45].contains($0) }) {
                    throw StdioTransportError.invalidRequestID
                }
                whitespace()
                if current == 0x7D { offset += 1; return }
                try take(0x2C)
            }
        }

        mutating func array(depth: Int) throws {
            guard depth <= 64 else { throw StdioTransportError.tooDeep }
            try take(0x5B)
            whitespace()
            if current == 0x5D { offset += 1; return }
            while true {
                try value(depth: depth + 1)
                whitespace()
                if current == 0x5D { offset += 1; return }
                try take(0x2C)
            }
        }

        mutating func string() throws -> String {
            let start = offset
            try take(0x22)
            while let byte = current {
                if byte == 0x22 {
                    offset += 1
                    do { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<offset])) }
                    catch { throw StdioTransportError.invalidJSON }
                }
                guard byte >= 0x20 else { throw StdioTransportError.invalidJSON }
                if byte == 0x5C {
                    offset += 2
                    guard offset <= bytes.count else { throw StdioTransportError.invalidJSON }
                } else { offset += 1 }
            }
            throw StdioTransportError.invalidJSON
        }

        mutating func literal(_ expected: [UInt8]) throws {
            for byte in expected { try take(byte) }
        }

        mutating func number() throws {
            if current == 0x2D { offset += 1 }
            if current == 0x30 { offset += 1 }
            else {
                guard let digit = current, (0x31...0x39).contains(digit) else {
                    throw StdioTransportError.invalidJSON
                }
                digits()
            }
            if current == 0x2E { offset += 1; try requiredDigits() }
            if current == 0x65 || current == 0x45 {
                offset += 1
                if current == 0x2B || current == 0x2D { offset += 1 }
                try requiredDigits()
            }
        }

        mutating func digits() {
            while let byte = current, (0x30...0x39).contains(byte) { offset += 1 }
        }

        mutating func requiredDigits() throws {
            let start = offset
            digits()
            guard offset > start else { throw StdioTransportError.invalidJSON }
        }
    }
}
