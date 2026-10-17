import Foundation

/// Secrets are born here, inside the trusted test process. Never describe this object or
/// use secret-bearing values as Testing assertion operands (which print on failure).
final class SecretExposureProbe: CustomStringConvertible, CustomDebugStringConvertible {
    var description: String { "SecretExposureProbe(redacted)" }
    var debugDescription: String { description }
    enum Channel: String, CaseIterable {
        case readReply, adminSnapshot, appMetadata, auditExport, persistedMetadata
        case mcpReply, mcpError, browserArtifacts, browserArgv, browserEnvironment
    }
    let password = UUID().uuidString + "+/=&\"\\" + UUID().uuidString
    let humanInput = UUID().uuidString + UUID().uuidString
    private var observations: [Channel: Int] = [:]
    private var leaks: [Channel: Int] = [:]

    /// Explicit finite encoding catalogue; no claim about arbitrary transforms or fragments.
    static func encodings(_ value: String) -> [Data] {
        let bytes = Data(value.utf8)
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        let percent = bytes.map { String(format: "%%%02X", $0) }.joined()
        let json = String(decoding: try! JSONEncoder().encode(value), as: UTF8.self)
        let unicode = value.utf16.map { String(format: "\\u%04x", $0) }.joined()
        let unicodeUpper = value.utf16.map { String(format: "\\u%04X", $0) }.joined()
        let base64 = bytes.base64EncodedString()
        let base64url = base64.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let form = value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        return [bytes, Data(base64.utf8), Data(base64.replacingOccurrences(of: "=", with: "").utf8),
                Data(base64url.utf8), Data(hex.utf8), Data(hex.uppercased().utf8),
                Data(percent.utf8), Data(percent.lowercased().utf8), Data(form.utf8), Data(json.utf8),
                Data(json.dropFirst().dropLast().utf8), Data(unicode.utf8), Data(unicodeUpper.utf8),
                value.data(using: .utf16LittleEndian)!, value.data(using: .utf16BigEndian)!]
    }
    func observe(_ channel: Channel, _ bytes: Data) {
        observations[channel, default: 0] += 1
        for secret in [password, "mfa-user\n" + password, humanInput] {
            for pattern in Self.encodings(secret) where bytes.range(of: pattern) != nil {
                leaks[channel, default: 0] += 1
            }
        }
    }
    func observe<T: Encodable>(_ channel: Channel, encoded value: T) throws {
        observe(channel, try JSONEncoder().encode(value))
    }
    func isClean(requiring required: Set<Channel>) -> Bool {
        required.allSatisfy { observations[$0, default: 0] > 0 && leaks[$0, default: 0] == 0 }
    }
    /// Only closed channel names, counts and booleans can reach the test output.
    func report(_ required: Set<Channel>) -> String {
        required.sorted { $0.rawValue < $1.rawValue }.map {
            "\($0.rawValue):observed=\(observations[$0, default: 0]),leaks=\(leaks[$0, default: 0])"
        }.joined(separator: ";")
    }
}
