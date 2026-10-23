@_spi(SecretReveal) import VaultSecret
import CSecretMemory
import Testing

private func synthetic() throws -> SecretBytes {
    var source = Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8)
    return try SecretBytes(consuming: &source)
}

@Test func trustedComparisonChecksEveryPositionAndLength() throws {
    let original = try synthetic()
    let same = try synthetic()
    let equal = original.matches(same)
    #expect(equal)
    for position in Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8).indices {
        var bytes = Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8)
        bytes[position] ^= 1
        let changed = try SecretBytes(consuming: &bytes)
        let different = !original.matches(changed)
        #expect(different)
    }
    var shorter = Array("short".utf8)
    let short = try SecretBytes(consuming: &shorter)
    let differentLength = !original.matches(short)
    #expect(differentLength)
}

@Test func consumingInputDoesNotEraseAnEarlierArrayAlias() throws {
    var source = Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8)
    let alias = source
    let secret = try SecretBytes(consuming: &source)
    #expect(source.isEmpty)
    let unchanged = alias == Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8)
    let correct = secret.withUnsafeBytes { Array($0) == alias }
    #expect(unchanged)
    #expect(correct)
}

@Test func ownedClearHelperOverwritesItsEntireBuffer() {
    var buffer: [UInt8] = [1, 2, 3, 4, 5, 6, 7]
    buffer.withUnsafeMutableBytes { av_secret_clear($0.baseAddress!, $0.count) }
    let allCleared = buffer.allSatisfy { $0 == 0 }
    #expect(allCleared)
}

@Test func consumesSuccessfulInputAndPreservesBorrowedBytes() throws {
    var source = Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8)
    let secret = try SecretBytes(consuming: &source)
    #expect(source.isEmpty)
    let matches = secret.withUnsafeBytes { bytes in
        Array(bytes) == Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8)
    }
    #expect(matches)
}

@Test func secretDiagnosticsAndMirrorsAreRedacted() throws {
    let secret = try synthetic()
    let login = LoginSecret(username: secret, password: secret)
    #expect(String(describing: secret) == "SecretBytes(<redacted>)")
    #expect(String(reflecting: secret) == "SecretBytes(<redacted>)")
    #expect(String(describing: login) == "LoginSecret(<redacted>)")
    #expect(String(reflecting: login) == "LoginSecret(<redacted>)")
    #expect(Mirror(reflecting: secret).children.isEmpty)
    #expect(Mirror(reflecting: login).children.isEmpty)
    var text = ""
    dump(login, to: &text)
    #expect(!text.contains("AV_SECRET_BUFFER_SYNTHETIC_6B3C"))
}

@Test func secretSizeBoundsFailWithFixedError() throws {
    for size in [0, SecretBytes.maximumBytes + 1] {
        var source = [UInt8](repeating: 0x51, count: size)
        do {
            _ = try SecretBytes(consuming: &source)
            Issue.record("Expected fixed size error")
        } catch {
            #expect(error == .invalidSize)
            #expect(source.count == size)
        }
    }
    var maximum = [UInt8](repeating: 0x51, count: SecretBytes.maximumBytes)
    let secret = try SecretBytes(consuming: &maximum)
    #expect(maximum.isEmpty)
    let correct = secret.withUnsafeBytes { $0.count == SecretBytes.maximumBytes }
    #expect(correct)
}

@Test func immutableSecretSupportsConcurrentScopedReads() async throws {
    let secret = try synthetic()
    let correct = await withTaskGroup(of: Bool.self, returning: Bool.self) { group in
        for _ in 0..<32 {
            group.addTask {
                secret.withUnsafeBytes { Array($0) == Array("AV_SECRET_BUFFER_SYNTHETIC_6B3C".utf8) }
            }
        }
        for await matches in group {
            if !matches { return false }
        }
        return true
    }
    #expect(correct)
}
