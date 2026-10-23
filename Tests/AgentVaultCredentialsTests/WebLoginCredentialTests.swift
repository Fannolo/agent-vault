@_spi(CredentialUse) import AgentVaultCredentials
import AgentVaultContracts
import Foundation
import Testing

private let fixture = Data("fixture-user\nSYNTHETIC_CREDENTIAL_89C2".utf8)

@Test func scopedCredentialRetainsExactUTF8AndFieldBoundaries() throws {
    for bytes in [fixture, Data("utente-é\nSYNTHETIC-密碼\u{2028}".utf8)] {
        let credential = try #require(WebLoginCredential(bytes))
        let same = credential.withCanonicalBytes { Data($0) == bytes }
        let fields = credential.withLoginBytes { username, password in
            !username.isEmpty && !password.isEmpty && Data(username) + Data([0x0A]) + Data(password) == bytes
        }
        #expect(same)
        #expect(fields)
    }
}

@Test func credentialRejectsMalformedNoncanonicalAndEmptyFields() {
    let invalid = [Data(), Data("one-line".utf8), Data("\npassword".utf8), Data("user\n".utf8),
                   Data("user\npass\nword".utf8), Data("user\npass\u{7}".utf8),
                   Data("\u{FEFF}user\npassword".utf8), Data("user\np\u{200D}word".utf8),
                   Data([0xFF, 0x0A, 0x41]), Data(repeating: 0x41, count: 4097),
                   Data((String(repeating: "u", count: 256) + "\npassword").utf8)]
    for bytes in invalid {
        let rejected = WebLoginCredential(bytes) == nil
        #expect(rejected)
        #expect(!WebLoginFormat.isValid(bytes))
    }
}

@Test func credentialLengthLimitsAndSlicedDataAreStable() throws {
    let bytes = Data((String(repeating: "u", count: 255) + "\n" + String(repeating: "p", count: 3840)).utf8)
    #expect(bytes.count == WebLoginFormat.maximumBytes)
    let maximum = try #require(WebLoginCredential(bytes))
    let correct = maximum.withCanonicalBytes { Data($0) == bytes }
    #expect(correct)
    let padded = Data([0xFF, 0x00]) + fixture
    let sliced = try #require(WebLoginCredential(padded.dropFirst(2)))
    let exact = sliced.withCanonicalBytes { Data($0) == fixture }
    #expect(exact)
}

@Test func credentialEqualityDoesNotExposeItsBytes() throws {
    let original = try #require(WebLoginCredential(fixture))
    let same = try #require(WebLoginCredential(fixture))
    let first = try #require(WebLoginCredential(Data("different-user\nSYNTHETIC_CREDENTIAL_89C2".utf8)))
    let last = try #require(WebLoginCredential(Data("fixture-user\nSYNTHETIC_CREDENTIAL_89C3".utf8)))
    let matches = original == same
    let mismatches = original != first && original != last
    #expect(matches)
    #expect(mismatches)
    var diagnostic = ""
    dump(original, to: &diagnostic)
    for text in [String(describing: original), String(reflecting: original), diagnostic] {
        #expect(!text.contains("fixture-user") && !text.contains("SYNTHETIC_CREDENTIAL_89C2"))
    }
    #expect(Mirror(reflecting: original).children.isEmpty)
}
