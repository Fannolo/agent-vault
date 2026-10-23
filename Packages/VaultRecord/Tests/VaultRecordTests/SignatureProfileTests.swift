internal import CCryptoBoringSSL
import Crypto
import Foundation
import Testing
@testable import VaultRecord

// SIGNATURE-PROFILE.md (proposal) and crypto-design-review-v2. Each case reports three
// outcomes separately: the effective profile, the raw pinned BoringSSL verifier, and the
// platform Crypto/CryptoKit verifier (comparison only, never the protocol predicate).

struct SignatureOutcome: Equatable, CustomStringConvertible {
    let effective: Bool
    let rawPinned: Bool
    let platform: Bool?
    var description: String { "effective=\(effective) raw_pinned=\(rawPinned) platform=\(platform.map(String.init) ?? "n/a")" }
}

func outcome(_ signature: Data, _ message: Data, _ author: Data) -> SignatureOutcome {
    let platformKey = try? Curve25519.Signing.PublicKey(rawRepresentation: author)
    return SignatureOutcome(effective: SignatureProfile.verify(signature: signature, body: message, author: author),
                            rawPinned: SignatureProfile.pinnedVerify(signature: Array(signature), body: message, author: Array(author)),
                            platform: platformKey.map { $0.isValidSignature(signature, for: message) })
}

let basepoint = unhex("5866666666666666666666666666666666666666666666666666666666666666")
let identityPoint = Data([1]) + Data(count: 31)

/// TEST ONLY scalar reduction of a 64-byte little-endian integer modulo L (no curve arithmetic).
func reduceModL(_ wide: [UInt8]) -> [UInt8] {
    let order = SignatureProfile.order + [0]
    var r = [UInt8](repeating: 0, count: 33)
    for byteIndex in stride(from: wide.count - 1, through: 0, by: -1) {
        for bit in stride(from: 7, through: 0, by: -1) {
            var carry = (wide[byteIndex] >> UInt8(bit)) & 1
            for index in 0..<33 {
                let shifted = (UInt16(r[index]) << 1) | UInt16(carry)
                r[index] = UInt8(truncatingIfNeeded: shifted)
                carry = UInt8(shifted >> 8)
            }
            var atLeast = true
            for index in stride(from: 32, through: 0, by: -1) where r[index] != order[index] {
                atLeast = r[index] > order[index]
                break
            }
            if atLeast {
                var borrow: Int16 = 0
                for index in 0..<33 {
                    var value = Int16(r[index]) - Int16(order[index]) - borrow
                    borrow = value < 0 ? 1 : 0
                    if value < 0 { value += 256 }
                    r[index] = UInt8(value)
                }
            }
        }
    }
    return Array(r.prefix(32))
}

func challenge(_ r: Data, _ a: Data, _ message: Data) -> [UInt8] {
    reduceModL(Array(SHA512.hash(data: r + a + message)))
}

/// A complete, syntactically valid record body whose author field is `author`.
func recordBody(author: Data) throws -> (header: Data, message: Data, body: Data) {
    var hostile = HostileRecord(Fixture(), content: login())
    hostile.author = author
    let header = hostile.headerBytes
    let message = try hostile.message()
    var writer = ByteWriter()
    writer.raw(header)
    writer.u32(UInt32(message.count))
    writer.raw(message)
    return (header, message, writer.data)
}

func assemble(_ body: Data, signature: Data) -> Data { body + signature }

@Test func scalarReductionMatchesKnownValues() {
    #expect(reduceModL(SignatureProfile.order + [UInt8](repeating: 0, count: 32)) == [UInt8](repeating: 0, count: 32))
    #expect(reduceModL([5] + [UInt8](repeating: 0, count: 63)) == [5] + [UInt8](repeating: 0, count: 31))
    // 2^256 mod L, independently computed with Python big integers.
    let twoTo256 = [UInt8](repeating: 0, count: 32) + [1] + [UInt8](repeating: 0, count: 31)
    #expect(Data(reduceModL(twoTo256)) == unhex("1d95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f"))
}

/// Review v2: A = identity, R = B, S = 1 satisfies the raw equation for every message.
/// Context screening and the effective predicate both refuse; R screening cannot mask it.
@Test func isolatedWeakAuthorForgery() throws {
    let s1 = Data([1]) + Data(count: 31)
    let signature = basepoint + s1
    for author in [identityPoint, { var a = identityPoint; a[31] |= 0x80; return a }()] {
        let (_, _, body) = try recordBody(author: author)
        let result = outcome(signature, body, author)
        emitPublic("AV_RECORD_SIG weak_identity_A sign=\(author[31] >> 7) \(result)")
        #expect(SignatureProfile.screensPoint(signature.prefix(32)))
        #expect(!result.effective)
        if author[31] == 0 { #expect(result.rawPinned) }
        #expect(throws: RecordError.invalidKey) {
            _ = try RecordAuthority(vaultID: Fixture().vaultID, membershipBodyID: Fixture().membership,
                                    authorEd25519: author, recipients: Fixture().recipients)
        }
    }
    for message in [Data(), Data("arbitrary".utf8), Data(repeating: 9, count: 1000)] {
        #expect(SignatureProfile.pinnedVerify(signature: Array(signature), body: message, author: Array(identityPoint)))
        #expect(!SignatureProfile.verify(signature: signature, body: message, author: identityPoint))
    }
}

/// Review v2: A = B, R = identity, S = h mod L holds uncofactored; the profile refuses R.
/// Exercised through the typed record path under an authority naming A = B.
@Test func smallOrderNonceIsRefusedThroughRecordPath() throws {
    let fixture = Fixture()
    let (_, _, body) = try recordBody(author: basepoint)
    let s = challenge(identityPoint, basepoint, body)
    let signature = identityPoint + Data(s)
    let result = outcome(signature, body, basepoint)
    emitPublic("AV_RECORD_SIG small_order_R \(result)")
    #expect(result.rawPinned)
    #expect(!result.effective)
    let authority = fixture.authority(author: basepoint)
    expectRefusal(.badSignature) {
        _ = try ParsedRecord(assemble(body, signature: signature)).verify(under: authority, item: fixture.itemID,
                                                                          revision: fixture.revisionID)
    }
}

/// CCTV ed25519vectors.json 6 and 7 at 3ec4d716e80597545ed285cf62af3dded3a14f65: canonical
/// mixed-order A and R. Primitive vectors, not record-shaped; no record-path claim.
@Test func cctvMixedOrderVectors() {
    let a = unhex("10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f")
    let r = unhex("36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b")
    let six = outcome(r + unhex("c02e2b9e63e385c058bf62b14b3a2b29ccefe8e38ddb536bc3f9865320a3d801"),
                      Data("ed25519vectors 10".utf8), a)
    let seven = outcome(r + unhex("bbfd00bd9c259d8d222d15e67a3d8228585050dbb9b9585be20d8fadc721da03"),
                        Data("ed25519vectors".utf8), a)
    emitPublic("AV_RECORD_SIG cctv6 \(six)")
    emitPublic("AV_RECORD_SIG cctv7 \(seven)")
    #expect(!six.effective && !six.rawPinned)
    #expect(seven.effective && seven.rawPinned)
    #expect(SignatureProfile.screensPoint(a) && SignatureProfile.screensPoint(r))
}

/// Canonical bounds and every torsion encoding with both signs, as A and as R.
@Test func pointScreeningBoundaries() throws {
    let pMinus1 = Data([0xec]) + Data(repeating: 0xff, count: 30) + Data([0x7f])
    let p = Data([0xed]) + Data(repeating: 0xff, count: 30) + Data([0x7f])
    let pPlus1 = Data([0xee]) + Data(repeating: 0xff, count: 30) + Data([0x7f])
    let maximum = Data(repeating: 0xff, count: 31) + Data([0x7f])
    var refused = SignatureProfile.smallOrderY.map { Data($0) } + [p, pPlus1, maximum]
    refused += refused.map { var signed = $0; signed[31] |= 0x80; return signed }
    #expect(refused.count == 16)
    #expect(SignatureProfile.smallOrderY.contains(Array(pMinus1)))
    let (_, _, body) = try recordBody(author: Fixture().author.publicKey.rawRepresentation)
    let honest = try Fixture().author.signature(for: body)
    for encoding in refused {
        #expect(!SignatureProfile.screensPoint(encoding))
        #expect(throws: RecordError.invalidKey) {
            _ = try RecordAuthority(vaultID: Fixture().vaultID, membershipBodyID: Fixture().membership,
                                    authorEd25519: encoding, recipients: Fixture().recipients)
        }
        #expect(!SignatureProfile.verify(signature: encoding + honest.suffix(32), body: body,
                                         author: Fixture().author.publicKey.rawRepresentation))
    }
    // Largest canonical y (p − 2 equivalent: 0xeb…) passes screening; validity is the verifier's job.
    #expect(SignatureProfile.screensPoint(Data([0xeb]) + Data(repeating: 0xff, count: 30) + Data([0x7f])))
}

/// y = 2 is not on the curve (x² is a nonresidue; checked with Python big integers). It
/// passes byte screening but never passes effective verification.
@Test func noncurveAuthorPassesScreeningButNeverVerifies() throws {
    let fixture = Fixture()
    let noncurve = Data([2]) + Data(count: 31)
    #expect(SignatureProfile.screensPoint(noncurve))
    let authority = fixture.authority(author: noncurve)
    var hostile = HostileRecord(fixture, content: login())
    hostile.author = noncurve
    let record = try hostile.build()
    let body = record.dropLast(64)
    for signature in [record.suffix(64), basepoint + Data([1]) + Data(count: 31)] {
        let result = outcome(Data(signature), Data(body), noncurve)
        emitPublic("AV_RECORD_SIG noncurve_A \(result)")
        #expect(!result.effective && !result.rawPinned)
        expectRefusal(.badSignature) {
            _ = try ParsedRecord(body + signature).verify(under: authority, item: fixture.itemID, revision: fixture.revisionID)
        }
    }
}

@Test func scalarBoundsSEqualsLAndSPlusL() throws {
    let fixture = Fixture()
    let record = try fixture.seal(login()).bytes
    let body = record.dropLast(64)
    let signature = Array(record.suffix(64))
    // S + L: add L to the little-endian scalar.
    var plusL = signature
    var carry = 0
    for index in 0..<32 {
        let sum = Int(plusL[32 + index]) + Int(SignatureProfile.order[index]) + carry
        plusL[32 + index] = UInt8(sum & 0xff)
        carry = sum >> 8
    }
    #expect(carry == 0)
    let sEqualsL = Array(signature.prefix(32)) + SignatureProfile.order
    for bad in [plusL, sEqualsL] {
        #expect(!SignatureProfile.scalarIsReduced(bad.suffix(32)))
        let result = outcome(Data(bad), Data(body), fixture.author.publicKey.rawRepresentation)
        emitPublic("AV_RECORD_SIG s_bound \(result)")
        #expect(!result.effective && !result.rawPinned)
        expectOpenRefusal(.badSignature, fixture, Data(body) + Data(bad))
    }
    var lMinus1 = SignatureProfile.order
    lMinus1[0] -= 1
    #expect(SignatureProfile.scalarIsReduced(lMinus1))
}

/// Honest signatures from both signers verify through the record path; alternate valid
/// signatures keep the body ID and change the transport digest.
@Test func bothSignersAndAlternateSignatures() throws {
    let fixture = Fixture()
    let sealed = try fixture.seal(login())
    let body = sealed.bytes.dropLast(64)
    let seed = Array(fixture.author.rawRepresentation)
    var publicKey = [UInt8](repeating: 0, count: 32)
    var privateKey = [UInt8](repeating: 0, count: 64)
    CCryptoBoringSSL_ED25519_keypair_from_seed(&publicKey, &privateKey, seed)
    #expect(Data(publicKey) == fixture.author.publicKey.rawRepresentation)
    var pinned = [UInt8](repeating: 0, count: 64)
    let signed = Array(body)
    #expect(CCryptoBoringSSL_ED25519_sign(&pinned, signed, signed.count, privateKey) == 1)
    wipe(&privateKey)
    let platform = try fixture.author.signature(for: body)
    var digests = Set<TransportDigest>()
    for signature in [Data(pinned), platform, sealed.bytes.suffix(64)] {
        let result = outcome(signature, Data(body), fixture.author.publicKey.rawRepresentation)
        #expect(result.effective && result.rawPinned && result.platform == true)
        let verified = try fixture.verify(Data(body) + signature)
        #expect(verified.bodyID == sealed.bodyID)
        digests.insert(verified.transportDigest)
        try verified.open(as: fixture.recipientKeys[1]) { _ in }
    }
    let distinct = Set([Data(pinned), platform, Data(sealed.bytes.suffix(64))]).count
    #expect(digests.count == distinct)
    emitPublic("AV_RECORD_SIG alternate_signatures platform=\(platformName) distinct_valid_signatures=\(distinct)")
    #if !os(Linux)
    #expect(distinct >= 2) // native CryptoKit signing is randomized; pinned BoringSSL is deterministic
    #endif
}

@Test func wycheproofProvenanceAndThreeOutcomeReport() throws {
    let table = Data(WycheproofEd25519Corpus.table.utf8)
    #expect(hex(SHA256.hash(data: table)) == WycheproofEd25519Corpus.tableSHA256)
    #expect(WycheproofEd25519Corpus.tableSHA256 == "e8ab9314a0f44531529f582847f21bb3acda8a416bd10fc8ece92ebd58077088")
    var rows: [String] = []
    var platformDisagreements: [Int] = []
    for line in WycheproofEd25519Corpus.table.split(separator: "\n") {
        let fields = line.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        try #require(fields.count == 7)
        let id = Int(fields[0])!
        let author = unhex(fields[2]), message = unhex(fields[3]), signature = unhex(fields[4])
        let expected = fields[5] == "valid" && !WycheproofEd25519Corpus.profileRefusedValidCases.contains(id)
        let result = outcome(signature, message, author)
        #expect(result.effective == expected, "tcId \(id)")
        if result.platform != result.effective { platformDisagreements.append(id) }
        rows.append("\(id):\(result.effective ? 1 : 0)\(result.rawPinned ? 1 : 0)\(result.platform == true ? 1 : 0)")
    }
    #expect(rows.count == 150)
    emitPublic("AV_RECORD_WYCHEPROOF platform=\(platformName) table=\(WycheproofEd25519Corpus.tableSHA256) "
        + "effective_raw_platform=\(rows.joined(separator: ",")) platform_differs=\(platformDisagreements)")
}
