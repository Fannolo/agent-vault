import Crypto
import Foundation
import Testing
@testable import VaultCore

// Reader-only exchange path. This file constructs no signing key, mints no membership and
// references no producer or all-authority helper. Its trust root is the compiled vault ID
// and genesis-body digest below, never exchanged metadata, environment or file hashes.

enum MembershipExchangeEnvironment {
    static let writeDirectory = "AV_MEMBERSHIP_WRITE_DIR"
    static let readDirectory = "AV_MEMBERSHIP_READ_DIR"
    static let reader = "AV_MEMBERSHIP_READER"
}

enum MembershipExchangeFailure: String, Error, CustomStringConvertible, CustomDebugStringConvertible {
    case environment, artifactBoundary, outcomeMismatch, plaintextMismatch, checkpointMismatch,
         evidenceMismatch, traceOverflow, artifactWrite
    var description: String { rawValue }
    var debugDescription: String { rawValue }
}

enum MembershipExchangeReader: String, CaseIterable, Sendable {
    case a = "A", b = "B"

    /// Publicly known reader-only synthetic agreement material. Only the selected reader is built.
    func agreementKey() throws -> Curve25519.KeyAgreement.PrivateKey {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: self == .a ? 0xD1 : 0xD2, count: 32))
    }
}

enum MembershipExchangeFile: String, CaseIterable, Sendable {
    case genesis = "genesis.avm"
    case addReader = "add-reader.avm"
    case removeReader = "remove-reader.avm"
    case head0 = "head0.avseal"
    case head1 = "head1.avseal"
    case head2 = "head2.avseal"
    case badSignature = "bad-signature.avseal"
    case incompleteRecipients = "incomplete-recipients.avseal"
    case badEncapsulation = "bad-encapsulation.avseal"
    case corruptWrap = "corrupt-wrap.avseal"
    case forkAt1 = "fork-at-1.avm"
    case contradictionAt2 = "contradiction-at-2.avm"
    case gapAt3 = "gap-at-3.avm"

    var isMembership: Bool { rawValue.hasSuffix(".avm") }
    var minimumSize: Int { isMembership ? MembershipBody.minimumRecordSize : 1 }
    var maximumSize: Int { isMembership ? MembershipBody.maximumRecordSize : SealedRecord.maximumSize }

    var revisionID: Data {
        let tags: [Self: UInt8] = [.head0: 0xB0, .head1: 0xB1, .head2: 0xB2, .badSignature: 0xB3,
                                   .incompleteRecipients: 0xB4, .badEncapsulation: 0xB5, .corruptWrap: 0xB6]
        return Data(repeating: tags[self] ?? 0, count: 16)
    }
}

/// Frozen public fixture oracle. Membership bodies are deterministic; signatures are not.
enum MembershipExchangeOracle {
    static let vaultID = Data(repeating: 0x6D, count: 16)
    static let itemID = Data(repeating: 0x69, count: 16)
    static let nonexistentParent = Data(SHA256.hash(data: Data("agent-vault membership exchange nonexistent parent".utf8)))
    static let username = "synthetic-member"
    static let canary = "AV_MEMBERSHIP_U1_SYNTHETIC_CANARY_5E3B91A4"

    static let genesisDigest = hex("a7b6578a9dc51eb7b3b2966b55c79db0daa6ced89851cd2a4d8714c797c16eaf")
    static let addReaderDigest = hex("368357653056c0d54205dbd259f3f575ee2c4ce1c8f2ed7f6247ee8d6504bd79")
    static let removeReaderDigest = hex("dbbfc5dcead52a8e76f69534790a5d9078516e5777cbcdecf68ff787cb8d251f")
    static let gapDigest = hex("4630ded00a362488d993f2fe1d4ef679abc0d37c731c0c1ed38e1b43f90d30b4")
    static let forkDigest = hex("5ac8f9d140e8490ae14dd7d842b8e9df2bc4d749ef6de805c427bcc013fb0117")
    static let contradictionDigest = hex("d829a5fb8e851dc488bcbb04b7db55cad538cb7bc8591581f39b86f788400866")

    static var heads: [Data] { [genesisDigest, addReaderDigest, removeReaderDigest, gapDigest] }

    static func anchor() throws -> FixtureTrustAnchor {
        try FixtureTrustAnchor(compiledVaultID: vaultID, genesisBodyDigest: genesisDigest)
    }

    static func item(_ file: MembershipExchangeFile) -> LoginItem {
        LoginItem(username: username, password: Data(canary.utf8),
                  origins: ["https://\(file.rawValue.split(separator: ".")[0]).membership.invalid"])
    }

    static func hex(_ text: String) -> Data {
        let characters = Array(text.utf8)
        return Data(stride(from: 0, to: characters.count - 1, by: 2).compactMap {
            UInt8(String(decoding: characters[$0..<($0 + 2)], as: UTF8.self), radix: 16)
        })
    }
}

enum MembershipExchangeOutcome: String, Sendable, Encodable {
    case initialized, advanced, duplicate, authorized, opened
    case staleMembership, unauthorizedRecipient, recipientSetMismatch, invalidEncapsulation,
         membershipFork, missingPredecessor
    case badSignature, badAuthentication

    func matches(_ error: any Error) -> Bool {
        switch self {
        case .badSignature, .badAuthentication:
            return (error as? VaultError)?.rawValue == rawValue
        case .staleMembership, .unauthorizedRecipient, .recipientSetMismatch, .invalidEncapsulation,
             .membershipFork, .missingPredecessor:
            return (error as? MembershipPolicyError)?.rawValue == rawValue
        case .initialized, .advanced, .duplicate, .authorized, .opened:
            return false
        }
    }
}

struct MembershipExchangeCase: Sendable {
    enum Session: String, Sendable { case main, fork, contradiction }
    enum Operation: Sendable { case initialize, advance, authorize, open }

    let id: String
    let session: Session
    let operation: Operation
    let file: MembershipExchangeFile
    let a: MembershipExchangeOutcome
    let b: MembershipExchangeOutcome
    let sequence: UInt64
    var evidence: (kind: MembershipForkEvidence.Kind, first: MembershipExchangeFile, second: MembershipExchangeFile)? = nil

    func expected(_ reader: MembershipExchangeReader) -> MembershipExchangeOutcome { reader == .a ? a : b }

    func perform(on session: FixtureMembershipSession, _ bytes: Data,
                 recipient: Curve25519.KeyAgreement.PrivateKey) throws -> MembershipExchangeOutcome {
        switch operation {
        case .initialize:
            throw MembershipExchangeFailure.checkpointMismatch
        case .advance:
            switch try session.advance(bytes) {
            case .advanced: return .advanced
            case .duplicate: return .duplicate
            }
        case .authorize:
            _ = try session.authorize(bytes, itemID: MembershipExchangeOracle.itemID, revisionID: file.revisionID)
            return .authorized
        case .open:
            let item = try session.openAtCurrentMembership(bytes, itemID: MembershipExchangeOracle.itemID,
                                                           revisionID: file.revisionID, role: .device, recipient: recipient)
            let reference = MembershipExchangeOracle.item(file)
            guard item.username == reference.username, item.password == reference.password,
                  item.origins == reference.origins else { throw MembershipExchangeFailure.plaintextMismatch }
            return .opened
        }
    }

    // head1.avseal is first used by the positive H1 open, so a corrupt transfer surfaces there.
    static let script: [MembershipExchangeCase] = [
        .init(id: "main.init.genesis", session: .main, operation: .initialize, file: .genesis, a: .initialized, b: .initialized, sequence: 0),
        .init(id: "main.open.head0", session: .main, operation: .open, file: .head0, a: .opened, b: .unauthorizedRecipient, sequence: 0),
        .init(id: "main.advance.add-reader", session: .main, operation: .advance, file: .addReader, a: .advanced, b: .advanced, sequence: 1),
        .init(id: "main.advance.genesis-duplicate", session: .main, operation: .advance, file: .genesis, a: .duplicate, b: .duplicate, sequence: 1),
        .init(id: "main.open.head0-stale", session: .main, operation: .open, file: .head0, a: .staleMembership, b: .staleMembership, sequence: 1),
        .init(id: "main.open.head1", session: .main, operation: .open, file: .head1, a: .opened, b: .opened, sequence: 1),
        .init(id: "main.authorize.bad-signature", session: .main, operation: .authorize, file: .badSignature, a: .badSignature, b: .badSignature, sequence: 1),
        .init(id: "main.authorize.incomplete-recipients", session: .main, operation: .authorize, file: .incompleteRecipients, a: .recipientSetMismatch, b: .recipientSetMismatch, sequence: 1),
        .init(id: "main.authorize.bad-encapsulation", session: .main, operation: .authorize, file: .badEncapsulation, a: .invalidEncapsulation, b: .invalidEncapsulation, sequence: 1),
        .init(id: "main.authorize.corrupt-wrap", session: .main, operation: .authorize, file: .corruptWrap, a: .authorized, b: .authorized, sequence: 1),
        .init(id: "main.open.corrupt-wrap", session: .main, operation: .open, file: .corruptWrap, a: .opened, b: .badAuthentication, sequence: 1),
        .init(id: "main.advance.gap-at-3", session: .main, operation: .advance, file: .gapAt3, a: .missingPredecessor, b: .missingPredecessor, sequence: 1),
        .init(id: "main.advance.remove-reader", session: .main, operation: .advance, file: .removeReader, a: .advanced, b: .advanced, sequence: 2),
        .init(id: "main.advance.add-reader-duplicate", session: .main, operation: .advance, file: .addReader, a: .duplicate, b: .duplicate, sequence: 2),
        .init(id: "main.open.head1-stale", session: .main, operation: .open, file: .head1, a: .staleMembership, b: .staleMembership, sequence: 2),
        .init(id: "main.open.head2", session: .main, operation: .open, file: .head2, a: .opened, b: .unauthorizedRecipient, sequence: 2),
        .init(id: "main.advance.gap-at-3-linked", session: .main, operation: .advance, file: .gapAt3, a: .advanced, b: .advanced, sequence: 3),
        .init(id: "main.open.head2-stale", session: .main, operation: .open, file: .head2, a: .staleMembership, b: .staleMembership, sequence: 3),
        .init(id: "fork.init.genesis", session: .fork, operation: .initialize, file: .genesis, a: .initialized, b: .initialized, sequence: 0),
        .init(id: "fork.advance.add-reader", session: .fork, operation: .advance, file: .addReader, a: .advanced, b: .advanced, sequence: 1),
        .init(id: "fork.advance.fork-at-1", session: .fork, operation: .advance, file: .forkAt1, a: .membershipFork, b: .membershipFork, sequence: 1,
              evidence: (.observedSequence, .addReader, .forkAt1)),
        .init(id: "fork.advance.remove-reader-terminal", session: .fork, operation: .advance, file: .removeReader, a: .membershipFork, b: .membershipFork, sequence: 1,
              evidence: (.observedSequence, .addReader, .forkAt1)),
        .init(id: "fork.authorize.head1-terminal", session: .fork, operation: .authorize, file: .head1, a: .membershipFork, b: .membershipFork, sequence: 1,
              evidence: (.observedSequence, .addReader, .forkAt1)),
        .init(id: "fork.open.head1-terminal", session: .fork, operation: .open, file: .head1, a: .membershipFork, b: .membershipFork, sequence: 1,
              evidence: (.observedSequence, .addReader, .forkAt1)),
        .init(id: "contradiction.init.genesis", session: .contradiction, operation: .initialize, file: .genesis, a: .initialized, b: .initialized, sequence: 0),
        .init(id: "contradiction.advance.add-reader", session: .contradiction, operation: .advance, file: .addReader, a: .advanced, b: .advanced, sequence: 1),
        .init(id: "contradiction.advance.contradiction-at-2", session: .contradiction, operation: .advance, file: .contradictionAt2, a: .membershipFork, b: .membershipFork, sequence: 1,
              evidence: (.signedLineageContradiction, .addReader, .contradictionAt2)),
        .init(id: "contradiction.advance.remove-reader-terminal", session: .contradiction, operation: .advance, file: .removeReader, a: .membershipFork, b: .membershipFork, sequence: 1,
              evidence: (.signedLineageContradiction, .addReader, .contradictionAt2)),
        .init(id: "contradiction.open.head1-terminal", session: .contradiction, operation: .open, file: .head1, a: .membershipFork, b: .membershipFork, sequence: 1,
              evidence: (.signedLineageContradiction, .addReader, .contradictionAt2)),
    ]
}

struct MembershipExchangeCaseRecord: Encodable, Sendable {
    let reader: String
    let index: Int
    let id: String
    let outcome: MembershipExchangeOutcome
    let sequence: UInt64
    let head: String
    let evidence: String?
}

struct MembershipExchangeFileRecord: Encodable, Sendable {
    let name: String
    let size: Int
    let sha256: String
}

struct MembershipExchangeBodyRecord: Encodable, Sendable {
    let name: String
    let sequence: UInt64
    let parent: String
    let body: String
}

struct MembershipExchangeCheckpointRecord: Encodable, Sendable {
    let sequence: UInt64
    let head: String
}

struct MembershipExchangeResult: Encodable, Sendable {
    var schema = "agent-vault-membership-exchange-v1"
    let role: String
    let reader: String?
    let platform: String
    let pin: [String: String]
    let files: [MembershipExchangeFileRecord]
    let bodies: [MembershipExchangeBodyRecord]
    let checkpoints: [MembershipExchangeCheckpointRecord]?
    let cases: [MembershipExchangeCaseRecord]?
    var status = "pass"
}

enum MembershipExchangeTrace {
    static let casePrefix = "AV_MEMBERSHIP_CASE_V1 "
    static let resultPrefix = "AV_MEMBERSHIP_RESULT_V1 "
    static let resultLimit = 64 * 1024

    static var platform: String {
        #if os(Linux)
        "linux"
        #else
        "macos"
        #endif
    }

    static func hex(_ data: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        return String(decoding: data.flatMap { [digits[Int($0 >> 4)], digits[Int($0 & 0x0f)]] }, as: UTF8.self)
    }

    static func line(_ prefix: String, _ value: some Encodable) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let line = prefix + String(decoding: try encoder.encode(value), as: UTF8.self) + "\n"
        guard line.utf8.count <= resultLimit else { throw MembershipExchangeFailure.traceOverflow }
        return line
    }

    /// Unbuffered, so case lines stay ordered with the test runner's own issue output.
    static func emit(_ line: String) {
        FileHandle.standardOutput.write(Data(line.utf8))
    }

    static func files(_ files: [MembershipExchangeFile: Data]) -> [MembershipExchangeFileRecord] {
        MembershipExchangeFile.allCases.compactMap { file in
            files[file].map { MembershipExchangeFileRecord(name: file.rawValue, size: $0.count, sha256: hex(Data(SHA256.hash(data: $0)))) }
        }
    }

    static func bodies(_ files: [MembershipExchangeFile: Data]) throws -> [MembershipExchangeBodyRecord] {
        try MembershipExchangeFile.allCases.filter(\.isMembership).compactMap { file in
            guard let bytes = files[file] else { return nil }
            let record = try MembershipRecord.parse(bytes)
            return MembershipExchangeBodyRecord(name: file.rawValue, sequence: record.body.sequence, parent: hex(record.body.parent),
                                                body: hex(Data(SHA256.hash(data: record.bodyBytes))))
        }
    }

    static var pin: [String: String] {
        ["vault": hex(MembershipExchangeOracle.vaultID), "genesisBody": hex(MembershipExchangeOracle.genesisDigest)]
    }
}

enum MembershipExchangeArtifacts {
    static let aggregateLimit = MembershipExchangeFile.allCases.reduce(0) { $0 + $1.maximumSize }

    /// Exact allowlist, non-following type checks and per-file/aggregate bounds before any read.
    /// The owning harness guarantees no concurrent writer; this is not a hostile same-UID sandbox.
    static func load(_ directory: String) throws -> [MembershipExchangeFile: Data] {
        let manager = FileManager.default
        guard (try? manager.attributesOfItem(atPath: directory)[.type] as? FileAttributeType) == .typeDirectory,
              let names = try? manager.contentsOfDirectory(atPath: directory),
              names.count == MembershipExchangeFile.allCases.count,
              Set(names) == Set(MembershipExchangeFile.allCases.map(\.rawValue)) else {
            throw MembershipExchangeFailure.artifactBoundary
        }
        var sizes: [MembershipExchangeFile: Int] = [:]
        for file in MembershipExchangeFile.allCases {
            guard let attributes = try? manager.attributesOfItem(atPath: directory + "/" + file.rawValue),
                  attributes[.type] as? FileAttributeType == .typeRegular,
                  let size = (attributes[.size] as? NSNumber)?.intValue,
                  size >= file.minimumSize, size <= file.maximumSize else {
                throw MembershipExchangeFailure.artifactBoundary
            }
            sizes[file] = size
        }
        guard sizes.values.reduce(0, +) <= aggregateLimit else { throw MembershipExchangeFailure.artifactBoundary }
        var files: [MembershipExchangeFile: Data] = [:]
        for file in MembershipExchangeFile.allCases {
            guard let handle = FileHandle(forReadingAtPath: directory + "/" + file.rawValue) else {
                throw MembershipExchangeFailure.artifactBoundary
            }
            defer { try? handle.close() }
            guard let bytes = try? handle.read(upToCount: file.maximumSize + 1), bytes.count == sizes[file] else { throw MembershipExchangeFailure.artifactBoundary }
            files[file] = bytes
        }
        return files
    }
}

/// Executes the frozen script. An unexpected error where success is expected propagates
/// unchanged, so its fixed enum is the uncaught failure attributed to the last unreported case.
func runMembershipExchangeReader(
    files: [MembershipExchangeFile: Data],
    reader: MembershipExchangeReader,
    onCase: (MembershipExchangeCaseRecord) throws -> Void = { _ in }
) throws -> [MembershipExchangeCaseRecord] {
    let anchor = try MembershipExchangeOracle.anchor()
    let recipient = try reader.agreementKey()
    var sessions: [MembershipExchangeCase.Session: FixtureMembershipSession] = [:]
    var records: [MembershipExchangeCaseRecord] = []
    for (index, step) in MembershipExchangeCase.script.enumerated() {
        guard let bytes = files[step.file] else { throw MembershipExchangeFailure.artifactBoundary }
        let expected = step.expected(reader)
        let observed: MembershipExchangeOutcome
        do {
            if step.operation == .initialize {
                sessions[step.session] = try FixtureMembershipSession(anchor: anchor, genesis: bytes)
                observed = .initialized
            } else {
                guard let session = sessions[step.session] else { throw MembershipExchangeFailure.checkpointMismatch }
                observed = try step.perform(on: session, bytes, recipient: recipient)
            }
        } catch {
            guard expected.matches(error) else { throw error }
            observed = expected
        }
        guard observed == expected else { throw MembershipExchangeFailure.outcomeMismatch }
        guard let session = sessions[step.session], session.checkpoint.sequence == step.sequence,
              Int(step.sequence) < MembershipExchangeOracle.heads.count,
              session.checkpoint.head.bytes == MembershipExchangeOracle.heads[Int(step.sequence)] else {
            throw MembershipExchangeFailure.checkpointMismatch
        }
        if let evidence = step.evidence {
            guard let latched = session.forkEvidence, latched.kind == evidence.kind,
                  latched.firstRecord == files[evidence.first], latched.secondRecord == files[evidence.second] else {
                throw MembershipExchangeFailure.evidenceMismatch
            }
        } else if session.forkEvidence != nil {
            throw MembershipExchangeFailure.evidenceMismatch
        }
        let record = MembershipExchangeCaseRecord(
            reader: reader.rawValue, index: index, id: step.id, outcome: observed, sequence: session.checkpoint.sequence,
            head: MembershipExchangeTrace.hex(session.checkpoint.head.bytes),
            evidence: step.evidence.map { $0.kind == .observedSequence ? "observedSequence" : "signedLineageContradiction" })
        records.append(record)
        try onCase(record)
    }
    return records
}

/// Separate reader process entry point. AV_MEMBERSHIP_READ_DIR names an exchange directory and
/// AV_MEMBERSHIP_READER is exactly A or B. Without them this test performs no fixture I/O.
@Test func membershipExchangeRead() throws {
    let environment = ProcessInfo.processInfo.environment
    _ = try MembershipExchangeOracle.anchor()
    guard let directory = environment[MembershipExchangeEnvironment.readDirectory] else {
        guard environment[MembershipExchangeEnvironment.reader] == nil else { throw MembershipExchangeFailure.environment }
        return
    }
    guard environment[MembershipExchangeEnvironment.writeDirectory] == nil,
          let reader = environment[MembershipExchangeEnvironment.reader].flatMap(MembershipExchangeReader.init(rawValue:)) else {
        throw MembershipExchangeFailure.environment
    }
    let files = try MembershipExchangeArtifacts.load(directory)
    let cases = try runMembershipExchangeReader(files: files, reader: reader) { record in
        MembershipExchangeTrace.emit(try MembershipExchangeTrace.line(MembershipExchangeTrace.casePrefix, record))
    }
    let result = MembershipExchangeResult(role: "reader", reader: reader.rawValue, platform: MembershipExchangeTrace.platform,
                                          pin: MembershipExchangeTrace.pin, files: MembershipExchangeTrace.files(files),
                                          bodies: try MembershipExchangeTrace.bodies(files), checkpoints: nil, cases: cases)
    MembershipExchangeTrace.emit(try MembershipExchangeTrace.line(MembershipExchangeTrace.resultPrefix, result))
}
