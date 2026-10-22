import Crypto
import Foundation
import Testing
@testable import VaultCore

/// Producer side of the bidirectional exchange. Authority keys exist only inside these calls.
enum MembershipExchangeProducer {
    struct Output {
        let files: [MembershipExchangeFile: Data]
        let checkpoints: [MembershipCheckpoint]
    }

    static func authority() throws -> MembershipAuthority {
        try MembershipAuthority(vaultID: MembershipExchangeOracle.vaultID)
    }

    static func members(_ authority: MembershipAuthority, withB: Bool) throws -> [FixtureMember] {
        let readers = withB ? [MembershipExchangeReader.a, .b] : [.a]
        return try [authority.writerMember()] + readers.map { try FixtureMember.reader($0.agreementKey().publicKey) }
    }

    static func recipients(_ authority: MembershipAuthority, withB: Bool) throws -> [(RecipientRole, Curve25519.KeyAgreement.PublicKey)] {
        let readers = withB ? [MembershipExchangeReader.a, .b] : [.a]
        return try [(.device, authority.writerAgreement.publicKey)] + readers.map { (.device, try $0.agreementKey().publicKey) }
    }

    static func genesis(_ authority: MembershipAuthority) throws -> (record: Data, anchor: FixtureTrustAnchor) {
        try authority.genesis(members(authority, withB: false))
    }

    static func produce() throws -> Output {
        let authority = try authority()
        let minted = try genesis(authority)
        guard minted.anchor.genesis.bytes == MembershipExchangeOracle.genesisDigest else {
            throw MembershipExchangeFailure.checkpointMismatch
        }
        // The producer's own verifier session supplies every checkpoint used for minting.
        let verifier = try FixtureMembershipSession(anchor: minted.anchor, genesis: minted.record)
        let h0 = verifier.checkpoint
        let addReader = try authority.advance(verifier, members(authority, withB: true))
        let h1 = verifier.checkpoint
        let removeReader = try authority.advance(verifier, members(authority, withB: false))
        let h2 = verifier.checkpoint
        let gap = try authority.advance(verifier, members(authority, withB: false))
        let h3 = verifier.checkpoint
        let fork = try authority.successor(h0, members(authority, withB: false))
        var contradictionBody = authority.body(after: h1, rows: try members(authority, withB: false).map(\.row))
        contradictionBody.parent = MembershipExchangeOracle.nonexistentParent
        let contradiction = try authority.signed(contradictionBody)

        func seal(_ file: MembershipExchangeFile, at checkpoint: MembershipCheckpoint, withB: Bool) throws -> Data {
            let context = try RevisionContext(vaultID: authority.vaultID.bytes, itemID: MembershipExchangeOracle.itemID,
                                              revisionID: file.revisionID, membershipHead: checkpoint.head.bytes)
            return try authority.seal(context, recipients(authority, withB: withB), item: MembershipExchangeOracle.item(file))
        }
        var badSignature = try seal(.badSignature, at: h1, withB: true)
        badSignature[badSignature.count - 1] ^= 0x01
        var badEncapsulation = try SealedRecord.parse(seal(.badEncapsulation, at: h1, withB: true))
        guard let writerEnvelope = badEncapsulation.envelopes.firstIndex(where: {
            $0.publicKey == authority.writerAgreement.publicKey.rawRepresentation
        }) else { throw MembershipExchangeFailure.artifactWrite }
        badEncapsulation.envelopes[writerEnvelope].encapsulatedKey = membershipLowOrderEncodings()[2]
        var corruptWrap = try SealedRecord.parse(seal(.corruptWrap, at: h1, withB: true))
        let readerB = try MembershipExchangeReader.b.agreementKey().publicKey.rawRepresentation
        guard let bEnvelope = corruptWrap.envelopes.firstIndex(where: { $0.publicKey == readerB }) else {
            throw MembershipExchangeFailure.artifactWrite
        }
        corruptWrap.envelopes[bEnvelope].ciphertext[0] ^= 0x01

        let files: [MembershipExchangeFile: Data] = [
            .genesis: minted.record, .addReader: addReader, .removeReader: removeReader,
            .head0: try seal(.head0, at: h0, withB: false), .head1: try seal(.head1, at: h1, withB: true),
            .head2: try seal(.head2, at: h2, withB: false), .badSignature: badSignature,
            .incompleteRecipients: try seal(.incompleteRecipients, at: h1, withB: false),
            .badEncapsulation: try authority.resign(badEncapsulation), .corruptWrap: try authority.resign(corruptWrap),
            .forkAt1: fork, .contradictionAt2: contradiction, .gapAt3: gap,
        ]
        let pinned: [(MembershipExchangeFile, Data)] = [
            (.genesis, MembershipExchangeOracle.genesisDigest), (.addReader, MembershipExchangeOracle.addReaderDigest),
            (.removeReader, MembershipExchangeOracle.removeReaderDigest), (.gapAt3, MembershipExchangeOracle.gapDigest),
            (.forkAt1, MembershipExchangeOracle.forkDigest), (.contradictionAt2, MembershipExchangeOracle.contradictionDigest),
        ]
        for (file, digest) in pinned {
            guard let bytes = files[file], try MembershipRecord.parse(bytes).bodyBytes == bytes.prefix(bytes.count - 64),
                  Data(SHA256.hash(data: bytes.prefix(bytes.count - 64))) == digest else {
                throw MembershipExchangeFailure.checkpointMismatch
            }
        }
        guard [h0, h1, h2, h3].map(\.head.bytes) == MembershipExchangeOracle.heads else {
            throw MembershipExchangeFailure.checkpointMismatch
        }
        return Output(files: files, checkpoints: [h0, h1, h2, h3])
    }

    static func write(_ files: [MembershipExchangeFile: Data], to directory: String) throws {
        let manager = FileManager.default
        guard !manager.fileExists(atPath: directory) else { throw MembershipExchangeFailure.artifactWrite }
        do {
            try manager.createDirectory(atPath: directory, withIntermediateDirectories: false,
                                        attributes: [.posixPermissions: 0o700])
        } catch {
            throw MembershipExchangeFailure.artifactWrite
        }
        for file in MembershipExchangeFile.allCases {
            let path = directory + "/" + file.rawValue
            guard let bytes = files[file],
                  manager.createFile(atPath: path, contents: bytes, attributes: [.posixPermissions: 0o600]),
                  (try? manager.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber)?.intValue == 0o600 else {
                throw MembershipExchangeFailure.artifactWrite
            }
        }
        guard (try? manager.attributesOfItem(atPath: directory)[.posixPermissions] as? NSNumber)?.intValue == 0o700 else {
            throw MembershipExchangeFailure.artifactWrite
        }
    }
}

/// Producer process entry point. AV_MEMBERSHIP_WRITE_DIR names a new directory to create.
/// Without it, production and self-validation run in memory with no fixture I/O and no output.
@Test func membershipExchangeProduce() throws {
    let environment = ProcessInfo.processInfo.environment
    guard environment[MembershipExchangeEnvironment.readDirectory] == nil,
          environment[MembershipExchangeEnvironment.reader] == nil else {
        throw MembershipExchangeFailure.environment
    }
    let output = try MembershipExchangeProducer.produce()
    for reader in MembershipExchangeReader.allCases {
        _ = try runMembershipExchangeReader(files: output.files, reader: reader)
    }
    guard let directory = environment[MembershipExchangeEnvironment.writeDirectory] else { return }
    try MembershipExchangeProducer.write(output.files, to: directory)
    let written = try MembershipExchangeArtifacts.load(directory)
    #expect(written == output.files)
    for reader in MembershipExchangeReader.allCases {
        _ = try runMembershipExchangeReader(files: written, reader: reader)
    }
    let result = MembershipExchangeResult(
        role: "producer", reader: nil, platform: MembershipExchangeTrace.platform, pin: MembershipExchangeTrace.pin,
        files: MembershipExchangeTrace.files(written), bodies: try MembershipExchangeTrace.bodies(written),
        checkpoints: output.checkpoints.map {
            MembershipExchangeCheckpointRecord(sequence: $0.sequence, head: MembershipExchangeTrace.hex($0.head.bytes))
        },
        cases: nil)
    MembershipExchangeTrace.emit(try MembershipExchangeTrace.line(MembershipExchangeTrace.resultPrefix, result))
}

@Test func membershipExchangeScriptCoversEveryArtifactAndReaderDifference() throws {
    let script = MembershipExchangeCase.script
    #expect(Set(script.map(\.id)).count == script.count)
    #expect(Set(script.map(\.file)) == Set(MembershipExchangeFile.allCases))
    #expect(MembershipExchangeFile.allCases.count == 13)
    #expect(MembershipExchangeFile.allCases.filter(\.isMembership).count == 6)
    #expect(MembershipExchangeArtifacts.aggregateLimit == 1_873_215)
    let firstHead1 = try #require(script.firstIndex { $0.file == .head1 })
    #expect(script[firstHead1].id == "main.open.head1" && script[firstHead1].a == .opened)
    let differences = script.filter { $0.a != $0.b }.map(\.id)
    #expect(differences == ["main.open.head0", "main.open.corrupt-wrap", "main.open.head2"])
    #expect(MembershipExchangeOracle.heads.allSatisfy { $0.count == 32 })
}
