"""Frozen synthetic membership specification; no process or filesystem access."""

ORIGINAL_SOURCE = '8d2470defaadd67e255535186c35d876fc80f932a647e4eb83a449f8cf29f076'

ORIGINAL_FILES = {
    'Package.swift': {
        'size': 547,
        'sha256': '86418ff81c07f714f3d4e259f81269e13bbeea47089b8b997669ad92624b8721',
    },
    'Package.resolved': {
        'size': 656,
        'sha256': '655e0a19222701d26fbd709837787af9e3d7a867d2c2e44ebbd966c6e86a747a',
    },
    'Sources/VaultCore/Binary.swift': {
        'size': 3666,
        'sha256': '98ba8309a66aa91c023094ddaebf0f19c2d154635b30d9376b42fbc565a3b6b9',
    },
    'Sources/VaultCore/Model.swift': {
        'size': 3260,
        'sha256': '699579e13c8ddf7ce6d5415439de7906e74466440e163aeb5a994efa3c698625',
    },
    'Sources/VaultCore/Record.swift': {
        'size': 4204,
        'sha256': '5f44daaf42b2654932402d44f1a7d43ca516c33b4267ec70400495a847f82f3a',
    },
    'Sources/VaultCore/RevisionCodec.swift': {
        'size': 4192,
        'sha256': 'fb7cbec6b8697ee90b7ed071aa694aefc8f6db2ad44905b2974dbbe5ee29cdef',
    },
    'Sources/VaultCore/RevisionLog.swift': {
        'size': 1774,
        'sha256': '624cb1d64808dc2bce55aeb300d0d9eab32366ebeed2c98dd38ff8c67bfdc047',
    },
    'Tests/VaultCoreTests/AssociatedDataTests.swift': {
        'size': 5467,
        'sha256': 'fe19fc069c713208d6638ae466273b172040cb4ab9d83ed7bcecfb8d1eb84687',
    },
    'Tests/VaultCoreTests/Fixtures.swift': {
        'size': 4874,
        'sha256': '94824c3350cb6173511d7e5864fa3cc9d2557630ba4e0d936dbfdf9151c6de0e',
    },
    'Tests/VaultCoreTests/FreezeRegressionTests.swift': {
        'size': 3172,
        'sha256': '61fdf53ce13502cb6ce4eb50516bdae027f8ca3e3ef82c0f4e5415dcbd5e4b70',
    },
    'Tests/VaultCoreTests/LowOrderTests.swift': {
        'size': 9110,
        'sha256': '3bd8bf550430e5ee673c94e3a58b4d1c053db18e7fcf2ea5ecca782736078b4b',
    },
    'Tests/VaultCoreTests/ParserTests.swift': {
        'size': 7097,
        'sha256': 'cd71fb500928d1b20cbac75574dd29f7eeafc7081fac61964dee9a5225cf6659',
    },
    'Tests/VaultCoreTests/RevisionTests.swift': {
        'size': 8381,
        'sha256': '07028ee96b22a8c88477fcfc0ef71f600c8269229ffc6ecaf1bb309cf0f801f0',
    },
}

ORIGINAL_NAMES = (
    'allRecipientsAndUnrelatedKey',
    'authenticatedMalformedPlaintextStaysMalformed',
    'bomPrefixedUsernamePreservesExactUTF8',
    'contextComparisonsAndTransplantBinding',
    'ed25519ScalarPlusOrderRejectedByOpenAndLog',
    'fixtureExchange',
    'freshNonceEncapsulationAndDataKey',
    'logPinsAuthorsAndVaultAndStoresExactBytes',
    'lowOrderEncapsulationRejectedAfterSignatureAndContext',
    'lowOrderRecipientValidationPreventsPublicRecovery',
    'malformedHeadersLengthsAndTruncation',
    'maximumRecipientCountRoundTrips',
    'nonzeroStartSlicesOpenAndLogInsertDuplicateConflict',
    'payloadAuthenticationCheckedAfterValidWraps',
    'plaintextParserBoundsUTF8AndCanonicalOrigins',
    'resignedPayloadAndEnvelopeTampering',
    'sealInputBoundsAndCanonicalOrdering',
    'secretDescriptionsAreRedacted',
    'signatureCheckedBeforeIdentityAndDecryption',
    'signedNoncanonicalParentsAndRecipientsAreMalformed',
    'wireLayoutAndAADMatchContract',
)

EXCHANGE_LIMITS = {
    'genesis.avm': (
        233,
        1287,
    ),
    'add-reader.avm': (
        233,
        1287,
    ),
    'remove-reader.avm': (
        233,
        1287,
    ),
    'fork-at-1.avm': (
        233,
        1287,
    ),
    'contradiction-at-2.avm': (
        233,
        1287,
    ),
    'gap-at-3.avm': (
        233,
        1287,
    ),
    'head0.avseal': (
        1,
        266499,
    ),
    'head1.avseal': (
        1,
        266499,
    ),
    'head2.avseal': (
        1,
        266499,
    ),
    'bad-signature.avseal': (
        1,
        266499,
    ),
    'incomplete-recipients.avseal': (
        1,
        266499,
    ),
    'bad-encapsulation.avseal': (
        1,
        266499,
    ),
    'corrupt-wrap.avseal': (
        1,
        266499,
    ),
}

MAX_EXCHANGE = 1873215

MAX_EXCHANGE_JSON = 65536

U1_SCHEMA = 'membership-u1-v1'

U1_SOURCE = '82a8de6cdcc79dacf468dc51b82ee4995beb5f7bd916e70da6428c920f5dbdd9'

U1_FILES = {
    'Package.resolved': {
        'sha256': '655e0a19222701d26fbd709837787af9e3d7a867d2c2e44ebbd966c6e86a747a',
        'size': 656,
    },
    'Package.swift': {
        'sha256': '86418ff81c07f714f3d4e259f81269e13bbeea47089b8b997669ad92624b8721',
        'size': 547,
    },
    'Sources/VaultCore/Binary.swift': {
        'sha256': '98ba8309a66aa91c023094ddaebf0f19c2d154635b30d9376b42fbc565a3b6b9',
        'size': 3666,
    },
    'Sources/VaultCore/FixtureController.swift': {
        'sha256': 'a3740eebd71c11c87bce4a986c21c5ad7ac163bc8cf7cd1f8b804cf16c2126e1',
        'size': 3173,
    },
    'Sources/VaultCore/MembershipCodec.swift': {
        'sha256': '702a09c87a61f5cb076895305f88077233b43770e47118dec12649d6b78bc164',
        'size': 6792,
    },
    'Sources/VaultCore/MembershipSession.swift': {
        'sha256': '3e84164a8e9df77e6f3da1cb2a2e35e6132816fda773da5a8b947e60fc2778e0',
        'size': 5399,
    },
    'Sources/VaultCore/MembershipTypes.swift': {
        'sha256': '7ce2724ad176b861a374d91b789a902a85ea21b312bd6e25802b2cbd204971b0',
        'size': 7189,
    },
    'Sources/VaultCore/Model.swift': {
        'sha256': '699579e13c8ddf7ce6d5415439de7906e74466440e163aeb5a994efa3c698625',
        'size': 3260,
    },
    'Sources/VaultCore/Record.swift': {
        'sha256': '5f44daaf42b2654932402d44f1a7d43ca516c33b4267ec70400495a847f82f3a',
        'size': 4204,
    },
    'Sources/VaultCore/RevisionAuthorization.swift': {
        'sha256': '552f72c1b260747e1eaf678f423eb46cebb0f8938c5bbc55608413bc1d1d7707',
        'size': 2712,
    },
    'Sources/VaultCore/RevisionCodec.swift': {
        'sha256': 'fb7cbec6b8697ee90b7ed071aa694aefc8f6db2ad44905b2974dbbe5ee29cdef',
        'size': 4192,
    },
    'Sources/VaultCore/RevisionLog.swift': {
        'sha256': '624cb1d64808dc2bce55aeb300d0d9eab32366ebeed2c98dd38ff8c67bfdc047',
        'size': 1774,
    },
    'Tests/VaultCoreTests/AssociatedDataTests.swift': {
        'sha256': 'fe19fc069c713208d6638ae466273b172040cb4ab9d83ed7bcecfb8d1eb84687',
        'size': 5467,
    },
    'Tests/VaultCoreTests/Fixtures.swift': {
        'sha256': '94824c3350cb6173511d7e5864fa3cc9d2557630ba4e0d936dbfdf9151c6de0e',
        'size': 4874,
    },
    'Tests/VaultCoreTests/FreezeRegressionTests.swift': {
        'sha256': '61fdf53ce13502cb6ce4eb50516bdae027f8ca3e3ef82c0f4e5415dcbd5e4b70',
        'size': 3172,
    },
    'Tests/VaultCoreTests/LowOrderTests.swift': {
        'sha256': '3bd8bf550430e5ee673c94e3a58b4d1c053db18e7fcf2ea5ecca782736078b4b',
        'size': 9110,
    },
    'Tests/VaultCoreTests/MembershipExchangeTests.swift': {
        'sha256': 'c27efc6c263fe899b58ed2fd764be2e75d63d0bb0ef3b558b234472a31e16955',
        'size': 9398,
    },
    'Tests/VaultCoreTests/MembershipFixtures.swift': {
        'sha256': '16ec17672fec1f27c19634716c28f611f511f5324eb9e1e3c8795a38772813bb',
        'size': 14676,
    },
    'Tests/VaultCoreTests/MembershipReaderFixtures.swift': {
        'sha256': '3540cd23c04488734056bcec0716566986063e8fa88c87ca1f9f1e4d28b91c73',
        'size': 21928,
    },
    'Tests/VaultCoreTests/MembershipTests.swift': {
        'sha256': '3afefd77da54c3b810011767ad03f29dfe45c628501ba23135ddd49710d61ce0',
        'size': 32570,
    },
    'Tests/VaultCoreTests/ParserTests.swift': {
        'sha256': 'cd71fb500928d1b20cbac75574dd29f7eeafc7081fac61964dee9a5225cf6659',
        'size': 7097,
    },
    'Tests/VaultCoreTests/RevisionAuthorizationTests.swift': {
        'sha256': '2e61b45b9afa9ec54851f5bbe5082c0db4a0b8234b36799dfc8b422d054147ca',
        'size': 19384,
    },
    'Tests/VaultCoreTests/RevisionTests.swift': {
        'sha256': '07028ee96b22a8c88477fcfc0ef71f600c8269229ffc6ecaf1bb309cf0f801f0',
        'size': 8381,
    },
    'Tests/VaultCoreTests/SignatureCompatibilityTests.swift': {
        'sha256': '53ec6399ff738b9596e0f418494f3d2fa555f1e910251114eed9e4c83ec9c370',
        'size': 3991,
    },
    'Tests/VaultCoreTests/SignatureCorpus.swift': {
        'sha256': '9bedd0d081b524f8d32427c73f4a03ae7c053197467ebfa8d7be01517df1479c',
        'size': 40660,
    },
}

U1_NAMES = (
    'allRecipientsAndUnrelatedKey',
    'authenticatedMalformedPlaintextStaysMalformed',
    'bomPrefixedUsernamePreservesExactUTF8',
    'contextComparisonsAndTransplantBinding',
    'ed25519ScalarPlusOrderRejectedByOpenAndLog',
    'fixtureExchange',
    'freshNonceEncapsulationAndDataKey',
    'logPinsAuthorsAndVaultAndStoresExactBytes',
    'lowOrderEncapsulationRejectedAfterSignatureAndContext',
    'lowOrderRecipientValidationPreventsPublicRecovery',
    'malformedHeadersLengthsAndTruncation',
    'maximumRecipientCountRoundTrips',
    'membershipBodyIdentityIgnoresSignatureRandomization',
    'membershipBootstrapRejectsUntrustedGenesis',
    'membershipChangedWriterAtObservedSequenceLatches',
    'membershipContiguousLineageAndDuplicates',
    'membershipDiagnosticsAreRedacted',
    'membershipExchangeProduce',
    'membershipExchangeRead',
    'membershipExchangeScriptCoversEveryArtifactAndReaderDifference',
    'membershipForgedSuccessorIsRejectedUnchanged',
    'membershipHistoryCapacityAndAtomicity',
    'membershipHostileStructureIsMalformedWithoutState',
    'membershipLineageContradictionAndGaps',
    'membershipMemberPolicyAndKeyHostility',
    'membershipMintingRejectsInvalidAuthority',
    'membershipObservedSequenceForkLatches',
    'membershipObservedSequenceForksAndPoisoningResistance',
    'membershipSequenceArithmeticIsChecked',
    'membershipSignedGapIsMissingPredecessor',
    'membershipWireLayoutMatchesContract',
    'membershipWriterDisableRetainOmitAndReenable',
    'membershipWrongParentLatchesLineageContradiction',
    'nonzeroStartSlicesOpenAndLogInsertDuplicateConflict',
    'payloadAuthenticationCheckedAfterValidWraps',
    'plaintextParserBoundsUTF8AndCanonicalOrigins',
    'resignedPayloadAndEnvelopeTampering',
    'revisionAuthorizationCheckOrder',
    'revisionAuthorizationIdentityAndCapability',
    'revisionCurrentHeadLimitationAndRequestingRecipient',
    'revisionEveryEncapsulationIsValidated',
    'revisionFromDisabledWriterIsUnauthorized',
    'revisionMaliciousWriterBounds',
    'revisionMissingRecipientIsRejected',
    'revisionPolicyOpenReturnsSyntheticItem',
    'revisionRecipientSetMustMatchExactly',
    'revisionStaleAfterNoOpSuccessor',
    'revisionUnselectedLowOrderEncapsulationIsRejected',
    'sealInputBoundsAndCanonicalOrdering',
    'secretDescriptionsAreRedacted',
    'signatureCheckedBeforeIdentityAndDecryption',
    'signedNoncanonicalParentsAndRecipientsAreMalformed',
    'wireLayoutAndAADMatchContract',
    'wycheproofEd25519ExpectedOutcomes',
    'wycheproofEd25519TableProvenanceAndCoverage',
)

CORPUS_SHA = '496a1ecd43c48c74355ee170a498064e4b1c89162b84c0322352450f1fce34e9'

TABLE_SHA = 'e8ab9314a0f44531529f582847f21bb3acda8a416bd10fc8ece92ebd58077088'

CRYPTO_REVISION = 'c2cbadd7263439d8015189668f96ff5b5be565ce'

READER_SOURCE = 'Tests/VaultCoreTests/MembershipReaderFixtures.swift'

PRODUCER_TEST = 'membershipExchangeProduce'

READER_TEST = 'membershipExchangeRead'

CASE_PREFIX = 'AV_MEMBERSHIP_CASE_V1 '

RESULT_PREFIX = 'AV_MEMBERSHIP_RESULT_V1 '

CORPUS_PREFIX = 'AV_SIGNATURE_CORPUS_V1 '

OPENSSL = '/opt/homebrew/bin/openssl'

EXCHANGE_ORDER = (
    'genesis.avm',
    'add-reader.avm',
    'remove-reader.avm',
    'head0.avseal',
    'head1.avseal',
    'head2.avseal',
    'bad-signature.avseal',
    'incomplete-recipients.avseal',
    'bad-encapsulation.avseal',
    'corrupt-wrap.avseal',
    'fork-at-1.avm',
    'contradiction-at-2.avm',
    'gap-at-3.avm',
)

BODY_PINS = {
    'genesis.avm': 'a7b6578a9dc51eb7b3b2966b55c79db0daa6ced89851cd2a4d8714c797c16eaf',
    'add-reader.avm': '368357653056c0d54205dbd259f3f575ee2c4ce1c8f2ed7f6247ee8d6504bd79',
    'remove-reader.avm': 'dbbfc5dcead52a8e76f69534790a5d9078516e5777cbcdecf68ff787cb8d251f',
    'gap-at-3.avm': '4630ded00a362488d993f2fe1d4ef679abc0d37c731c0c1ed38e1b43f90d30b4',
    'fork-at-1.avm': '5ac8f9d140e8490ae14dd7d842b8e9df2bc4d749ef6de805c427bcc013fb0117',
    'contradiction-at-2.avm': 'd829a5fb8e851dc488bcbb04b7db55cad538cb7bc8591581f39b86f788400866',
}

HEADS = (
    'a7b6578a9dc51eb7b3b2966b55c79db0daa6ced89851cd2a4d8714c797c16eaf',
    '368357653056c0d54205dbd259f3f575ee2c4ce1c8f2ed7f6247ee8d6504bd79',
    'dbbfc5dcead52a8e76f69534790a5d9078516e5777cbcdecf68ff787cb8d251f',
    '4630ded00a362488d993f2fe1d4ef679abc0d37c731c0c1ed38e1b43f90d30b4',
)

CASE_TABLE = (
    (
        'main.init.genesis',
        'initialized',
        0,
    ),
    (
        'main.open.head0',
        'opened',
        0,
    ),
    (
        'main.advance.add-reader',
        'advanced',
        1,
    ),
    (
        'main.advance.genesis-duplicate',
        'duplicate',
        1,
    ),
    (
        'main.open.head0-stale',
        'staleMembership',
        1,
    ),
    (
        'main.open.head1',
        'opened',
        1,
    ),
    (
        'main.authorize.bad-signature',
        'badSignature',
        1,
    ),
    (
        'main.authorize.incomplete-recipients',
        'recipientSetMismatch',
        1,
    ),
    (
        'main.authorize.bad-encapsulation',
        'invalidEncapsulation',
        1,
    ),
    (
        'main.authorize.corrupt-wrap',
        'authorized',
        1,
    ),
    (
        'main.open.corrupt-wrap',
        'opened',
        1,
    ),
    (
        'main.advance.gap-at-3',
        'missingPredecessor',
        1,
    ),
    (
        'main.advance.remove-reader',
        'advanced',
        2,
    ),
    (
        'main.advance.add-reader-duplicate',
        'duplicate',
        2,
    ),
    (
        'main.open.head1-stale',
        'staleMembership',
        2,
    ),
    (
        'main.open.head2',
        'opened',
        2,
    ),
    (
        'main.advance.gap-at-3-linked',
        'advanced',
        3,
    ),
    (
        'main.open.head2-stale',
        'staleMembership',
        3,
    ),
    (
        'fork.init.genesis',
        'initialized',
        0,
    ),
    (
        'fork.advance.add-reader',
        'advanced',
        1,
    ),
    (
        'fork.advance.fork-at-1',
        'membershipFork',
        1,
    ),
    (
        'fork.advance.remove-reader-terminal',
        'membershipFork',
        1,
    ),
    (
        'fork.authorize.head1-terminal',
        'membershipFork',
        1,
    ),
    (
        'fork.open.head1-terminal',
        'membershipFork',
        1,
    ),
    (
        'contradiction.init.genesis',
        'initialized',
        0,
    ),
    (
        'contradiction.advance.add-reader',
        'advanced',
        1,
    ),
    (
        'contradiction.advance.contradiction-at-2',
        'membershipFork',
        1,
    ),
    (
        'contradiction.advance.remove-reader-terminal',
        'membershipFork',
        1,
    ),
    (
        'contradiction.open.head1-terminal',
        'membershipFork',
        1,
    ),
)

ORACLE_KEYS = (
    'controller',
    'writer',
    'writer-agreement',
    'reader-a',
    'reader-b',
)

ORACLE_SEEDS = (
    (
        'ed25519',
        193,
    ),
    (
        'ed25519',
        194,
    ),
    (
        'x25519',
        195,
    ),
    (
        'x25519',
        209,
    ),
    (
        'x25519',
        210,
    ),
)

READER_FAILURE_REMARKS = (
    '↳ /// Separate reader process entry point. AV_MEMBERSHIP_READ_DIR names an exchange directory and',
    '↳ /// AV_MEMBERSHIP_READER is exactly A or B. Without them this test performs no fixture I/O.',
)

U1_DETECTORS = {
    'M1': {
        'test': 'membershipForgedSuccessorIsRejectedUnchanged',
        'location': 'MembershipTests.swift:471:28',
        'message': 'Issue recorded',
        'detail': 'Expected fixed membership error',
    },
    'M2': {
        'test': 'membershipSignedGapIsMissingPredecessor',
        'location': 'MembershipTests.swift:479:28',
        'message': 'Issue recorded',
        'detail': 'Expected fixed membership error',
    },
    'M3': {
        'test': 'membershipObservedSequenceForkLatches',
        'location': 'MembershipTests.swift:487:20',
        'message': 'Expectation failed: (actual → missingPredecessor) == (.membershipFork → membershipFork)',
        'detail': None,
    },
    'M4': {
        'test': 'membershipWrongParentLatchesLineageContradiction',
        'location': 'MembershipTests.swift:499:20',
        'message': 'Expectation failed: (actual → malformed) == (.membershipFork → membershipFork)',
        'detail': None,
    },
    'M5': {
        'test': 'membershipChangedWriterAtObservedSequenceLatches',
        'location': 'MembershipTests.swift:510:20',
        'message': 'Expectation failed: (actual → unsupportedAuthorityChange) == (.membershipFork → membershipFork)',
        'detail': None,
    },
    'M6': {
        'test': 'revisionStaleAfterNoOpSuccessor',
        'location': 'RevisionAuthorizationTests.swift:285:22',
        'message': 'Issue recorded',
        'detail': 'Expected fixed membership error',
    },
    'M7': {
        'test': 'revisionFromDisabledWriterIsUnauthorized',
        'location': 'RevisionAuthorizationTests.swift:292:22',
        'message': 'Issue recorded',
        'detail': 'Expected fixed membership error',
    },
    'M8': {
        'test': 'revisionMissingRecipientIsRejected',
        'location': 'RevisionAuthorizationTests.swift:298:22',
        'message': 'Issue recorded',
        'detail': 'Expected fixed membership error',
    },
    'M9': {
        'test': 'revisionUnselectedLowOrderEncapsulationIsRejected',
        'location': 'RevisionAuthorizationTests.swift:307:22',
        'message': 'Issue recorded',
        'detail': 'Expected fixed membership error',
    },
    'M10': {
        'test': 'revisionPolicyOpenReturnsSyntheticItem',
        'location': None,
        'message': None,
        'detail': None,
    },
}

U1_MUTATIONS = {
    'M1': {
        'file': 'Sources/VaultCore/MembershipSession.swift',
        'old': b"""        guard controller.isValidSignature(record.signature, for: record.bodyBytes) else {
            throw MembershipPolicyError.badMembershipSignature
        }
""",
        'new': b'',
    },
    'M2': {
        'file': 'Sources/VaultCore/MembershipSession.swift',
        'old': b"""        guard body.sequence == next else { throw MembershipPolicyError.missingPredecessor }
""",
        'new': b'',
    },
    'M3': {
        'file': 'Sources/VaultCore/MembershipSession.swift',
        'old': b"""            try latch(.observedSequence, first: retained, second: record.encoded)
""",
        'new': b'',
    },
    'M4': {
        'file': 'Sources/VaultCore/MembershipSession.swift',
        'old': b"""        guard body.parent == checkpoint.head.bytes else {
            try latch(.signedLineageContradiction, first: history[history.count - 1], second: record.encoded)
        }
""",
        'new': b'',
    },
    'M5': {
        'file': 'Sources/VaultCore/MembershipSession.swift',
        'old': b"""        if let index = MembershipSequence.historyIndex(of: body.sequence, current: checkpoint.sequence) {
            let retained = history[index]
            if retained.prefix(retained.count - MembershipBody.signatureSize) == record.bodyBytes {
                return .duplicate(checkpoint)
            }
            try latch(.observedSequence, first: retained, second: record.encoded)
        }
        let next = try MembershipSequence.successor(after: checkpoint.sequence)
        guard body.sequence == next else { throw MembershipPolicyError.missingPredecessor }
        guard body.parent == checkpoint.head.bytes else {
            try latch(.signedLineageContradiction, first: history[history.count - 1], second: record.encoded)
        }
        guard body.writerKey == authority.writerKey else { throw MembershipPolicyError.unsupportedAuthorityChange }
        let membership = try MembershipPolicy.validate(rows: body.rows, pinnedWriterAgreement: authority.writerAgreementKey)
""",
        'new': b"""        guard body.writerKey == authority.writerKey else { throw MembershipPolicyError.unsupportedAuthorityChange }
        let membership = try MembershipPolicy.validate(rows: body.rows, pinnedWriterAgreement: authority.writerAgreementKey)
        if let index = MembershipSequence.historyIndex(of: body.sequence, current: checkpoint.sequence) {
            let retained = history[index]
            if retained.prefix(retained.count - MembershipBody.signatureSize) == record.bodyBytes {
                return .duplicate(checkpoint)
            }
            try latch(.observedSequence, first: retained, second: record.encoded)
        }
        let next = try MembershipSequence.successor(after: checkpoint.sequence)
        guard body.sequence == next else { throw MembershipPolicyError.missingPredecessor }
        guard body.parent == checkpoint.head.bytes else {
            try latch(.signedLineageContradiction, first: history[history.count - 1], second: record.encoded)
        }
""",
    },
    'M6': {
        'file': 'Sources/VaultCore/RevisionAuthorization.swift',
        'old': b"""        guard context.membershipHead == checkpoint.head.bytes else { throw MembershipPolicyError.staleMembership }
""",
        'new': b'',
    },
    'M7': {
        'file': 'Sources/VaultCore/RevisionAuthorization.swift',
        'old': b"""        guard membership.writerActive else { throw MembershipPolicyError.unauthorizedAuthor }
""",
        'new': b'',
    },
    'M8': {
        'file': 'Sources/VaultCore/RevisionAuthorization.swift',
        'old': b"""        guard parsed.envelopes.map(\\.sortKey) == membership.recipients else {
""",
        'new': b"""        guard Set(parsed.envelopes.map(\\.sortKey)).isSubset(of: membership.recipients) else {
""",
    },
    'M9': {
        'file': 'Sources/VaultCore/RevisionAuthorization.swift',
        'old': b"""        for envelope in parsed.envelopes {
            do {
                try validateX25519PublicKey(Curve25519.KeyAgreement.PublicKey(rawRepresentation: envelope.encapsulatedKey))
            } catch {
                throw MembershipPolicyError.invalidEncapsulation
            }
        }
""",
        'new': b'',
    },
    'M10': {
        'file': 'Sources/VaultCore/RevisionCodec.swift',
        'old': b"""        plaintext = try ChaChaPoly.open(payload, using: SymmetricKey(data: keyBytes), authenticating: record.payloadAAD)
""",
        'new': b"""        plaintext = try ChaChaPoly.open(payload, using: SymmetricKey(data: keyBytes), authenticating: record.payloadAAD)
        print(String(decoding: plaintext, as: UTF8.self))
""",
    },
}

# One exchange sequence drives both the live run and strict receipt replay.
EXCHANGE_STEPS = (
    ("produce", "producer", None),
    ("read-a", "reader", "A"),
    ("read-b", "reader", "B"),
    ("negative-read-a", "negative", "A"),
    ("read-a-restored", "restored", "A"),
)

# N1 uses the same source/patch construction as all policy controls.
MUTATIONS = {
    **U1_MUTATIONS,
    "N1": {
        "file": "Sources/VaultCore/RevisionCodec.swift",
        "old": b"        try validateX25519PublicKey(encapsulatedKey)\n",
        "new": b"",
    },
}
