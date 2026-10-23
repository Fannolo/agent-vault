import Foundation
import Testing
import VaultPersistence
import VaultPersistenceTestSupport
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

@Test(arguments: TestOnlyFileCustodyPin.Fault.allCases)
func pinFailuresNeverAcknowledge(fault: TestOnlyFileCustodyPin.Fault) throws {
    let box = try Sandbox()
    let old = Synthetic.state(seed: 1)
    let next = Synthetic.state(seed: 2)
    _ = try box.create()
    do {
        let kernel = try box.open(fault: fault)
        let error = failure { try kernel.commit(expecting: kernel.head, next: next, adding: Synthetic.objects(seed: 2, count: 1, size: 64)) }
        let step: AmbiguousStep = [.prepareBeforeWrite, .prepareAfterPersist, .prepareFsync].contains(fault) ? .custodyPrepare : .custodyFinish
        #expect(error == .recoveryRequired(step), "NAMED: pin failure never acknowledged")
        #expect(kernel.head.state == old.id, "NAMED: acknowledged head unchanged")
        #expect(failure { try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 3), adding: []) }
                == .recoveryRequired(step), "NAMED: admission blocked until recovery")
        #expect(failure { try kernel.state() } == .recoveryRequired(step), "NAMED: reads blocked until recovery")
    }
    let reachedDatabase = [.finishBeforeWrite, .finishAfterPersist, .finishFsync].contains(fault)
    let expected = reachedDatabase ? next : old
    let kernel = try box.open()
    #expect(kernel.head.state == expected.id, "NAMED: restart resolves the pin")
    #expect(try box.pinRecord() == .stable(Head(generation: reachedDatabase ? 1 : 0, state: expected.id)), "NAMED: restart leaves a stable pin")
    #expect(try RawDatabase.read(box.database).objects.count == (reachedDatabase ? 1 : 0), "NAMED: objects follow the state")
}

@Test func objectsAreImmutableAndIdempotent() throws {
    let box = try Sandbox()
    let kernel = try box.create()
    let objects = Synthetic.objects(seed: 5, count: 2, size: 128)
    var head = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: objects + objects)
    head = try kernel.commit(expecting: head, next: Synthetic.state(seed: 3), adding: [objects[1]])
    let image = try RawDatabase.read(box.database)
    #expect(image.objects.count == 2 && image.objectCount == 2, "NAMED: duplicates stored once")
    #expect(image.objects[objects[1].digest.bytes]?.generation == 1, "NAMED: duplicate keeps first admission")
    #expect(try kernel.object(objects[0].digest) == objects[0])
    #expect(try kernel.object(SignedObject(bytes: [9]).digest) == nil)

    let wrong = SignedObject(bytes: [1, 2, 3]).digest
    #expect(failure { try SignedObject(bytes: [4, 5, 6], expectedDigest: wrong) } == .refused(.digestMismatch),
            "NAMED: claimed digest must match")

    // Substitute stored bytes underneath the open owner, then re-admit the honest object.
    try RawDatabase.execute(box.database, "UPDATE objects SET bytes = ?1 WHERE digest = ?2",
                            blobs: [[0xee], objects[0].digest.bytes])
    #expect(failure { try kernel.commit(expecting: head, next: Synthetic.state(seed: 4), adding: [objects[0]]) }
            == .locked(.objectCorrupt), "NAMED: substituted object refused")
    #expect(failure { try kernel.commit(expecting: head, next: Synthetic.state(seed: 4), adding: []) }
            == .recoveryRequired(.integrity), "NAMED: substitution blocks admission")
    #expect(try RawDatabase.read(box.database).stateID == Synthetic.state(seed: 3).id.bytes)
}

@Test func boundsRefuseAndRetainState() throws {
    #expect(failure { try KernelLimits(maxObjectBytes: 0, maxStateBytes: 1, maxObjectCount: 1, maxTotalObjectBytes: 1) }
            == .refused(.invalidLimits))
    let limits = try KernelLimits(maxObjectBytes: 64, maxStateBytes: 600, maxObjectCount: 3, maxTotalObjectBytes: 150)
    let box = try Sandbox()
    let kernel = try box.create(limits: limits)
    let start = kernel.head
    let object = { (seed: UInt64, size: Int) in SignedObject(bytes: Array(Synthetic.bytes("o", seed: seed, count: max(64, size)).suffix(size))) }
    let refusals: [([SignedObject], SealedState, Refusal)] = [
        ([object(1, 65)], Synthetic.state(seed: 2), .objectTooLarge),
        ([], Synthetic.state(seed: 2, count: 601), .stateTooLarge),
        ([], SealedState(frame: []), .emptyState),
        ([SignedObject(bytes: [])], Synthetic.state(seed: 2), .emptyObject),
        ([], Synthetic.state(seed: 1), .stateUnchanged),
        ((1...4).map { object($0, 8) }, Synthetic.state(seed: 2), .objectCountExhausted),
        ((1...3).map { object($0, 60) }, Synthetic.state(seed: 2), .objectBytesExhausted),
    ]
    for (objects, state, refusal) in refusals {
        #expect(failure { try kernel.commit(expecting: start, next: state, adding: objects) } == .refused(refusal),
                "NAMED: bound refused \(refusal)")
        #expect(kernel.head == start, "NAMED: refusal retains state")
    }
    var head = try kernel.commit(expecting: start, next: Synthetic.state(seed: 2), adding: [object(1, 64), object(2, 64)])
    #expect(failure { try kernel.commit(expecting: head, next: Synthetic.state(seed: 3), adding: [object(3, 64)]) }
            == .refused(.objectBytesExhausted), "NAMED: cumulative bytes bounded")
    head = try kernel.commit(expecting: head, next: Synthetic.state(seed: 3), adding: [object(3, 8)])
    #expect(failure { try kernel.commit(expecting: head, next: Synthetic.state(seed: 4), adding: [object(4, 8)]) }
            == .refused(.objectCountExhausted), "NAMED: cumulative count bounded")
    #expect(failure { try kernel.commit(expecting: start, next: Synthetic.state(seed: 5), adding: []) }
            == .refused(.staleHead), "NAMED: stale expected head refused")
    head = try kernel.commit(expecting: head, next: Synthetic.state(seed: 6), adding: [])
    #expect(head.generation == 3)
    let image = try RawDatabase.read(box.database)
    #expect(image.objectCount == 3 && image.objectBytes == 136 && image.state == Synthetic.state(seed: 6).frame,
            "NAMED: only accepted commits persisted")

}

@Test func openingWithSmallerLimitsLocks() throws {
    let box = try Sandbox()
    do {
        let kernel = try box.create()
        _ = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2),
                              adding: Synthetic.objects(seed: 2, count: 3, size: 32))
    }
    let small = try KernelLimits(maxObjectBytes: 64, maxStateBytes: 600, maxObjectCount: 2, maxTotalObjectBytes: 150)
    #expect(failure { try box.open(limits: small) } == .locked(.exceedsLimits), "NAMED: stored data beyond limits locks")
}

@Test func leaseReplacementBlocksCommit() throws {
    let box = try Sandbox()
    let kernel = try box.create()
    rename(box.lease, box.base + "/old-lease")
    let replacement = open(box.lease, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    close(replacement)
    #expect(failure { try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: []) }
            == .locked(.leaseReplaced), "NAMED: replaced lease refuses commit")
    #expect(failure { try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: []) }
            == .recoveryRequired(.integrity), "NAMED: replaced lease blocks admission")
    #expect(try RawDatabase.read(box.database).generation == 0)
}

@Test func settingsAreReadBack() throws {
    let box = try Sandbox()
    let kernel = try box.create()
    #expect(kernel.settings == .required, "NAMED: durability settings read back")
    #expect(kernel.settings.journalMode == "delete" && kernel.settings.synchronous == 3)
    let runtime = SQLiteRuntime.current()
    #expect(!runtime.libraryVersion.isEmpty && !runtime.compileOptions.isEmpty)
    _ = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: 2), adding: [SignedObject(bytes: [1])])
    #expect(box.entries() == [VaultKernel.leaseName, VaultKernel.databaseName], "NAMED: no journal or temp file after commit")
    #expect(!box.entries().contains(TestOnlyFileCustodyPin.fileName), "NAMED: pin lives outside the vault root")
}

@Test func interruptedEnrollmentStaysLocked() throws {
    let box = try Sandbox()
    #expect(failure {
        try VaultKernel.create(root: box.root, initial: Synthetic.state(seed: 1),
                               custody: box.pin(fault: .finishBeforeWrite))
    } == .recoveryRequired(.custodyFinish), "NAMED: incomplete enrollment never acknowledged")
    #expect(try box.pinRecord() == .enrolling(Head(generation: 0, state: Synthetic.state(seed: 1).id)))
    #expect(failure { try box.open() } == .locked(.incompleteEnrollment),
            "NAMED: ordinary open cannot complete enrollment")
    #expect(try RawDatabase.read(box.database).state == Synthetic.state(seed: 1).frame)
}
