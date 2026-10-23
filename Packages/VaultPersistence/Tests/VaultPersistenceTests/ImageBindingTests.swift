import Testing
import Foundation
import VaultPersistence
import VaultPersistenceTestSupport

@Test func pendingAbortRetryCannotLoseAcknowledgedObject() throws {
    let box = try Sandbox()
    let a = SealedState(frame: [0x41])
    let b = SealedState(frame: [0x42])
    let x = SignedObject(bytes: [0x58])
    do { _ = try VaultKernel.create(root: box.root, initial: a, custody: box.pin()) }
    let d0 = box.bytes(box.database)
    do {
        let kernel = try box.open(fault: .finishBeforeWrite)
        #expect(failure { try kernel.commit(expecting: kernel.head, next: b, adding: []) }
                == .recoveryRequired(.custodyFinish))
    }
    let d1 = box.bytes(box.database)
    box.overwrite(box.database, d0)
    do {
        let kernel = try box.open()
        #expect(kernel.head == Head(generation: 0, state: a.id))
        let ack = try kernel.commit(expecting: kernel.head, next: b, adding: [x])
        #expect(ack == Head(generation: 1, state: b.id))
        #expect(try kernel.object(x.digest) == x)
    }
    let acknowledgedPin = box.bytes(box.pinDirectory + "/pin")
    box.overwrite(box.database, d1)
    #expect(failure { try box.open() } == .locked(.pinMismatch),
            "NAMED: aborted retry cannot lose acknowledged object")
    #expect(box.bytes(box.pinDirectory + "/pin") == acknowledgedPin)
    // Makes the prior loss directly observable in the failing-before experiment.
    if let opened = try? box.open() {
        #expect(try opened.object(x.digest) == x, "NAMED: acknowledged X survives replay")
    }
}

private let frameA = SealedState(frame: [0x41])
private let frameB = SealedState(frame: [0x42])
private let frameC = SealedState(frame: [0x43])
private let objectX = SignedObject(bytes: [0x58])
private let objectY = SignedObject(bytes: [0x59])

/// Every restored image here came from a legitimate kernel transaction. Only raw DB
/// bytes rewind; lease inode and custody never rewind. Existing precise finish fault.
private func abandonedAttempt(with objects: [SignedObject]) throws -> (Sandbox, [UInt8], PinnedImage) {
    let box = try Sandbox()
    do { _ = try VaultKernel.create(root: box.root, initial: frameA, custody: box.pin()) }
    let d0 = box.bytes(box.database)
    do {
        let kernel = try box.open(fault: .finishBeforeWrite)
        #expect(failure { try kernel.commit(expecting: kernel.head, next: frameB, adding: objects) }
                == .recoveryRequired(.custodyFinish))
    }
    let d1 = box.bytes(box.database)
    guard case .pending(_, let abandoned) = try box.pinRecord() else { throw POSIXError(.EINVAL) }
    box.overwrite(box.database, d0)
    do { _ = try box.open() }
    #expect(try box.pinnedImage().head == Head(generation: 0, state: frameA.id))
    return (box, d1, abandoned)
}

@Test(arguments: [false, true])
func wholeImageStableRejectsAbandonedInventory(sameTotals: Bool) throws {
    let (box, d1, abandoned) = try abandonedAttempt(with: sameTotals ? [objectY] : [])
    do {
        let kernel = try box.open()
        _ = try kernel.commit(expecting: kernel.head, next: frameB, adding: [objectX])
    }
    let acknowledged = try box.pinnedImage()
    #expect(acknowledged.head == abandoned.head && acknowledged.image != abandoned.image)
    let pin = box.bytes(box.pinDirectory + "/pin")
    box.overwrite(box.database, d1)
    #expect(failure { try box.open() } == .locked(.pinMismatch),
            "NAMED: stable compares whole inventory")
    #expect(box.bytes(box.pinDirectory + "/pin") == pin)
}

@Test(arguments: [false, true])
func wholeImagePendingFinishRejectsAbandonedInventory(sameTotals: Bool) throws {
    let (box, d1, abandoned) = try abandonedAttempt(with: sameTotals ? [objectY] : [])
    do {
        let kernel = try box.open(fault: .finishBeforeWrite)
        #expect(failure { try kernel.commit(expecting: kernel.head, next: frameB, adding: [objectX]) }
                == .recoveryRequired(.custodyFinish))
    }
    guard case .pending(_, let next) = try box.pinRecord() else { throw POSIXError(.EINVAL) }
    #expect(next.head == abandoned.head && next.image != abandoned.image)
    let pin = box.bytes(box.pinDirectory + "/pin")
    box.overwrite(box.database, d1)
    #expect(failure { try box.open() } == .locked(.pinMismatch),
            "NAMED: pending finish compares whole inventory")
    #expect(box.bytes(box.pinDirectory + "/pin") == pin)
}

@Test(arguments: [false, true])
func wholeImagePendingAbortRejectsAbandonedInventory(sameTotals: Bool) throws {
    let (box, d1, abandoned) = try abandonedAttempt(with: sameTotals ? [objectY] : [])
    do {
        let kernel = try box.open()
        _ = try kernel.commit(expecting: kernel.head, next: frameB, adding: [objectX])
        #expect(try kernel.object(objectX.digest) == objectX)
    }
    do {
        let kernel = try box.open(fault: .prepareAfterPersist)
        #expect(failure { try kernel.commit(expecting: kernel.head, next: frameC, adding: []) }
                == .recoveryRequired(.custodyPrepare))
    }
    guard case .pending(let stable, _) = try box.pinRecord() else { throw POSIXError(.EINVAL) }
    #expect(stable.head == abandoned.head && stable.image != abandoned.image)
    let pin = box.bytes(box.pinDirectory + "/pin")
    box.overwrite(box.database, d1)
    #expect(failure { try box.open() } == .locked(.pinMismatch),
            "NAMED: pending abort compares whole inventory")
    #expect(box.bytes(box.pinDirectory + "/pin") == pin)
}

@Test func identicalCompleteRetryAndDuplicateOrderCompareEqual() throws {
    let (box, d1, abandoned) = try abandonedAttempt(with: [objectX, objectY])
    do {
        let kernel = try box.open()
        _ = try kernel.commit(expecting: kernel.head, next: frameB, adding: [objectY, objectX, objectX])
    }
    #expect(try box.pinnedImage() == abandoned,
            "NAMED: image identity is not attempt identity")
    box.overwrite(box.database, d1)
    do {
        let kernel = try box.open()
        #expect(try kernel.object(objectX.digest) == objectX)
        #expect(try kernel.object(objectY.digest) == objectY)
        _ = try kernel.commit(expecting: kernel.head, next: frameC, adding: [objectX])
    }
    let finalPin = try box.pinnedImage()
    let other = try Sandbox()
    do {
        let kernel = try VaultKernel.create(root: other.root, initial: frameA, custody: other.pin())
        _ = try kernel.commit(expecting: kernel.head, next: frameB, adding: [objectX, objectY])
        _ = try kernel.commit(expecting: kernel.head, next: frameC, adding: [])
    }
    #expect(try other.pinnedImage() == finalPin, "NAMED: duplicate retry preserves admission generation")
    let raw = try RawDatabase.read(box.database)
    #expect(raw.objectCount == 2 && raw.objectBytes == 2)
    #expect(raw.objects.values.allSatisfy { $0.generation == 1 })
}

@Test func wholeImageBindsObjectAdmissionGeneration() throws {
    let early = try Sandbox(), late = try Sandbox()
    do {
        let kernel = try VaultKernel.create(root: early.root, initial: frameA, custody: early.pin())
        _ = try kernel.commit(expecting: kernel.head, next: frameB, adding: [objectX])
        _ = try kernel.commit(expecting: kernel.head, next: frameC, adding: [])
    }
    do {
        let kernel = try VaultKernel.create(root: late.root, initial: frameA, custody: late.pin())
        _ = try kernel.commit(expecting: kernel.head, next: frameB, adding: [])
        _ = try kernel.commit(expecting: kernel.head, next: frameC, adding: [objectX])
    }
    let earlyPin = try early.pinnedImage(), latePin = try late.pinnedImage()
    #expect(earlyPin.head == latePin.head && earlyPin.image != latePin.image,
            "NAMED: image binds object admission metadata")
    early.overwrite(early.database, late.bytes(late.database))
    #expect(failure { try early.open() } == .locked(.pinMismatch),
            "NAMED: custody rejects admission metadata substitution")
}

@Test func liveInventorySubstitutionCannotBeAcknowledged() throws {
    let box = try Sandbox()
    let kernel = try VaultKernel.create(root: box.root, initial: frameA, custody: box.pin())
    _ = try kernel.commit(expecting: kernel.head, next: frameB, adding: [objectX])
    let pin = box.bytes(box.pinDirectory + "/pin")
    // Deliberate object-only tamper: valid digest, same count/size, unchanged Head.
    try RawDatabase.execute(box.database, "UPDATE objects SET digest = ?1, bytes = ?2",
                            blobs: [objectY.digest.bytes, objectY.bytes])
    #expect(failure { try kernel.commit(expecting: kernel.head, next: frameC, adding: []) }
            == .locked(.databaseChangedOutsideOwner), "NAMED: commit verifies previous whole image")
    #expect(failure { try kernel.state() } == .recoveryRequired(.integrity))
    #expect(box.bytes(box.pinDirectory + "/pin") == pin)
}

@Test func unchangedFrameCannotAcknowledgeNewObjects() throws {
    let box = try Sandbox()
    let kernel = try VaultKernel.create(root: box.root, initial: frameA, custody: box.pin())
    let db = box.bytes(box.database), pin = box.bytes(box.pinDirectory + "/pin")
    #expect(failure { try kernel.commit(expecting: kernel.head, next: frameA, adding: [objectX]) }
            == .refused(.stateUnchanged), "NAMED: unchanged frame cannot acknowledge objects")
    #expect(box.bytes(box.database) == db && box.bytes(box.pinDirectory + "/pin") == pin)
    #expect(try kernel.object(objectX.digest) == nil)
}
