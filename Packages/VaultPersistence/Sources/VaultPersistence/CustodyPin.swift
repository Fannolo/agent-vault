/// What protected custody retains about the kernel commit, outside the database.
public enum PinRecord: Equatable, Sendable {
    /// Custody was provisioned by an enrollment ceremony; no state is pinned yet.
    case unenrolled
    /// First creation is in progress; nothing is acknowledged.
    case enrolling(PinnedImage)
    case stable(PinnedImage)
    /// A commit from `stable` to `next` may or may not have reached the database.
    case pending(stable: PinnedImage, next: PinnedImage)
}

/// Protected custody pin port. Every operation is bounded and synchronous, performs no
/// network work, and is atomic and durable before it returns. Each update is a
/// compare-and-set: it fails unless the current record is the stated predecessor.
///
/// Each identity binds the complete verified logical image, including exact opaque frame,
/// object digests, admission generations and inventory totals. Adapters must retain and
/// compare every field. The public Head alone can alias after abort/retry and is unsafe.
/// This is local byte identity, not a signature, authority protocol or unique attempt ID.
///
/// The non-rollback property of the backing storage is an assumption the adapter states;
/// this kernel cannot establish it. Restoring both the database and custody defeats it.
public protocol VaultCustodyPin: AnyObject {
    /// Throws if custody is missing, unreadable or corrupt. Never provisions.
    func read() throws -> PinRecord
    /// `.unenrolled` → `.enrolling(first)`.
    func beginEnrollment(_ first: PinnedImage) throws
    /// `.stable(from)` → `.pending(stable: from, next: to)`.
    func prepare(from: PinnedImage, to: PinnedImage) throws
    /// `.pending(_, next)` or `.enrolling(next)` → `.stable(next)`.
    func finish(_ next: PinnedImage) throws
    /// `.pending(stable: retained, _)` → `.stable(retained)`.
    func abort(retaining: PinnedImage) throws
}
