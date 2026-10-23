/// What protected custody retains about the local state, outside the database.
public enum PinRecord: Equatable, Sendable {
    /// Custody was provisioned by an enrollment ceremony; no state is pinned yet.
    case unenrolled
    /// First creation is in progress; nothing is acknowledged.
    case enrolling(StateID)
    case stable(StateID)
    /// A commit from `stable` to `next` may or may not have reached the database.
    case pending(stable: StateID, next: StateID)
}

/// Protected custody pin port. Every operation is bounded and synchronous, performs no
/// network work, and is atomic and durable before it returns. Each update is a
/// compare-and-set: it fails unless the current record is the stated predecessor.
///
/// The non-rollback property of the backing storage is an assumption the adapter states;
/// this kernel cannot establish it. Restoring both the database and custody defeats it.
public protocol VaultCustodyPin: AnyObject {
    /// Throws if custody is missing, unreadable or corrupt. Never provisions.
    func read() throws -> PinRecord
    /// `.unenrolled` → `.enrolling(first)`.
    func beginEnrollment(_ first: StateID) throws
    /// `.stable(from)` → `.pending(stable: from, next: to)`.
    func prepare(from: StateID, to: StateID) throws
    /// `.pending(_, next)` or `.enrolling(next)` → `.stable(next)`.
    func finish(_ next: StateID) throws
    /// `.pending(stable: retained, _)` → `.stable(retained)`.
    func abort(retaining: StateID) throws
}
