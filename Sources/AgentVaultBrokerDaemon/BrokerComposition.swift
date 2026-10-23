import AgentVaultContracts
import AgentVaultCore
import AgentVaultIPC

/// The broker operations served by either transport. Each transport supplies the kernel-checked
/// UID and the admin connection identity it minted; nothing here reads an identity from a request.
enum BrokerComposition {
    static func handlers(broker: Broker, administration admin: Administration) -> BrokerHandlers {
        let read = ReadOperations(broker: broker), continuation = ContinuationOperations(broker: broker)
        return BrokerHandlers(
            read: { uid, request in
                do { return try await read.perform(uid: uid, request: request) }
                catch { return ReadReply(.failure((error as? VaultError)?.readFailure ?? .operationFailed)) }
            }, snapshot: { _ in try await admin.snapshot() },
            begin: { peer, request in
                do { return try await admin.begin(request, connection: ContinuationConnectionID(peer)) }
                catch { throw AdminRejection(status: (error as? VaultError)?.rawValue ?? "operation_failed") }
            }, authorize: { peer, id, signature in
                do {
                    return try await admin.authorize(id, signature: signature, connection: ContinuationConnectionID(peer))
                } catch { return AdminReply(status: (error as? VaultError)?.rawValue ?? "operation_failed") }
            }, continuation: { peer, request in
                await continuation.perform(request, connection: ContinuationConnectionID(peer))
            }, closed: { peer in
                await broker.continuationConnectionClosed(ContinuationConnectionID(peer))
            })
    }
}

extension ContinuationConnectionID {
    /// The transport-minted identity and liveness of an admin connection.
    init(_ peer: AdminConnection) { self.init(minted: peer.id, isOpen: { peer.isOpen }) }
}
