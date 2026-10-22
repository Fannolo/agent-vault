import AgentVaultContracts
import AgentVaultIPC
import Foundation

/// Hostile-client probes that bypass the typed client and its local validation.
enum RawProbe {
    static func run(_ command: String, _ configuration: IPCConfiguration, options: [String: String]) async -> [String: Any] {
        switch command {
        case "raw-read":
            let payload: Data = switch options["payload"] {
            case "oversize": Data(repeating: 0x20, count: IPCLimits.standard.maxRequestBytes + 1)
            case "unknown-key": Data(#"{"operation":"accounts","clientID":"00000000-0000-4000-8000-000000000001"}"#.utf8)
            case "unknown-operation": Data(#"{"operation":"export"}"#.utf8)
            case "null-value": Data(#"{"operation":"run","accountID":null,"action":"demo.status"}"#.utf8)
            default: Data("not json".utf8)
            }
            return await call(configuration, service: configuration.readServiceName, protocol: VaultReadRPC.self) {
                ($0 as? VaultReadRPC)?.perform(payload, reply: $1)
            }
        case "raw-admin-selector":
            // Sends an admin selector over the read service, which exports only VaultReadRPC.
            return await call(configuration, service: configuration.readServiceName, protocol: VaultAdminRPC.self) {
                ($0 as? VaultAdminRPC)?.snapshot(reply: $1)
            }
        default:
            return ["outcome": "usage"]
        }
    }

    private static func call(_ configuration: IPCConfiguration, service: String, protocol interface: Protocol,
                             _ send: @escaping @Sendable (AnyObject, @escaping (Data) -> Void) -> Void?) async -> [String: Any] {
        let connection = NSXPCConnection(machServiceName: service, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: interface)
        connection.setCodeSigningRequirement(configuration.brokerRequirement)
        connection.activate()
        defer { connection.invalidate() }
        let box = ConnectionBox(connection)
        let text = await withCheckedContinuation { (continuation: CheckedContinuation<String, Never>) in
            let once = Once(continuation)
            let proxy = box.connection.remoteObjectProxyWithErrorHandler { error in
                once.resume("xpc_error_\((error as NSError).code)")
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 5) { once.resume("timeout") }
            _ = send(proxy as AnyObject) { data in once.resume(String(decoding: data, as: UTF8.self)) }
        }
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: String],
              let code = object["error"] else { return ["outcome": text.hasPrefix("{") ? "unexpected_reply" : text] }
        return ["outcome": code]
    }
}

private final class ConnectionBox: @unchecked Sendable {
    let connection: NSXPCConnection
    init(_ connection: NSXPCConnection) { self.connection = connection }
}

private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<String, Never>?
    init(_ continuation: CheckedContinuation<String, Never>) { self.continuation = continuation }
    func resume(_ value: String) {
        let continuation = lock.withLock { () -> CheckedContinuation<String, Never>? in
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(returning: value)
    }
}
