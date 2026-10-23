#if os(Linux)
import AgentVaultIPC
import Foundation

/// The Linux service entry point. It validates the protected socket configuration for the broker
/// role, then stays locked: vault key custody (a systemd encrypted credential) is the next
/// delivery unit, and there is no fallback store. `BrokerComposition` and `VaultSocketServer`
/// are the serving path once custody can open the state and secret stores.
@main
enum BrokerMain {
    static func main() {
        guard CommandLine.arguments.count == 1 else { fail("invalid_installation") }
        do { try SocketConfiguration.load(contentsOf: SocketConfiguration.installedPath).validate(for: .broker) }
        catch { fail("invalid_installation") }
        fail("custody_unavailable")
    }

    private static func fail(_ code: String) -> Never {
        FileHandle.standardError.write(Data("Agent Vault broker: \(code)\n".utf8))
        exit(1)
    }
}
#endif
