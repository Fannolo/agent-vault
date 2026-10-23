import AgentVaultContracts
import AgentVaultIPC
import AgentVaultMCPBridge
#if canImport(Darwin)
import AgentVaultRuntime
import Darwin
#else
import Glibc
#endif
import Foundation
import MCP

@main
enum BridgeMain {
    static func main() async {
        do {
            guard Array(CommandLine.arguments.dropFirst()) == ["mcp"] else { throw BridgeError.invalidInput }
            #if os(Linux)
            let config = try SocketConfiguration.load(contentsOf: SocketConfiguration.installedPath)
            guard !config.development else { throw BridgeError.invalidInput }
            let client = try VaultSocketReadClient(configuration: config)
            do {
                try await BridgeServer.serve { try await client.perform($0) }
            } catch {
                await client.close()
                throw error
            }
            await client.close()
            #else
            let config = try DeploymentConfiguration.load(for: .readClient)
            let client = try VaultReadClient(configuration: config.ipc)
            defer { client.invalidate() }
            try await BridgeServer.serve { try await client.perform($0) }
            #endif
        } catch {
            FileHandle.standardError.write(Data("Agent Vault bridge: unavailable\n".utf8))
            exit(1)
        }
    }

    private enum BridgeError: Error { case invalidInput }
}
