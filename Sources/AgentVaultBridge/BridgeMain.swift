import AgentVaultContracts
import AgentVaultIPC
import AgentVaultMCPBridge
import AgentVaultRuntime
import Darwin
import Foundation
import MCP

@main
enum BridgeMain {
    static func main() async {
        do {
            guard Array(CommandLine.arguments.dropFirst()) == ["mcp"] else { throw BridgeError.invalidInput }
            let config = try DeploymentConfiguration.load(for: .readClient)
            let client = try VaultReadClient(configuration: config.ipc)
            defer { client.invalidate() }
            try await BridgeServer.serve { try await client.perform($0) }
        } catch {
            FileHandle.standardError.write(Data("Agent Vault bridge: unavailable\n".utf8))
            exit(1)
        }
    }

    private enum BridgeError: Error { case invalidInput }
}
