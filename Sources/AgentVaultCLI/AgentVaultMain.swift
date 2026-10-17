import AgentVaultCore
import Foundation
import Darwin

@main
struct AgentVaultMain {
    static func main() async {
        do { try await run(Array(CommandLine.arguments.dropFirst())) }
        catch {
            // Never forward provider, Keychain, parser or user-input error strings.
            let code = (error as? VaultError)?.rawValue ?? "operation_failed"
            FileHandle.standardError.write(Data("Agent Vault: \(code)\n".utf8))
            exit(1)
        }
    }

    private static func run(_ arguments: [String]) async throws {
        var args = arguments
        let statePath = try option("--state-dir", in: &args)
        let namespace = try option("--keychain-namespace", in: &args) ?? "io.agent-vault.credentials.v1"
        let directory = statePath.map { URL(fileURLWithPath: $0, isDirectory: true) } ??
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/share/agent-vault")
        guard let command = args.first else { printHelp(); return }
        args.removeFirst()
        if command == "help" || command == "--help" { printHelp(); return }
        guard ["demo", "client", "grant", "revoke-grant", "revoke-client", "mcp"].contains(command)
        else { throw VaultError.invalidInput }
        let store = try FileStateStore(directory: directory)
        let broker = Broker(state: store, secrets: KeychainStore(namespace: namespace))
        switch command {
        case "demo":
            guard args.isEmpty else { throw VaultError.invalidInput }
            // Synthetic account only. The generated credential is never printed.
            let account = try await broker.enroll(service: .demo, credential: Data(UUID().uuidString.utf8))
            let client = try await broker.registerClient()
            let grant = try await broker.grant(clientID: client.id, accountID: account.id,
                                               duration: 3600, callLimit: 20)
            try printJSON(["accountId": account.id.uuidString.lowercased(),
                           "clientId": client.id.uuidString.lowercased(),
                           "grantId": grant.id.uuidString.lowercased(), "service": "demo"])
        case "client":
            guard args.isEmpty else { throw VaultError.invalidInput }
            let client = try await broker.registerClient()
            try printJSON(["clientId": client.id.uuidString.lowercased()])
        case "grant":
            let client = try uuidOption("--client-id", in: &args)
            let account = try uuidOption("--account-id", in: &args)
            let rawSeconds = try option("--seconds", in: &args) ?? "3600"
            let rawCalls = try option("--calls", in: &args) ?? "20"
            guard let seconds = Double(rawSeconds), let calls = Int(rawCalls) else {
                throw VaultError.invalidInput
            }
            guard args.isEmpty else { throw VaultError.invalidInput }
            let grant = try await broker.grant(clientID: client, accountID: account,
                                               duration: seconds, callLimit: calls)
            try printJSON(["grantId": grant.id.uuidString.lowercased(), "callLimit": grant.callLimit])
        case "revoke-grant":
            let id = try uuidOption("--grant-id", in: &args)
            guard args.isEmpty else { throw VaultError.invalidInput }
            try await broker.revokeGrant(id)
            try printJSON(["revoked": true])
        case "revoke-client":
            let id = try uuidOption("--client-id", in: &args)
            guard args.isEmpty else { throw VaultError.invalidInput }
            try await broker.revokeClient(id)
            try printJSON(["revoked": true])
        case "mcp":
            let client = try uuidOption("--client-id", in: &args)
            guard args == ["--development"] else { throw VaultError.invalidInput }
            // This is trusted host launch configuration, NOT authenticated client identity.
            try await MCPInterface.serve(broker: broker, clientID: client)
        default: throw VaultError.invalidInput
        }
    }

    private static func option(_ name: String, in args: inout [String]) throws -> String? {
        let indices = args.indices.filter { args[$0] == name }
        guard indices.count <= 1 else { throw VaultError.invalidInput }
        guard let index = indices.first else { return nil }
        guard index + 1 < args.count, !args[index + 1].hasPrefix("--") else {
            throw VaultError.invalidInput
        }
        let value = args[index + 1]
        args.removeSubrange(index...(index + 1))
        return value
    }

    private static func uuidOption(_ name: String, in args: inout [String]) throws -> UUID {
        guard let raw = try option(name, in: &args), let id = UUID(uuidString: raw) else {
            throw VaultError.invalidInput
        }
        return id
    }

    private static func printJSON(_ object: [String: Any]) throws {
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        FileHandle.standardOutput.write(bytes + Data([0x0a]))
    }

    private static func printHelp() {
        print("""
        Agent Vault — synthetic development fixture
        Commands:
          demo                              Create a synthetic account and one-hour grant
          client                            Register a development client ID
          grant --client-id ID --account-id ID [--seconds 3600] [--calls 20]
          revoke-grant --grant-id ID
          revoke-client --client-id ID
          mcp --client-id ID --development   Start the stdio MCP development server
        Global options: --state-dir PATH, --keychain-namespace NAME
        Real credentials are accepted only by the native app, never by this terminal fixture.
        Only demo.status is exposed here. The launch client ID is not an authentication boundary.
        """)
    }
}
