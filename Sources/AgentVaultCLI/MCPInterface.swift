import AgentVaultContracts
import AgentVaultCore
import Foundation
import MCP

enum MCPInterface {
    static func serve(broker: Broker, clientID: UUID) async throws {
        let server = Server(name: "agent-vault", version: "0.1.0", capabilities: .init(tools: .init()))
        await server.withMethodHandler(ListTools.self) { _ in
            .init(tools: [
                Tool(name: "accounts_list", description: "List synthetic demo accounts permitted by development grants.",
                     inputSchema: .object(["type": "object", "properties": .object([:]),
                                           "additionalProperties": false])),
                Tool(name: "action_run", description: "Run synthetic demo.status. No URLs or credentials accepted.",
                     inputSchema: .object([
                        "type": "object", "properties": .object([
                            "accountId": .object(["type": "string", "format": "uuid"]),
                            "action": .object(["type": "string", "enum": .array([.string(Action.demoStatus.rawValue)])])
                        ]), "required": .array(["accountId", "action"]), "additionalProperties": false
                     ]))
            ])
        }
        await server.withMethodHandler(CallTool.self) { params in
            do {
                let arguments = params.arguments ?? [:]
                switch params.name {
                case "accounts_list":
                    guard arguments.isEmpty else { throw VaultError.invalidInput }
                    let accounts = try await broker.availableAccounts(clientID: clientID)
                    return try response(ReadReply(.outcome(.completed), accounts: accounts.filter { $0.service == .demo }.map {
                        AccountSummary(id: $0.id, service: $0.service.wire, status: $0.lifecycle.rawValue)
                    }))
                case "action_run":
                    guard Set(arguments.keys) == ["accountId", "action"],
                          let id = arguments["accountId"]?.stringValue.flatMap(UUID.init(uuidString:)),
                          let action = arguments["action"]?.stringValue.flatMap(Action.init(rawValue:)),
                          action == .demoStatus else {
                        throw VaultError.invalidInput
                    }
                    let result = try await broker.run(clientID: clientID, accountID: id, action: action)
                    switch result {
                    case .demoReady:
                        return try response(ReadReply(.outcome(.ready)))
                    case .profile(let profile):
                        return try response(ReadReply(.outcome(.completed), profile: profile))
                    case .approvalRequired(let id):
                        return try response(ReadReply(.outcome(.approvalRequired), requestID: id.uuid))
                    case .humanStepRequired(let id):
                        return try response(ReadReply(.outcome(.humanStepRequired), requestID: id.uuid))
                    }
                default: throw VaultError.invalidInput
                }
            } catch {
                let code = ((error as? VaultError)?.readFailure ?? .operationFailed).rawValue
                return .init(content: [.text(text: code, annotations: nil, _meta: nil)], isError: true)
            }
        }
        try await server.start(transport: StdioTransport())
        await server.waitUntilCompleted()
    }

    private static func response(_ value: some Encodable) throws -> CallTool.Result {
        let data = try JSONEncoder().encode(value)
        return .init(content: [.text(text: String(decoding: data, as: UTF8.self), annotations: nil, _meta: nil)], isError: false)
    }
}
