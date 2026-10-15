import AgentVaultCore
import Foundation
import MCP

enum MCPInterface {
    static func serve(broker: Broker, clientID: UUID) async throws {
        let server = Server(name: "agent-vault", version: "0.1.0", capabilities: .init(tools: .init()))
        await server.withMethodHandler(ListTools.self) { _ in
            .init(tools: [
                Tool(name: "accounts_list", description: "List accounts permitted by current development grants.",
                     inputSchema: .object(["type": "object", "properties": .object([:]),
                                           "additionalProperties": false])),
                Tool(name: "action_run", description: "Run one fixed read-only action. No URLs or credentials accepted.",
                     inputSchema: .object([
                        "type": "object", "properties": .object([
                            "accountId": .object(["type": "string", "format": "uuid"]),
                            "action": .object(["type": "string", "enum": .array(Action.allCases.map { .string($0.rawValue) })])
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
                    let payload = Value.object(["accounts": .array(accounts.map {
                        .object(["id": .string($0.id.uuidString.lowercased()),
                                 "service": .string($0.service.rawValue),
                                 "action": .string($0.service.action.rawValue)])
                    })])
                    return try response(payload)
                case "action_run":
                    guard Set(arguments.keys) == ["accountId", "action"],
                          let id = arguments["accountId"]?.stringValue.flatMap(UUID.init(uuidString:)),
                          let action = arguments["action"]?.stringValue.flatMap(Action.init(rawValue:)) else {
                        throw VaultError.invalidInput
                    }
                    let result = try await broker.run(clientID: clientID, accountID: id, action: action)
                    switch result {
                    case .demoReady:
                        return try response(.object(["status": "ready", "service": "demo"]))
                    case .profile(let profile):
                        return try response(.object(["status": "completed", "profile": .object([
                            "login": .string(profile.login), "id": .int(profile.userID)
                        ])]))
                    case .approvalRequired(let id):
                        return try response(.object(["status": "approval_required", "requestId": .string(id.uuid.uuidString)]))
                    case .humanStepRequired(let id):
                        return try response(.object(["status": "human_step_required", "requestId": .string(id.uuid.uuidString)]))
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

    private static func response(_ value: Value) throws -> CallTool.Result {
        let data = try JSONEncoder().encode(value)
        return .init(content: [.text(text: String(decoding: data, as: UTF8.self), annotations: nil, _meta: nil)], isError: false)
    }
}
