import AgentVaultContracts
import AgentVaultMCPTransport
import Foundation
import MCP

public enum BridgeServer {
    public static func serve(perform: @escaping @Sendable (ReadRequest) async throws -> ReadReply) async throws {
        let server = await makeServer(perform: perform)
        try await server.start(transport: BoundedStdioTransport())
        await server.waitUntilCompleted()
    }

    public static func makeServer(perform: @escaping @Sendable (ReadRequest) async throws -> ReadReply) async -> Server {
        let server = Server(name: "agent-vault", version: "0.2.0", capabilities: .init(tools: .init()))
        await server.withMethodHandler(ListTools.self) { _ in .init(tools: tools) }
        await server.withMethodHandler(CallTool.self) { params in
            do {
                let args = params.arguments ?? [:]
                let request: ReadRequest
                switch params.name {
                case "accounts_list":
                    guard args.isEmpty else { throw BridgeError.invalidInput }
                    request = .init(operation: .accounts)
                case "action_run":
                    guard Set(args.keys) == ["accountId", "action"],
                          let id = args["accountId"]?.stringValue.flatMap(UUID.init(uuidString:)),
                          let action = args["action"]?.stringValue.flatMap(WireAction.init(rawValue:)) else { throw BridgeError.invalidInput }
                    request = .init(operation: .run, accountID: id, action: action)
                case "request_resume", "request_cancel":
                    guard Set(args.keys) == ["requestId"],
                          let id = args["requestId"]?.stringValue.flatMap(UUID.init(uuidString:)) else { throw BridgeError.invalidInput }
                    request = .init(operation: params.name == "request_resume" ? .resume : .cancel, requestID: id)
                default: throw BridgeError.invalidInput
                }
                let reply = try await perform(request)
                switch reply.parsedStatus {
                case .outcome?: break
                case .failure(let status)?: return failure(status)
                case nil: return failure(.operationFailed)
                }
                let data = try JSONEncoder().encode(reply)
                return .init(content: [.text(text: String(decoding: data, as: UTF8.self), annotations: nil, _meta: nil)], isError: false)
            } catch {
                return failure(error as? BridgeError == .invalidInput ? .invalidInput : .brokerUnavailable)
            }
        }
        return server
    }

    private enum BridgeError: Error { case invalidInput }
    private static func failure(_ code: ReadFailureStatus) -> CallTool.Result {
        .init(content: [.text(text: code.rawValue, annotations: nil, _meta: nil)], isError: true)
    }
    private static var tools: [Tool] {
        let id: Value = .object(["type": "string", "format": "uuid"])
        return [
            Tool(name: "accounts_list", description: "List accounts allowed for this signed bridge and OS user.",
                 inputSchema: .object(["type": "object", "properties": .object([:]), "additionalProperties": false])),
            Tool(name: "action_run", description: "Run a fixed read-only operation under a current grant.", inputSchema: .object([
                "type": "object", "properties": .object(["accountId": id,
                    "action": .object(["type": "string", "enum": .array(WireAction.allCases.map { .string($0.rawValue) })])]),
                "required": .array(["accountId", "action"]), "additionalProperties": false])),
            Tool(name: "request_resume", description: "Return the current state of a request. Use the requestId from the latest reply; "
                 + "keep calling while it is approval_required or human_step_required. A person completes any human step in "
                 + "the Agent Vault app; this tool never accepts codes or page input.", inputSchema: requestSchema),
            Tool(name: "request_cancel", description: "Cancel a request awaiting approval or a person's step, discarding its browser "
                 + "session. Work already sent to a service cannot be recalled.", inputSchema: requestSchema)
        ]
    }
    private static var requestSchema: Value {
        .object(["type": "object", "properties": .object(["requestId": .object(["type": "string", "format": "uuid"])]),
                 "required": .array(["requestId"]), "additionalProperties": false])
    }
}
