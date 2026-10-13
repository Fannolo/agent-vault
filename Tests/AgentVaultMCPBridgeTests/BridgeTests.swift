import AgentVaultContracts
import AgentVaultMCPBridge
import Foundation
import MCP
import Testing

@Test(.timeLimit(.minutes(1))) func bridgeExposesOnlyClosedOperationsAndSuppressesErrors() async throws {
    let (clientTransport, serverTransport) = await InMemoryTransport.createConnectedPair()
    let server = await BridgeServer.makeServer { request in
        if request.operation == .accounts { return .init(status: "completed", accounts: []) }
        if request.operation == .resume { return .init(status: "approval_required", requestID: request.requestID) }
        if request.operation == .cancel { throw NSError(domain: "SYNTHETIC-error-secret", code: 1) }
        return .init(status: "access_denied")
    }
    try await server.start(transport: serverTransport)
    let client = Client(name: "synthetic-client", version: "1")
    _ = try await client.connect(transport: clientTransport)
    let tools = try await client.listTools().tools
    #expect(Set(tools.map(\.name)) == ["accounts_list", "action_run", "request_resume", "request_cancel"])
    let accounts = try await client.callTool(name: "accounts_list", arguments: [:])
    #expect(accounts.isError == false)
    for (name, args): (String, [String: Value]) in [
        ("get_password", [:]), ("accounts_list", ["clientId": .string(UUID().uuidString)]),
        ("action_run", ["accountId": .string(UUID().uuidString), "action": "demo.status", "url": "https://elsewhere.invalid"]),
        ("request_resume", ["requestId": .string(UUID().uuidString), "accountId": .string(UUID().uuidString)])
    ] {
        let result = try await client.callTool(name: name, arguments: args)
        #expect(result.isError == true)
        guard case .text(let text, _, _) = result.content.first else { Issue.record("Missing error text"); continue }
        #expect(text == "invalid_input")
    }
    let id = UUID()
    let resume = try await client.callTool(name: "request_resume", arguments: ["requestId": .string(id.uuidString)])
    #expect(resume.isError == false)
    let cancel = try await client.callTool(name: "request_cancel", arguments: ["requestId": .string(id.uuidString)])
    #expect(cancel.isError == true)
    guard case .text(let text, _, _) = cancel.content.first else { Issue.record("Missing failure"); return }
    #expect(text == "broker_unavailable")
    await client.disconnect()
    await server.stop()
}
