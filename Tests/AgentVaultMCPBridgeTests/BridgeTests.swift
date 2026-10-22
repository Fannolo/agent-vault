import AgentVaultContracts
import AgentVaultMCPBridge
import Foundation
import MCP
import Testing

@Test(.timeLimit(.minutes(1))) func bridgeExposesOnlyClosedOperationsAndSuppressesErrors() async throws {
    let (clientTransport, serverTransport) = await InMemoryTransport.createConnectedPair()
    let server = await BridgeServer.makeServer { request in
        if request.operation == .accounts { return .init(.outcome(.completed), accounts: []) }
        if request.operation == .resume { return .init(.outcome(.approvalRequired), requestID: request.requestID) }
        if request.operation == .cancel { throw NSError(domain: "SYNTHETIC-error-secret", code: 1) }
        return .init(.failure(.accessDenied))
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

@Test(.timeLimit(.minutes(1))) func bridgeReportsEveryClosedFailureVerbatimAndNothingElse() async throws {
    let failures = ReadFailureStatus.allCases
    let unknown = try JSONDecoder().decode(ReadReply.self, from: Data(#"{"status":"failed:login_rejected"}"#.utf8))
    let (clientTransport, serverTransport) = await InMemoryTransport.createConnectedPair()
    let index = Counter()
    let server = await BridgeServer.makeServer { _ in
        let next = index.next()
        return next < failures.count ? ReadReply(.failure(failures[next])) : unknown
    }
    try await server.start(transport: serverTransport)
    let client = Client(name: "synthetic-client", version: "1")
    _ = try await client.connect(transport: clientTransport)
    let arguments: [String: Value] = ["requestId": .string(UUID().uuidString)]
    for expected in failures.map(\.rawValue) + ["operation_failed"] {
        let result = try await client.callTool(name: "request_resume", arguments: arguments)
        #expect(result.isError == true)
        guard case .text(let text, _, _) = result.content.first else { Issue.record("Missing failure"); continue }
        #expect(text == expected)
    }
    await client.disconnect()
    await server.stop()
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func next() -> Int { lock.withLock { defer { value += 1 }; return value } }
}
