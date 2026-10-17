import AgentVaultContracts
import AgentVaultMCPBridge
@testable import AgentVaultAppSupport
@testable import AgentVaultWebHost
import Darwin
import Foundation
import MCP
import Testing

@Suite struct SecretExposureDetectorTests {
    @Test func deliberateLeaksAndUnobservedChannelsFailClosed() {
        let probe = SecretExposureProbe()
        #expect(!probe.isClean(requiring: [.readReply]))
        probe.observe(.readReply, Data("safe".utf8))
        #expect(probe.isClean(requiring: [.readReply]))
        #expect(!probe.isClean(requiring: [.readReply, .mcpReply]))
        for useHumanInput in [false, true] {
            for index in SecretExposureProbe.encodings(probe.password).indices {
                let detector = SecretExposureProbe()
                let secret = useHumanInput ? detector.humanInput : detector.password
                detector.observe(.mcpReply, SecretExposureProbe.encodings(secret)[index])
                #expect(!detector.isClean(requiring: [.mcpReply]), "deliberate encoded leak must fail")
            }
        }
    }
    @Test(.timeLimit(.minutes(1))) func detectorRejectsDeliberateLeakThroughRealMCPSerializer() async throws {
        let probe = SecretExposureProbe()
        let leakedBytes = try JSONSerialization.data(withJSONObject: ["status": "completed", "login": probe.password, "userID": 42])
        let leakedReply = try JSONDecoder().decode(ReadReply.self, from: leakedBytes)
        let (first, second) = await InMemoryTransport.createConnectedPair()
        let server = await BridgeServer.makeServer { _ in leakedReply }
        try await server.start(transport: second)
        let client = Client(name: "synthetic-negative-control", version: "1")
        do {
            _ = try await client.connect(transport: first)
            try probe.observeMCP(.mcpReply, try await client.callTool(name: "accounts_list", arguments: [:]))
            #expect(!probe.isClean(requiring: [.mcpReply]), "actual MCP serialization of a deliberate leak must fail")
        } catch { await client.disconnect(); await server.stop(); throw BoundaryFailure.unavailable }
        await client.disconnect(); await server.stop()
    }
}

@MainActor
@Suite(.serialized, .enabled(if: fixtureChromium != nil, "explicit designated synthetic Chromium required"))
struct SecretBoundaryTests {
    @Test(.timeLimit(.minutes(2))) func realWorkflowKeepsFreshCanariesOutOfObservedOutputs() async throws {
        let probe = SecretExposureProbe()
        try await HeadlessStack.using(password: probe.password) { stack in
            let model = stack.app()
            await model.refresh()
            let account = try #require(model.snapshot?.accounts.first)
            // Actual native model -> signed admin XPC -> Core secret store rotation.
            let rotated = await model.rotate(account: account, secret: probe.password, username: "mfa-user")
            #expect(rotated)
            #expect(await model.grant(.init(clientID: stack.grant.clientID, accountID: account.id,
                callLimit: 1, alwaysRequireApproval: false)))
            try probe.observe(.adminSnapshot, encoded: try await stack.transport().0.snapshot())
            let first = try await stack.read.perform(.init(operation: .run, accountID: stack.account.id, action: .browserDemo))
            try probe.observe(.readReply, encoded: first)
            #expect(first.parsedStatus == .outcome(.humanStepRequired))
            let run = try #require(first.requestID)
            await model.refresh()
            #expect(await model.openHumanStep(try #require(model.humanSteps.first)))
            let window = try #require(model.humanStep)
            #expect(await eventually { window.phase == .live })
            let image = try #require(window.frame)
            let size = CGSize(width: image.width, height: image.height)
            window.pointer(.down, at: CGPoint(x: 4, y: 4), in: size)
            window.pointer(.up, at: CGPoint(x: 4, y: 4), in: size)
            // Fresh synthetic long MFA input; fixture accepts any completed step.
            window.type(probe.humanInput)
            window.key(.enter)
            #expect(await eventually { stack.posts.contains { $0.path == "/step" } })
            let reachedFixture = stack.posts.contains {
                $0.path == "/step" && $0.body.range(of: Data(probe.humanInput.utf8)) != nil
            }
            #expect(reachedFixture, "fresh human-input canary must actually reach the trusted fixture")
            await window.finish()
            let completed = try await stack.collect(run)
            try probe.observe(.readReply, encoded: completed)
            #expect(completed.parsedStatus == .outcome(.completed))
            try probe.observe(.readReply, encoded: try await stack.collect(run))
            await model.refresh()
            try probe.observe(.adminSnapshot, encoded: try await stack.transport().0.snapshot())
            try probe.observe(.appMetadata, encoded: model.snapshot)
            try probe.observe(.appMetadata, encoded: model.audit)
            probe.observe(.appMetadata, Data((model.notice?.text ?? "").utf8))
            try probe.observe(.persistedMetadata, encoded: stack.state.snapshot())
            let export = stack.directory.appendingPathComponent("audit-export.json")
            model.exportAudit(to: export)
            probe.observe(.auditExport, try Data(contentsOf: export))

            let (clientTransport, serverTransport) = await InMemoryTransport.createConnectedPair()
            let read = stack.read
            let syntheticError = probe.password
            let server = await BridgeServer.makeServer { request in
                if request.operation == .cancel { throw NSError(domain: syntheticError, code: 1) }
                // Replay the actual collected typed reply through the MCP serializer too.
                if request.operation == .resume { return completed }
                return try await read.perform(request)
            }
            try await server.start(transport: serverTransport)
            let client = Client(name: "synthetic-boundary-client", version: "1")
            do {
                _ = try await client.connect(transport: clientTransport)
                try probe.observe(.mcpReply, encoded: try await client.listTools().tools)
                try probe.observeMCP(.mcpReply, try await client.callTool(name: "accounts_list", arguments: [:]))
                try probe.observeMCP(.mcpReply, try await client.callTool(name: "request_resume",
                    arguments: ["requestId": .string(run.uuidString)]))
                try probe.observeMCP(.mcpError, try await client.callTool(name: "get_password", arguments: [:]))
                try probe.observeMCP(.mcpError, try await client.callTool(name: "request_cancel",
                    arguments: ["requestId": .string(run.uuidString)]))
            } catch { await client.disconnect(); await server.stop(); throw error }
            await client.disconnect(); await server.stop()

            // Scan only this owned directory. Stop/reap before filesystem enumeration so the
            // artifact set is stable; HeadlessStack still performs its independent final cleanup.
            if let pipe = await stack.host.launched {
                pipe.killGroup()
                #expect(await eventually { pipe.isReaped })
            }
            let count = try scanOwnedArtifacts(stack.directory, probe: probe)
            #expect(count > 1, "real browser artifacts must be observed")
            let required: Set<SecretExposureProbe.Channel> = [.readReply, .adminSnapshot, .appMetadata,
                .auditExport, .persistedMetadata, .mcpReply, .mcpError, .browserArtifacts]
            if !probe.isClean(requiring: required) { Issue.record(Comment(rawValue: probe.report(required))) }
        }
    }

    @Test func actualOwnedBrowserLaunchHasCleanArgvAndEnvironment() async throws {
        let probe = LaunchObservation()
        var template = Array(FileManager.default.temporaryDirectory.appendingPathComponent("av-boundary-XXXXXX").path.utf8CString)
        guard let path = mkdtemp(&template) else { throw BoundaryFailure.unavailable }
        let directory = URL(fileURLWithPath: String(cString: path))
        defer { try? FileManager.default.removeItem(at: directory) }
        let pipe = try ChromiumPipe(binary: try #require(fixtureChromium), runDirectory: directory,
            onEvent: { _ in }, onExit: {}, makeGroup: { pid in
                // Called synchronously after this exact spawn and BEFORE its reaper starts.
                // No process-name search or unrelated process/environment inspection occurs.
                probe.captureOwnedUnreapedChild(pid)
                return OwnedGroup(pid)
            })
        pipe.killGroup()
        #expect(await eventually { pipe.isReaped })
        #expect(probe.clean, "owned launch argv/environment unavailable or contaminated")
    }
}

private enum BoundaryFailure: Error { case unavailable }
private final class LaunchObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var result = false
    var clean: Bool { lock.withLock { result } }
    func captureOwnedUnreapedChild(_ pid: pid_t) {
        let probe = SecretExposureProbe()
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &bytes, &size, nil, 0) == 0 else { return }
        let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        var offset = MemoryLayout<Int32>.size
        func next() -> Data? {
            guard offset < size, let end = bytes[offset..<size].firstIndex(of: 0) else { return nil }
            defer { offset = end + 1 }
            return Data(bytes[offset..<end])
        }
        guard next() != nil else { return } // executable path
        while offset < size && bytes[offset] == 0 { offset += 1 }
        guard argc > 0 && argc < 100 else { return }
        for _ in 0..<argc {
            guard let arg = next() else { return }
            probe.observe(.browserArgv, arg)
        }
        var names: Set<String> = []
        while let field = next(), !field.isEmpty {
            probe.observe(.browserEnvironment, field)
            let text = String(decoding: field, as: UTF8.self)
            names.insert(String(text.prefix { $0 != "=" }))
        }
        let valid = names == ["HOME", "TMPDIR", "PATH"] && probe.isClean(requiring: [.browserArgv, .browserEnvironment])
        lock.withLock { result = valid }
    }
}

private extension SecretExposureProbe {
    func observeMCP(_ channel: Channel, _ result: (content: [Tool.Content], isError: Bool?)) throws {
        for item in result.content {
            if case .text(let text, _, _) = item { observe(channel, Data(text.utf8)) }
        }
        try observe(channel, encoded: result.content)
        try observe(channel, encoded: result.isError)
    }
}

private func scanOwnedArtifacts(_ directory: URL, probe: SecretExposureProbe) throws -> Int {
    let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey]
    guard let files = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: keys) else {
        throw BoundaryFailure.unavailable
    }
    var count = 0
    for case let url as URL in files {
        let info = try url.resourceValues(forKeys: Set(keys))
        probe.observe(.browserArtifacts, Data(url.lastPathComponent.utf8))
        guard info.isSymbolicLink != true, info.isRegularFile == true else { continue }
        probe.observe(.browserArtifacts, try Data(contentsOf: url)); count += 1
    }
    return count
}
