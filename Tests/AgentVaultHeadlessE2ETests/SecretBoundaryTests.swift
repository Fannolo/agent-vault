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
        let padded = Data(probe.password.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let exercisesPadding = padded.hasSuffix("=")
        #expect(exercisesPadding, "canary grammar must exercise padded base64url independently")
        for useHumanInput in [false, true] {
            for index in SecretExposureProbe.encodings(probe.password).indices {
                let detector = SecretExposureProbe()
                let secret = useHumanInput ? detector.humanInput : detector.password
                detector.observe(.mcpReply, SecretExposureProbe.encodings(secret)[index])
                #expect(!detector.isClean(requiring: [.mcpReply]), "deliberate encoded leak must fail")
            }
        }
    }
    @MainActor @Test func uncertainReapClosesServicesButPreservesOwnedDirectory() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("av-cleanup-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) } // synthetic directory, no browser ever spawned
        let sentinel = directory.appendingPathComponent("evidence")
        try Data("synthetic".utf8).write(to: sentinel)
        var closed = false, refused = false
        do {
            try await OwnedTestCleanup.finish(directory: directory, confirmedReap: false) { closed = true }
        } catch OwnedTestCleanup.Failure.unconfirmedReap { refused = true }
        #expect(refused && closed)
        let preserved = FileManager.default.fileExists(atPath: sentinel.path)
        #expect(preserved, "uncertain ownership must preserve the profile/evidence")
        try await OwnedTestCleanup.finish(directory: directory, confirmedReap: true) {}
        let deleted = !FileManager.default.fileExists(atPath: directory.path)
        #expect(deleted, "confirmed reap permits deletion")
    }

    @Test func exactLaunchPolicyRejectsExtraSwitchAndChangedAllowedEnvironment() {
        let binary = URL(fileURLWithPath: "/synthetic/chrome-headless-shell")
        let directory = URL(fileURLWithPath: "/synthetic/owned")
        let profile = directory.appendingPathComponent("profile-fixture")
        let safe = ObservedLaunch.expected(binary: binary, directory: directory, profile: profile)
        let baseline = safe.validate(probe: SecretExposureProbe(), binary: binary, directory: directory, profile: profile)
        #expect(baseline)
        for scenario in 0..<3 {
            let probe = SecretExposureProbe()
            var changed = safe
            switch scenario {
            case 0: changed.argv.append("--remote-debugging-port=9222")
            case 1: changed.environment[0] = "HOME=" + probe.password
            default: changed.environment[0] = "HOME=/synthetic/wrong-safe-value"
            }
            let accepted = changed.validate(probe: probe, binary: binary, directory: directory, profile: profile)
            #expect(!accepted, "deliberate launch-policy mutation must fail")
            if scenario == 1 {
                let clean = probe.isClean(requiring: [.browserEnvironment])
                #expect(!clean, "a canary in an allowed environment key must be detected")
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
        try await HeadlessStack.using(password: probe.previousPassword, acceptedPassword: probe.password) { stack in
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
            let usedRotatedCredential = stack.posts.filter { $0.path == "/session" }.map {
                decodedForm($0.body)["password"] == probe.password && decodedForm($0.body)["password"] != probe.previousPassword
            }
            let rotatedCredentialReachedFixture = usedRotatedCredential == [true]
            #expect(rotatedCredentialReachedFixture, "decoded login POST must use rotated B rather than enrolled A")
            guard let pipe = await stack.host.launched,
                  let launch = pipe.withOwnedChild({ ObservedLaunch.readOwnedChild($0) }) ?? nil else {
                throw BoundaryFailure.unavailable
            }
            let profiles = try FileManager.default.contentsOfDirectory(at: stack.directory,
                includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("profile-") }
            guard profiles.count == 1, let binary = fixtureChromium else { throw BoundaryFailure.unavailable }
            // Directory enumeration may canonicalize /var to /private/var. Rebuild the
            // expected argument with the launcher's exact owned directory spelling.
            let profile = stack.directory.appendingPathComponent(profiles[0].lastPathComponent)
            let launchMatches = launch.validate(probe: probe, binary: binary, directory: stack.directory, profile: profile)
            if !launchMatches {
                Issue.record(Comment(rawValue: launch.policyReport(binary: binary, directory: stack.directory, profile: profile)))
            }
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
                let cancel = try await client.callTool(name: "request_cancel", arguments: ["requestId": .string(run.uuidString)])
                try probe.observeMCP(.mcpError, cancel)
                let closedException = cancel.isError == true && cancel.content.count == 1 && cancel.content.allSatisfy {
                    if case .text(let text, _, _) = $0 { return text == ReadFailureStatus.brokerUnavailable.rawValue }
                    return false
                }
                #expect(closedException, "canary-bearing internal exception must become exactly broker_unavailable")
            } catch { await client.disconnect(); await server.stop(); throw error }
            await client.disconnect(); await server.stop()

            // Scan only this owned directory. Stop/reap before filesystem enumeration so the
            // artifact set is stable; HeadlessStack still performs its independent final cleanup.
            if let pipe = await stack.host.launched {
                pipe.killGroup()
                guard await eventually({ pipe.isReaped }) else { throw OwnedTestCleanup.Failure.unconfirmedReap }
            }
            let count = try scanOwnedArtifacts(stack.directory, probe: probe)
            #expect(count > 1, "real browser artifacts must be observed")
            let required: Set<SecretExposureProbe.Channel> = [.readReply, .adminSnapshot, .appMetadata,
                .auditExport, .persistedMetadata, .mcpReply, .mcpError, .browserArtifacts, .browserArgv, .browserEnvironment]
            if !probe.isClean(requiring: required) { Issue.record(Comment(rawValue: probe.report(required))) }
        }
    }

}

private enum BoundaryFailure: Error { case unavailable }

/// Values captured only under the actual browser's OwnedGroup lock. Never render these
/// fields in assertions: controls deliberately put an in-memory canary into them.
private struct ObservedLaunch: CustomDebugStringConvertible {
    var executable: String
    var argv: [String]
    var environment: [String]
    var debugDescription: String { "ObservedLaunch(redacted)" }

    static func expected(binary: URL, directory: URL, profile: URL) -> Self {
        Self(executable: binary.path,
             argv: [binary.path, "--user-data-dir=\(profile.path)"] + ChromiumPipe.arguments,
             environment: ["HOME=\(directory.path)", "TMPDIR=\(directory.path)/", "PATH=/usr/bin:/bin"])
    }
    func validate(probe: SecretExposureProbe, binary: URL, directory: URL, profile: URL) -> Bool {
        for field in [executable] + argv { probe.observe(.browserArgv, Data(field.utf8)) }
        for field in environment { probe.observe(.browserEnvironment, Data(field.utf8)) }
        let expected = Self.expected(binary: binary, directory: directory, profile: profile)
        return executable == expected.executable && argv == expected.argv &&
            environment.count == expected.environment.count && Set(environment) == Set(expected.environment) &&
            probe.isClean(requiring: [.browserArgv, .browserEnvironment])
    }
    func policyReport(binary: URL, directory: URL, profile: URL) -> String {
        let expected = Self.expected(binary: binary, directory: directory, profile: profile)
        let same = argv.indices.filter { $0 < expected.argv.count && argv[$0] == expected.argv[$0] }
        let envSame = expected.environment.map { environment.contains($0) }
        return "launch:executableMatches=\(executable == expected.executable),argvCount=\(argv.count),expectedArgvCount=\(expected.argv.count),matchingArgvCount=\(same.count),environmentCount=\(environment.count),expectedEnvironmentMatches=\(envSame)"
    }
    static func readOwnedChild(_ pid: pid_t) -> Self? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &bytes, &size, nil, 0) == 0 else { return nil }
        let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        var offset = MemoryLayout<Int32>.size
        func next() -> String? {
            guard offset < size, let end = bytes[offset..<size].firstIndex(of: 0) else { return nil }
            defer { offset = end + 1 }
            return String(decoding: bytes[offset..<end], as: UTF8.self)
        }
        guard let executable = next() else { return nil }
        while offset < size && bytes[offset] == 0 { offset += 1 }
        guard argc > 0 && argc < 100 else { return nil }
        var argv: [String] = [], environment: [String] = []
        for _ in 0..<argc {
            guard let arg = next() else { return nil }
            argv.append(arg)
        }
        while let field = next(), !field.isEmpty { environment.append(field) }
        return Self(executable: executable, argv: argv, environment: environment)
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

private func decodedForm(_ bytes: Data) -> [String: String] {
    var fields: [String: String] = [:]
    for pair in String(decoding: bytes, as: UTF8.self).split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { continue }
        func decode(_ value: Substring) -> String {
            String(value).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? ""
        }
        fields[decode(parts[0])] = decode(parts[1])
    }
    return fields
}
