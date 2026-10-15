@testable import AgentVaultWebHostLink
@testable import AgentVaultWebHostProtocol
import AgentVaultCore
import AgentVaultIPC
import Foundation
import Testing

private let team = #"certificate leaf[subject.OU] = "3JWAQ92CB4""#
private let productionHost = #"anchor apple generic and identifier "dev.agentvault.webhost" and \#(team) and cdhash H"1111111111111111111111111111111111111111""#
private let productionBroker = #"anchor apple generic and identifier "dev.agentvault.broker" and \#(team) and cdhash H"2222222222222222222222222222222222222222""#

private func production(hostUID: UInt32 = 270, brokerUID: UInt32 = 260, agentUID: UInt32 = 501,
                        host: String = productionHost, broker: String = productionBroker) -> WebHostConfiguration {
    WebHostConfiguration(serviceName: "dev.agentvault.webhost", hostRequirement: host, brokerRequirement: broker,
                         hostUID: hostUID, brokerUID: brokerUID, agentUID: agentUID, development: false)
}

@Suite struct ConfigurationTests {
    @Test func productionNeedsThreeDistinctNonRootUIDsAndFullPins() throws {
        try production().validate(for: .host, effectiveUID: 270)
        try production().validate(for: .broker, effectiveUID: 260)
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(for: .host, effectiveUID: 260) }
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(for: .broker, effectiveUID: 270) }
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(for: .host, effectiveUID: 0) }
        for (host, broker, agent) in [(260, 260, 501), (501, 260, 501), (270, 501, 501), (0, 260, 501),
                                      (UInt32.max, 260, 501)] as [(UInt32, UInt32, UInt32)] {
            #expect(throws: IPCError.invalidConfiguration) {
                try production(hostUID: host, brokerUID: broker, agentUID: agent).validate(for: .broker, effectiveUID: broker)
            }
        }
        // Pins without team, anchor or cdhash, disjunctions and a shared requirement are refused.
        for host in [productionHost.replacingOccurrences(of: " and \(team)", with: ""),
                     productionHost.replacingOccurrences(of: "anchor apple generic and ", with: ""),
                     #"anchor apple generic and identifier "dev.agentvault.webhost" and \#(team)"#,
                     productionHost + #" or identifier "x""#, productionBroker] {
            #expect(throws: IPCError.invalidConfiguration) { try production(host: host).validate(for: .host, effectiveUID: 270) }
        }
    }

    @Test func developmentAllowsOneSyntheticUIDButStillPinsCode() throws {
        try developmentConfiguration().validate(for: .host)
        try developmentConfiguration().validate(for: .broker)
        #expect(throws: IPCError.invalidConfiguration) {
            try developmentConfiguration(host: "identifier \"\(testCode.identifier)\"").validate(for: .host)
        }
        #expect(throws: IPCError.invalidConfiguration) { try developmentConfiguration(hostUID: me + 1).validate(for: .host) }
    }

    @Test func brokerSideMustAgreeWithTheBrokerIPCIdentity() throws {
        let ipc = IPCConfiguration(readServiceName: "dev.agentvault.broker.read", adminServiceName: "dev.agentvault.broker.admin",
                                   brokerRequirement: productionBroker, readRequirement: "r", adminRequirement: "a",
                                   brokerUID: 260, allowedUID: 501, development: false)
        try production().validate(brokerIPC: ipc)
        var other = ipc; other.allowedUID = 502
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(brokerIPC: other) }
        other = ipc; other.development = true
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(brokerIPC: other) }
        other = ipc; other.readServiceName = "dev.agentvault.webhost"
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(brokerIPC: other) }
        other = ipc; other.adminRequirement = productionHost
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(brokerIPC: other) }
    }

    @Test func fileLoadingIsExactAndProductionMustBeRootProtected() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("webhost-config-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        func write(_ object: [String: Any]) throws -> String {
            let path = directory.appendingPathComponent("\(UUID()).json").path
            try JSONSerialization.data(withJSONObject: object).write(to: URL(fileURLWithPath: path))
            return path
        }
        let fields: [String: Any] = ["serviceName": "dev.agentvault.test.webhost", "hostRequirement": hostPin,
                                     "brokerRequirement": brokerPin, "hostUID": me, "brokerUID": me, "agentUID": me,
                                     "development": true]
        #expect(try WebHostConfiguration.load(contentsOf: try write(fields)) == developmentConfiguration())
        var extra = fields; extra["fallback"] = true
        #expect(throws: IPCError.invalidConfiguration) { try WebHostConfiguration.load(contentsOf: try write(extra)) }
        var missing = fields; missing.removeValue(forKey: "agentUID")
        #expect(throws: IPCError.invalidConfiguration) { try WebHostConfiguration.load(contentsOf: try write(missing)) }
        var empty = fields; empty["agentUID"] = NSNull()
        #expect(throws: IPCError.invalidConfiguration) { try WebHostConfiguration.load(contentsOf: try write(empty)) }
        // A production file owned by this user could be rewritten by the agent: refused.
        var prod = fields; prod["development"] = false
        prod["hostRequirement"] = productionHost; prod["brokerRequirement"] = productionBroker
        prod["hostUID"] = 270; prod["brokerUID"] = 260; prod["agentUID"] = 501
        #expect(throws: IPCError.invalidConfiguration) { try WebHostConfiguration.load(contentsOf: try write(prod)) }
        // A final symlink is refused.
        let link = directory.appendingPathComponent("link.json").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: try write(fields))
        #expect(throws: IPCError.invalidConfiguration) { try WebHostConfiguration.load(contentsOf: link) }
    }

    @Test func standardBudgetsFitInsideTheReadDeadline() throws {
        let credential = SecretIOPolicy.standard.timeout, read = VaultReadClient.defaultTimeout
        #expect(WebHostBudgets.standard.fits(credentialTimeout: credential, callerTimeout: read))
        #expect(WebHostBudgets.standard.start + WebHostBudgets.standard.end + credential < read)
        let slow = WebHostBudgets(start: 25, classify: 10, end: 2, showHuman: 5, frame: 2, input: 2)
        #expect(!slow.fits(credentialTimeout: credential, callerTimeout: read))
        #expect(throws: IPCError.invalidConfiguration) {
            _ = try WebHostLink(configuration: developmentConfiguration(),
                                brokerIPC: IPCConfiguration(readServiceName: "dev.agentvault.test.read",
                                                            adminServiceName: "dev.agentvault.test.admin",
                                                            brokerRequirement: brokerPin, readRequirement: "r",
                                                            adminRequirement: "a", brokerUID: me, allowedUID: me,
                                                            development: true),
                                credentialTimeout: 20)
        }
    }
}
