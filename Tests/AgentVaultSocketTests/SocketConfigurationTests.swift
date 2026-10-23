@testable import AgentVaultIPC
import Foundation
import Testing

@Suite struct SocketConfigurationTests {
    private func production(broker: UInt32 = 900, read: UInt32 = 1000, admin: UInt32 = 1001) -> SocketConfiguration {
        SocketConfiguration(read: .init(path: "/run/agent-vault/read.sock", clientUID: read, group: 990),
                            admin: .init(path: "/run/agent-vault/admin.sock", clientUID: admin, group: 991),
                            brokerUID: broker, development: false)
    }

    @Test func productionNeedsThreeDistinctNonRootIdentities() throws {
        try production().validate(for: .broker, effectiveUID: 900)
        try production().validate(for: .readClient, effectiveUID: 1000)
        try production().validate(for: .adminClient, effectiveUID: 1001)
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(for: .broker, effectiveUID: 1000) }
        #expect(throws: IPCError.invalidConfiguration) { try production().validate(for: .readClient, effectiveUID: 1001) }
        for bad in [production(read: 1001), production(read: 900), production(admin: 900), production(broker: 0),
                    production(read: 0), production(read: UInt32.max)] {
            #expect(throws: IPCError.invalidConfiguration) { try bad.validate(for: .broker, effectiveUID: bad.brokerUID) }
        }
        var rootGroup = production(); rootGroup.read.group = 0
        #expect(throws: IPCError.invalidConfiguration) { try rootGroup.validate(for: .broker, effectiveUID: 900) }
        #expect(throws: IPCError.invalidConfiguration) { try production(broker: 0).validate(for: .broker, effectiveUID: 0) }
    }

    @Test func socketPathsAreAbsoluteNormalizedAndShort() {
        for good in ["/run/agent-vault/read.sock", "/tmp/a_b-c.d/x"] { #expect(SocketConfiguration.isSocketPath(good)) }
        for bad in ["run/read.sock", "/run//read.sock", "/run/./read.sock", "/run/../read.sock", "/run/read.sock/",
                    "/run/re ad.sock", "/run/rëad.sock", "/" + String(repeating: "a", count: 103), "/"] {
            #expect(!SocketConfiguration.isSocketPath(bad), "\(bad)")
        }
        var same = production(); same.admin.path = same.read.path
        #expect(throws: IPCError.invalidConfiguration) { try same.validate(for: .broker, effectiveUID: 900) }
    }

    @Test func loadAcceptsExactlyTheKnownKeysAndProtectsProduction() throws {
        let directory = try OwnedDirectory()
        defer { directory.remove(["dev.json", "extra.json", "prod.json"]) }
        func write(_ name: String, _ value: Any) throws -> String {
            let path = directory.file(name)
            try JSONSerialization.data(withJSONObject: value).write(to: URL(fileURLWithPath: path))
            return path
        }
        let endpoint: [String: Any] = ["path": "/run/agent-vault/read.sock", "clientUID": 1000, "group": 990]
        var admin = endpoint; admin["path"] = "/run/agent-vault/admin.sock"; admin["clientUID"] = 1001
        let document: [String: Any] = ["read": endpoint, "admin": admin, "brokerUID": 900, "development": true]
        let loaded = try SocketConfiguration.load(contentsOf: try write("dev.json", document))
        #expect(loaded.read.clientUID == 1000 && loaded.admin.path == "/run/agent-vault/admin.sock" && loaded.development)

        var extra = document; var nested = endpoint; nested["mode"] = 438; extra["read"] = nested
        #expect(throws: IPCError.invalidConfiguration) { try SocketConfiguration.load(contentsOf: try write("extra.json", extra)) }
        // A production file this test can write is, by construction, not root-protected.
        var production = document; production["development"] = false
        #expect(throws: IPCError.invalidConfiguration) { try SocketConfiguration.load(contentsOf: try write("prod.json", production)) }
    }
}
