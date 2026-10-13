// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "AgentVault",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "agent-vault", targets: ["AgentVaultCLI"]),
        .executable(name: "agent-vault-bridge", targets: ["AgentVaultBridge"]),
        .executable(name: "agent-vault-broker", targets: ["AgentVaultBrokerDaemon"])
    ],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1"),
        .package(url: "https://github.com/apple/swift-log.git", exact: "1.16.1")
    ],
    targets: [
        .target(name: "AgentVaultContracts"),
        .target(name: "AgentVaultAppSupport", dependencies: ["AgentVaultContracts", "AgentVaultIPC", "AgentVaultRuntime"],
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("LocalAuthentication"), .linkedFramework("SwiftUI"), .linkedFramework("AppKit")]),
        .executableTarget(name: "AgentVaultApp", dependencies: ["AgentVaultAppSupport"]),
        .testTarget(name: "AgentVaultAppTests", dependencies: ["AgentVaultAppSupport", "AgentVaultContracts"]),
        .target(name: "AgentVaultRuntime", dependencies: ["AgentVaultIPC"]),
        .target(name: "AgentVaultMCPTransport", dependencies: [.product(name: "MCP", package: "swift-sdk"), .product(name: "Logging", package: "swift-log")]),
        .target(name: "AgentVaultMCPBridge", dependencies: ["AgentVaultContracts", "AgentVaultMCPTransport", .product(name: "MCP", package: "swift-sdk")]),
        .executableTarget(name: "AgentVaultBridge", dependencies: ["AgentVaultIPC", "AgentVaultRuntime", "AgentVaultMCPBridge"]),
        .executableTarget(name: "AgentVaultBrokerDaemon", dependencies: ["AgentVaultCore", "AgentVaultIPC", "AgentVaultRuntime"]),
        .testTarget(name: "AgentVaultMCPTransportTests", dependencies: ["AgentVaultMCPTransport"]),
        .testTarget(name: "AgentVaultRuntimeTests", dependencies: ["AgentVaultRuntime"]),
        .testTarget(name: "AgentVaultMCPBridgeTests", dependencies: ["AgentVaultMCPBridge", "AgentVaultContracts", .product(name: "MCP", package: "swift-sdk")]),
        .target(name: "AgentVaultCore", dependencies: ["AgentVaultContracts"], linkerSettings: [.linkedFramework("Security")]),
        .executableTarget(name: "AgentVaultCLI", dependencies: [
            "AgentVaultCore", .product(name: "MCP", package: "swift-sdk")
        ]),
        .testTarget(name: "AgentVaultCoreTests", dependencies: ["AgentVaultCore"]),
        // Broker-linked WebKit component. Depends only on data contracts: it receives
        // credential bytes from its caller and never links Core or any secret store.
        .target(name: "AgentVaultBrowser", dependencies: ["AgentVaultContracts"],
                linkerSettings: [.linkedFramework("WebKit"), .linkedFramework("AppKit")]),
        // Synthetic loopback websites used only by automated and GUI verification.
        .target(name: "AgentVaultBrowserFixture", linkerSettings: [.linkedFramework("Network")]),
        .testTarget(name: "AgentVaultBrowserTests",
                    dependencies: ["AgentVaultBrowser", "AgentVaultBrowserFixture", "AgentVaultContracts"]),
        .target(name: "AgentVaultIPC", dependencies: ["AgentVaultContracts"], linkerSettings: [.linkedFramework("Security")]),
        .target(name: "IPCFixtureKit", dependencies: ["AgentVaultIPC", "AgentVaultContracts"], path: "Tests/IPCFixtures/Kit"),
        .executableTarget(name: "agent-vault-ipc-fixture", dependencies: ["IPCFixtureKit"], path: "Tests/IPCFixtures/Genuine"),
        .executableTarget(name: "agent-vault-ipc-impostor", dependencies: ["IPCFixtureKit"], path: "Tests/IPCFixtures/Impostor"),
        .testTarget(name: "AgentVaultIPCTests", dependencies: ["AgentVaultIPC", "AgentVaultContracts"])
    ]
)
