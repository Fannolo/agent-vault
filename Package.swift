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
        .target(name: "AgentVaultJSON"),
        .target(name: "AgentVaultApproval", dependencies: ["AgentVaultContracts"]),
        .testTarget(name: "AgentVaultApprovalTests", dependencies: ["AgentVaultApproval", "AgentVaultContracts"]),
        .target(name: "AgentVaultAppSupport", dependencies: ["AgentVaultContracts", "AgentVaultApproval", "AgentVaultIPC", "AgentVaultRuntime"],
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("LocalAuthentication"), .linkedFramework("SwiftUI"), .linkedFramework("AppKit")]),
        .executableTarget(name: "AgentVaultApp", dependencies: ["AgentVaultAppSupport"]),
        .testTarget(name: "AgentVaultAppTests", dependencies: ["AgentVaultAppSupport", "AgentVaultContracts"]),
        .target(name: "AgentVaultRuntime", dependencies: ["AgentVaultIPC"]),
        .target(name: "AgentVaultMCPTransport", dependencies: ["AgentVaultJSON", .product(name: "MCP", package: "swift-sdk"), .product(name: "Logging", package: "swift-log")]),
        .target(name: "AgentVaultMCPBridge", dependencies: ["AgentVaultContracts", "AgentVaultMCPTransport", .product(name: "MCP", package: "swift-sdk")]),
        .executableTarget(name: "AgentVaultBridge", dependencies: ["AgentVaultIPC", "AgentVaultRuntime", "AgentVaultMCPBridge"]),
        .executableTarget(name: "AgentVaultBrokerDaemon", dependencies: ["AgentVaultCore", "AgentVaultIPC", "AgentVaultRuntime"]),
        .testTarget(name: "AgentVaultMCPTransportTests", dependencies: ["AgentVaultMCPTransport"]),
        .testTarget(name: "AgentVaultRuntimeTests", dependencies: ["AgentVaultRuntime"]),
        .testTarget(name: "AgentVaultMCPBridgeTests", dependencies: ["AgentVaultMCPBridge", "AgentVaultContracts", .product(name: "MCP", package: "swift-sdk")]),
        .target(name: "AgentVaultCore", dependencies: ["AgentVaultContracts", "AgentVaultApproval", "AgentVaultJSON"], linkerSettings: [.linkedFramework("Security")]),
        .executableTarget(name: "AgentVaultCLI", dependencies: [
            "AgentVaultCore", "AgentVaultContracts", .product(name: "MCP", package: "swift-sdk")
        ]),
        .testTarget(name: "AgentVaultCoreTests", dependencies: ["AgentVaultCore", "AgentVaultContracts"]),
        .testTarget(name: "AgentVaultParserFuzzTests", dependencies: [
            "AgentVaultIPC", "AgentVaultMCPTransport", "AgentVaultCore", "AgentVaultContracts", "AgentVaultWebHostProtocol"
        ], exclude: ["README.md"]),
        // Broker-linked WebKit component. Depends only on data contracts: it receives
        // credential bytes from its caller and never links Core or any secret store.
        .target(name: "AgentVaultBrowser", dependencies: ["AgentVaultContracts"],
                linkerSettings: [.linkedFramework("WebKit"), .linkedFramework("AppKit")]),
        // Synthetic loopback websites used only by automated and GUI verification.
        .target(name: "AgentVaultBrowserFixture", linkerSettings: [.linkedFramework("Network")]),
        .testTarget(name: "AgentVaultBrowserTests",
                    dependencies: ["AgentVaultBrowser", "AgentVaultBrowserFixture", "AgentVaultContracts"]),
        .target(name: "AgentVaultIPC", dependencies: ["AgentVaultContracts", "AgentVaultJSON"], linkerSettings: [.linkedFramework("Security")]),
        // Credential-bearing broker <-> web host wire. Linked only by the host link and the host:
        // never by Core, the app or the MCP bridge (enforced by scripts/verify-boundaries.py).
        .target(name: "AgentVaultWebHostProtocol", dependencies: ["AgentVaultContracts", "AgentVaultJSON", "AgentVaultIPC"]),
        // The broker's client for the web host; implements Core's domain port over that wire.
        .target(name: "AgentVaultWebHostLink", dependencies: ["AgentVaultCore", "AgentVaultWebHostProtocol", "AgentVaultIPC"]),
        // The `_agentvaultweb` host: Chromium over private pipes, fixed recipes and a pure request
        // gate. An executable, so nothing can import its CDP surface; never links Core or WebKit.
        .executableTarget(name: "AgentVaultWebHost", dependencies: ["AgentVaultWebHostProtocol", "AgentVaultContracts", "AgentVaultIPC"]),
        .testTarget(name: "AgentVaultWebHostTests", dependencies: [
            "AgentVaultWebHost", "AgentVaultWebHostProtocol", "AgentVaultContracts", "AgentVaultBrowserFixture"
        ]),
        .testTarget(name: "AgentVaultWebHostLinkTests", dependencies: [
            "AgentVaultWebHostLink", "AgentVaultWebHostProtocol", "AgentVaultCore", "AgentVaultContracts", "AgentVaultIPC"
        ]),
        .target(name: "IPCFixtureKit", dependencies: ["AgentVaultIPC", "AgentVaultContracts"], path: "Tests/IPCFixtures/Kit"),
        .executableTarget(name: "agent-vault-ipc-fixture", dependencies: ["IPCFixtureKit"], path: "Tests/IPCFixtures/Genuine"),
        .executableTarget(name: "agent-vault-ipc-impostor", dependencies: ["IPCFixtureKit"], path: "Tests/IPCFixtures/Impostor"),
        .testTarget(name: "AgentVaultIPCTests", dependencies: ["AgentVaultIPC", "AgentVaultContracts"])
    ]
)
