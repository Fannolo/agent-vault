// swift-tools-version: 6.2
import PackageDescription

let portableCrypto: Target.Dependency = .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))

let package = Package(
    name: "AgentVault",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "agent-vault", targets: ["AgentVaultCLI"]),
        .executable(name: "agent-vault-bridge", targets: ["AgentVaultBridge"]),
        .executable(name: "agent-vault-broker", targets: ["AgentVaultBrokerDaemon"])
    ],
    dependencies: [
        .package(path: "Packages/VaultSecret"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.3"),
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1"),
        .package(url: "https://github.com/apple/swift-log.git", exact: "1.16.1")
    ],
    targets: [
        .target(name: "AgentVaultContracts"),
        .target(name: "AgentVaultCredentials", dependencies: ["AgentVaultContracts", .product(name: "VaultSecret", package: "VaultSecret")]),
        .testTarget(name: "AgentVaultCredentialsTests", dependencies: ["AgentVaultCredentials", "AgentVaultContracts"]),
        .target(name: "AgentVaultJSON"),
        .target(name: "AgentVaultCloud", dependencies: ["AgentVaultCredentials", portableCrypto]),
        .testTarget(name: "AgentVaultCloudTests", dependencies: ["AgentVaultCloud", "AgentVaultCredentials"]),
        .target(name: "AgentVaultApproval", dependencies: ["AgentVaultContracts", portableCrypto]),
        .testTarget(name: "AgentVaultApprovalTests", dependencies: ["AgentVaultApproval", "AgentVaultContracts"]),
        .target(name: "AgentVaultAppSupport", dependencies: ["AgentVaultContracts", "AgentVaultApproval", "AgentVaultIPC", "AgentVaultRuntime"],
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("LocalAuthentication"), .linkedFramework("SwiftUI"), .linkedFramework("AppKit")]),
        .executableTarget(name: "AgentVaultApp", dependencies: ["AgentVaultAppSupport"]),
        .testTarget(name: "AgentVaultAppTests", dependencies: ["AgentVaultAppSupport", "AgentVaultContracts"]),
        .target(name: "AgentVaultRuntime", dependencies: ["AgentVaultIPC"]),
        .target(name: "CAgentVaultStdio"),
        .target(name: "AgentVaultMCPTransport", dependencies: [.target(name: "CAgentVaultStdio", condition: .when(platforms: [.linux])), "AgentVaultJSON", .product(name: "MCP", package: "swift-sdk"), .product(name: "Logging", package: "swift-log")]),
        .target(name: "AgentVaultMCPBridge", dependencies: ["AgentVaultContracts", "AgentVaultMCPTransport", .product(name: "MCP", package: "swift-sdk")]),
        .executableTarget(name: "AgentVaultBridge", dependencies: ["AgentVaultIPC", "AgentVaultRuntime", "AgentVaultMCPBridge"]),
        .executableTarget(name: "AgentVaultBrokerDaemon", dependencies: ["AgentVaultCore", "AgentVaultIPC", "AgentVaultRuntime"]),
        .testTarget(name: "AgentVaultMCPTransportTests", dependencies: ["AgentVaultMCPTransport", .target(name: "CAgentVaultStdio", condition: .when(platforms: [.linux]))]),
        .testTarget(name: "AgentVaultRuntimeTests", dependencies: ["AgentVaultRuntime"]),
        .testTarget(name: "AgentVaultMCPBridgeTests", dependencies: ["AgentVaultMCPBridge", "AgentVaultContracts", .product(name: "MCP", package: "swift-sdk")]),
        .target(name: "AgentVaultCore", dependencies: ["AgentVaultCredentials", "AgentVaultContracts", "AgentVaultApproval", "AgentVaultJSON", portableCrypto], linkerSettings: [.linkedFramework("Security", .when(platforms: [.macOS]))]),
        .executableTarget(name: "AgentVaultCLI", dependencies: [
            "AgentVaultCore", "AgentVaultContracts", .product(name: "MCP", package: "swift-sdk")
        ]),
        .testTarget(name: "AgentVaultCoreTests", dependencies: ["AgentVaultCredentials", "AgentVaultCore", "AgentVaultContracts", portableCrypto]),
        .testTarget(name: "AgentVaultParserFuzzTests", dependencies: [
            "AgentVaultIPC", "AgentVaultMCPTransport", "AgentVaultCore", "AgentVaultContracts", "AgentVaultWebHostProtocol"
        ], exclude: ["README.md"]),
        // Synthetic loopback websites used only by automated and GUI verification.
        .target(name: "AgentVaultBrowserFixture", linkerSettings: [.linkedFramework("Network")]),
        // Broker transports: XPC on macOS; kernel-peer-authenticated Unix sockets on Linux and in tests.
        .target(name: "CAgentVaultSocket"),
        .target(name: "AgentVaultIPC", dependencies: ["AgentVaultContracts", "AgentVaultJSON", "CAgentVaultSocket"],
                linkerSettings: [.linkedFramework("Security", .when(platforms: [.macOS]))]),
        // Credential-bearing broker <-> web host wire. Linked only by the host link and the host:
        // never by Core, the app or the MCP bridge (enforced by scripts/verify-boundaries.py).
        .target(name: "AgentVaultWebHostProtocol", dependencies: ["AgentVaultCredentials", "AgentVaultContracts", "AgentVaultJSON", "AgentVaultIPC"]),
        // The broker's client for the web host; implements Core's domain port over that wire.
        .target(name: "AgentVaultWebHostLink", dependencies: ["AgentVaultCredentials", "AgentVaultCore", "AgentVaultWebHostProtocol", "AgentVaultIPC"]),
        // The `_agentvaultweb` host: Chromium over private pipes, fixed recipes and a pure request
        // gate. Product graph checks keep its CDP surface out of every other process role.
        .executableTarget(name: "AgentVaultWebHost", dependencies: ["AgentVaultCredentials", "AgentVaultWebHostProtocol", "AgentVaultContracts", "AgentVaultIPC"]),
        .testTarget(name: "AgentVaultWebHostTests", dependencies: ["AgentVaultCredentials",
            "AgentVaultWebHost", "AgentVaultWebHostProtocol", "AgentVaultContracts", "AgentVaultBrowserFixture"
        ]),
        .testTarget(name: "AgentVaultWebHostLinkTests", dependencies: ["AgentVaultCredentials",
            "AgentVaultWebHostLink", "AgentVaultWebHostProtocol", "AgentVaultCore", "AgentVaultContracts", "AgentVaultIPC"
        ]),
        .target(name: "IPCFixtureKit", dependencies: ["AgentVaultIPC", "AgentVaultContracts"], path: "Tests/IPCFixtures/Kit"),
        .executableTarget(name: "agent-vault-ipc-fixture", dependencies: ["IPCFixtureKit"], path: "Tests/IPCFixtures/Genuine"),
        .executableTarget(name: "agent-vault-ipc-impostor", dependencies: ["IPCFixtureKit"], path: "Tests/IPCFixtures/Impostor"),
        .testTarget(name: "AgentVaultIPCTests", dependencies: ["AgentVaultIPC", "AgentVaultContracts"]),
        // Real sockets into the real broker through the daemon's own handler composition.
        .testTarget(name: "AgentVaultSocketTests", dependencies: [
            "AgentVaultIPC", "AgentVaultBrokerDaemon", "AgentVaultCore", "AgentVaultContracts", "CAgentVaultSocket", portableCrypto
        ]),
        // The human app driven over real XPC into the real broker, in one test process. Only this
        // test target may link the app with Core; verify-boundaries.py checks product targets.
        .testTarget(name: "AgentVaultContinuationE2ETests", dependencies: ["AgentVaultCredentials",
            "AgentVaultAppSupport", "AgentVaultCore", "AgentVaultIPC", "AgentVaultContracts"
        ]),
        // Synthetic composition only: no product role may link these implementation surfaces.
        .testTarget(name: "AgentVaultHeadlessE2ETests", dependencies: [
            "AgentVaultWebHost", "AgentVaultWebHostLink", "AgentVaultWebHostProtocol", "AgentVaultCore",
            "AgentVaultAppSupport", "AgentVaultIPC", "AgentVaultContracts", "AgentVaultBrowserFixture",
            "AgentVaultMCPBridge", .product(name: "MCP", package: "swift-sdk")
        ])
    ]
)

// Linux builds the same broker authority and metadata implementation and the native socket
// transport. OS-specific stores, XPC and UI remain excluded until their native replacements
// are integrated. The Linux broker executable stays locked until vault key custody exists.
#if os(Linux)
let portableTargets: Set<String> = [
    "AgentVaultContracts", "AgentVaultCredentials", "AgentVaultCredentialsTests", "AgentVaultJSON",
    "AgentVaultApproval", "AgentVaultApprovalTests", "AgentVaultCore", "AgentVaultCoreTests",
    "CAgentVaultSocket", "AgentVaultIPC", "AgentVaultBrokerDaemon", "AgentVaultSocketTests",
    "CAgentVaultStdio", "AgentVaultMCPTransport", "AgentVaultMCPTransportTests",
    "AgentVaultMCPBridge", "AgentVaultMCPBridgeTests", "AgentVaultBridge",
    "AgentVaultCloud", "AgentVaultCloudTests",
]
package.products = [.library(name: "AgentVaultCore", targets: ["AgentVaultCore"]),
                    .executable(name: "agent-vault-bridge", targets: ["AgentVaultBridge"])]
package.targets = package.targets.filter { portableTargets.contains($0.name) }
package.targets.first { $0.name == "AgentVaultCore" }?.exclude = ["KeychainStore.swift", "PrivateKeychainStore.swift"]
package.targets.first { $0.name == "AgentVaultIPC" }?.exclude = [
    "IPCConfiguration.swift", "VaultXPCClients.swift",
]
package.targets.first { $0.name == "AgentVaultBrokerDaemon" }?.dependencies = ["AgentVaultCore", "AgentVaultIPC"]
package.targets.first { $0.name == "AgentVaultBridge" }?.dependencies = ["AgentVaultIPC", "AgentVaultMCPBridge"]
#endif
