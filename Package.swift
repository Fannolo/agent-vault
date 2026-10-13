// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "AgentVault",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "agent-vault", targets: ["AgentVaultCLI"])],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1")
    ],
    targets: [
        .target(name: "AgentVaultContracts"),
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
                    dependencies: ["AgentVaultBrowser", "AgentVaultBrowserFixture", "AgentVaultContracts"])
    ]
)
