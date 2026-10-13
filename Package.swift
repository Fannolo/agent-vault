// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AgentVault",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "agent-vault", targets: ["AgentVaultCLI"])],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1")
    ],
    targets: [
        .target(name: "AgentVaultCore", linkerSettings: [.linkedFramework("Security")]),
        .executableTarget(name: "AgentVaultCLI", dependencies: [
            "AgentVaultCore", .product(name: "MCP", package: "swift-sdk")
        ]),
        .testTarget(name: "AgentVaultCoreTests", dependencies: ["AgentVaultCore"])
    ]
)
