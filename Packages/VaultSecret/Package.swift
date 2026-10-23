// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "VaultSecret",
    platforms: [.macOS(.v14)],
    products: [.library(name: "VaultSecret", targets: ["VaultSecret"])],
    targets: [
        .target(name: "CSecretMemory", publicHeadersPath: "include"),
        .target(name: "VaultSecret", dependencies: ["CSecretMemory"]),
        .testTarget(name: "VaultSecretTests", dependencies: ["VaultSecret", "CSecretMemory"]),
    ]
)
