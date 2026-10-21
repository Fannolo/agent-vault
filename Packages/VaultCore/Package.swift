// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "VaultCore",
    platforms: [.macOS(.v14)],
    products: [.library(name: "VaultCore", targets: ["VaultCore"])],
    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.3")],
    targets: [
        .target(name: "VaultCore", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "VaultCoreTests", dependencies: ["VaultCore", .product(name: "Crypto", package: "swift-crypto")])
    ]
)
