// swift-tools-version: 6.2
import PackageDescription

// Standalone durable commit/pin kernel. No root product depends on it.
let package = Package(
    name: "VaultPersistence",
    platforms: [.macOS(.v14)],
    products: [.library(name: "VaultPersistence", targets: ["VaultPersistence"])],
    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.3")],
    targets: [
        // The platform's system SQLite (macOS SDK libsqlite3, Linux libsqlite3-dev). No
        // pkg-config, so a Homebrew or other private copy is never picked up implicitly.
        .systemLibrary(name: "CSQLite", providers: [.apt(["libsqlite3-dev"])]),
        .target(name: "CPrivateFiles"),
        .target(name: "VaultPersistence", dependencies: ["CPrivateFiles", "CSQLite", .product(name: "Crypto", package: "swift-crypto")]),
        // TEST-ONLY: file custody pin, synthetic bytes, raw tamper access. Not a product.
        .target(name: "VaultPersistenceTestSupport", dependencies: [
            "VaultPersistence", "CSQLite", .product(name: "Crypto", package: "swift-crypto")
        ]),
        // TEST-ONLY separate-process crash/lease probe. Not a product.
        .executableTarget(name: "VaultPersistenceProbe", dependencies: ["VaultPersistence", "VaultPersistenceTestSupport", "CSQLite"]),
        .testTarget(name: "VaultPersistenceTests", dependencies: [
            "VaultPersistence", "VaultPersistenceTestSupport", "CSQLite", "VaultPersistenceProbe",
            .product(name: "Crypto", package: "swift-crypto")
        ])
    ]
)
