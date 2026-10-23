// swift-tools-version: 6.2
import PackageDescription

// Synthetic committed-record codec (unit 1). Not a product dependency of the root package.
let package = Package(
    name: "VaultRecord",
    platforms: [.macOS(.v14)],
    products: [.library(name: "VaultRecord", targets: ["VaultRecord"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.3"),
        .package(path: "../VaultSecret"),
    ],
    targets: [
        .target(name: "VaultRecord", dependencies: [
            .product(name: "Crypto", package: "swift-crypto"),
            // Links the vendored CCryptoBoringSSL module, imported internally for the one
            // pinned Ed25519 verifier on every platform (SIGNATURE-PROFILE.md).
            .product(name: "CryptoExtras", package: "swift-crypto"),
            .product(name: "VaultSecret", package: "VaultSecret"),
        ]),
        .testTarget(name: "VaultRecordTests", dependencies: [
            "VaultRecord",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "CryptoExtras", package: "swift-crypto"),
            .product(name: "VaultSecret", package: "VaultSecret"),
        ]),
    ]
)
