// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "token-server",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "TokenServer", targets: ["TokenServer"]),
        .library(name: "TokenServerAuth", targets: ["TokenServerAuth"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.102.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.6.0"),
    ],
    targets: [
        .executableTarget(
            name: "TokenServer",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Crypto", package: "swift-crypto"),
                .target(name: "TokenServerAuth"),
            ]
        ),
        .target(
            name: "TokenServerAuth",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        )
    ]
)
