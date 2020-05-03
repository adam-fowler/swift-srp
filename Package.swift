// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SRP",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(name: "SRPKit", targets: ["SRPKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto", from: "1.0.0"),
        .package(url: "https://github.com/adam-fowler/big-num", from: "1.1.1"),
    ],
    targets: [
        .target(name: "SRPKit", dependencies: ["BigNum", "Crypto"]),
        .testTarget(
            name: "SRPTests", dependencies: ["SRPKit"]),
    ]
)
