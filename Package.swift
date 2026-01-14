// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "web-security",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "WebSecurity",
            targets: ["WebSecurity"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/jwt-kit/jwt-kit.git", from: "5.0.0"),
    ],
    targets: [
        .target(
            name: "WebSecurity",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ]),
        .testTarget(
            name: "WebSecurityTests",
            dependencies: ["WebSecurity"]),
    ]
)
