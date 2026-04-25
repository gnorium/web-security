// swift-tools-version: 6.2
import PackageDescription

let package = Package(
  name: "web-security",
  platforms: [
    .macOS(.v13),
    .iOS(.v16),
  ],
  products: [
    .library(
      name: "WebSecurity",
      targets: ["WebSecurity"])
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
    .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.0.0"),
  ],
  targets: [
    .target(
      name: "Argon2",
      dependencies: [
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "CryptoExtras", package: "swift-crypto"),
      ],
      swiftSettings: [
        .enableExperimentalFeature("Embedded", .when(platforms: [.wasi])),
        .define("CLIENT", .when(platforms: [.wasi])),
        .define("SERVER", .when(platforms: [.macOS, .linux, .windows])),
      ]),
    .target(
      name: "WebSecurity",
      dependencies: [
        "Argon2",
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "JWTKit", package: "jwt-kit"),
      ],
      swiftSettings: [
        .enableExperimentalFeature("Embedded", .when(platforms: [.wasi])),
        .define("CLIENT", .when(platforms: [.wasi])),
        .define("SERVER", .when(platforms: [.macOS, .linux, .windows])),
      ]),
    .testTarget(
      name: "WebSecurityTests",
      dependencies: ["WebSecurity"]),
  ]
)
