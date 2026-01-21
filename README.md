# WebSecurity, as used in [gnorium.com](https://gnorium.com)

A Swift package providing portable security utilities for web applications.

## Overview

WebSecurity provides reusable, framework-agnostic security components for authentication, encryption, and authorization. Built on `swift-crypto` and `jwt-kit` for cross-platform compatibility.

### Components

- **JWTAuthenticator**: JWT token signing and verification with configurable claims
- **TOTPAuthenticator**: Time-based One-Time Password (RFC 6238) generation and verification
- **PasswordHasher**: Salted password hashing with configurable rounds
- **DataEncryptor**: AES-GCM encryption/decryption for sensitive data
- **OIDCProvider**: OAuth/OIDC authorization URL generation for various providers

## Installation

### Swift Package Manager

Add WebSecurity to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/gnorium/web-security.git", branch: "main")
]
```

Then add it to your target dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "WebSecurity", package: "web-security")
    ]
)
```

## Requirements

- Swift 6.2+

## Usage

### TOTP Authentication

```swift
import WebSecurity

let totp = TOTPAuthenticator()
let secret = totp.generateSecret()
let otpauthURL = totp.generateOTPAuthURL(secret: secret, accountName: "user@example.com", issuer: "MyApp")

// Verify a code
let isValid = totp.verifyCode(userCode, secret: secret)
```

### JWT Authentication

```swift
import WebSecurity

let jwt = JWTAuthenticator(signers: app.jwt.signers)
let token = try jwt.sign(subject: userId, mfaVerified: true)
let payload = try jwt.verify(token: token)
```

### Password Hashing

```swift
import WebSecurity

let hash = PasswordHasher.hash("password123")
let isValid = PasswordHasher.verify("password123", against: hash)
```

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Related Packages

- [design-tokens](https://github.com/gnorium/design-tokens) - Universal design tokens based on Apple HIG
- [embedded-swift-utilities](https://github.com/gnorium/embedded-swift-utilities) - Utility functions for Embedded Swift environments
- [markdown-utilities](https://github.com/gnorium/markdown-utilities) - Markdown to HTML rendering with media support
- [admin-core](https://github.com/gnorium/admin-core) - Core admin functionalities for web applications
- [web-apis](https://github.com/gnorium/web-apis) - Web API implementations for Swift WebAssembly
- [web-builders](https://github.com/gnorium/web-builders) - HTML, CSS, JS, and SVG DSL builders
- [web-components](https://github.com/gnorium/web-components) - Reusable UI components for web applications
- [web-formats](https://github.com/gnorium/web-formats) - Structured data format builders
- [web-types](https://github.com/gnorium/web-types) - Shared web types and design tokens
