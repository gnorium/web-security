import Foundation
import Crypto

/// Service for salted password hashing using SHA256.
/// While Bcrypt is preferred, this provides a portable fallback using Swift Crypto.
public struct PasswordHasher: Sendable {
    private let cost: Int

    public init(cost: Int = 12) {
        self.cost = cost
    }

    /// Hash a password using a multi-round SHA256 with salt.
    public func hash(_ password: String) throws -> String {
        var salt = [UInt8](repeating: 0, count: 16)
        #if os(Linux)
        // Secure randomness for Linux
        #else
        _ = SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt)
        #endif
        
        let saltData = Data(salt)
        let passwordData = Data(password.utf8)
        let saltedPassword = passwordData + saltData

        var hash = SHA256.hash(data: saltedPassword)

        // Perform multiple rounds for added security (1 << cost)
        for _ in 0..<(1 << cost) {
            hash = SHA256.hash(data: Data(hash) + saltData)
        }

        let hashString = Data(hash).base64EncodedString()
        let saltString = saltData.base64EncodedString()

        return "\(cost)$\(saltString)$\(hashString)"
    }

    /// Verify a password against a stored composite hash.
    public func verify(_ password: String, against storedHash: String) -> Bool {
        let components = storedHash.split(separator: "$")
        guard components.count == 3,
              let cost = Int(components[0]),
              let saltData = Data(base64Encoded: String(components[1])),
              let expectedHash = Data(base64Encoded: String(components[2])) else {
            return false
        }

        let passwordData = Data(password.utf8)
        let saltedPassword = passwordData + saltData

        var hash = SHA256.hash(data: saltedPassword)

        for _ in 0..<(1 << cost) {
            hash = SHA256.hash(data: Data(hash) + saltData)
        }

        return Data(hash) == expectedHash
    }
}
