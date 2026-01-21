import Foundation
import Argon2
import Crypto
import CryptoExtras

/// Pure Swift Argon2id-based password hasher.
/// Follows the PHC string format standard for future-proof compatibility.
public struct PasswordHasher: Sendable {
    public struct Parameters: Sendable {
        public let memoryUsage: Int      // KiB (m)
        public let iterations: Int       // t
        public let parallelism: Int      // p
        
        public static let recommended = Parameters(memoryUsage: 65536, iterations: 3, parallelism: 4)
        public static let interactive = Parameters(memoryUsage: 32768, iterations: 2, parallelism: 1)
    }

    private let parameters: Parameters

    public init(parameters: Parameters = .recommended) {
        self.parameters = parameters
    }

    /// Hash a password using Argon2id.
    /// Returns a PHC-formatted string: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    public func hash(_ password: String) throws -> String {
        let salt = [UInt8].random(count: 16)
        let saltData = Data(salt)
        
        let key = try KDF.Argon2id.deriveKey(
            from: Data(password.utf8),
            salt: saltData,
            outputByteCount: 32,
            iterations: parameters.iterations,
            memoryByteCount: parameters.memoryUsage * 1024,
            parallelism: parameters.parallelism
        )
        
        let hash = key.withUnsafeBytes { Data($0) }
        
        let saltBase64 = saltData.base64EncodedString().replacingOccurrences(of: "=", with: "")
        let hashBase64 = hash.base64EncodedString().replacingOccurrences(of: "=", with: "")
        
        return "$argon2id$v=19$m=\(parameters.memoryUsage),t=\(parameters.iterations),p=\(parameters.parallelism)$\(saltBase64)$\(hashBase64)"
    }

    /// Verify a password against a stored PHC-formatted hash.
    public func verify(_ password: String, against storedHash: String) -> Bool {
        let parts = storedHash.split(separator: "$")
        // Format: $argon2id$v=...$m=...,t=...,p=...$salt$hash
        guard parts.count == 5, parts[0] == "argon2id" else {
            return false
        }
        
        let paramsPart = parts[2]
        let paramsSubParts = paramsPart.split(separator: ",")
        var m: Int?
        var t: Int?
        var p: Int?
        
        for subPart in paramsSubParts {
            let kv = subPart.split(separator: "=")
            if kv.count == 2 {
                if kv[0] == "m" { m = Int(kv[1]) }
                else if kv[0] == "t" { t = Int(kv[1]) }
                else if kv[0] == "p" { p = Int(kv[1]) }
            }
        }
        
        guard let memoryUsage = m, let iterations = t, let parallelism = p else {
            return false
        }
        
        func decodeBase64(_ base64: String) -> Data? {
            var s = base64
            while s.count % 4 != 0 { s += "=" }
            return Data(base64Encoded: s)
        }
        
        guard let saltData = decodeBase64(String(parts[3])),
              let expectedHashData = decodeBase64(String(parts[4])) else {
            return false
        }
        
        do {
            let key = try KDF.Argon2id.deriveKey(
                from: Data(password.utf8),
                salt: saltData,
                outputByteCount: expectedHashData.count,
                iterations: iterations,
                memoryByteCount: memoryUsage * 1024,
                parallelism: parallelism
            )
            
            let actualHash = key.withUnsafeBytes { Data($0) }
            return safeCompare(actualHash, expectedHashData)
        } catch {
            return false
        }
    }
    
    private func safeCompare(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for (byteA, byteB) in zip(a, b) {
            result |= byteA ^ byteB
        }
        return result == 0
    }
}
