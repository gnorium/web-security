import Foundation
import Crypto

/// Utilities for encrypting and decrypting data using AES-GCM.
public struct DataEncryptor: Sendable {
    
    public init() {}

    /// Encrypt a string using AES-GCM and a symmetric key.
    /// - Returns: Base64 encoded combined representation of the sealed box.
    public func encrypt(_ value: String, using key: SymmetricKey) throws -> String {
        guard let data = value.data(using: .utf8) else {
            throw EncryptionError.invalidInput
        }
        let sealedBox = try AES.GCM.seal(data, using: key)
        guard let combined = sealedBox.combined else {
            throw EncryptionError.encryptionFailed
        }
        return combined.base64EncodedString()
    }

    /// Decrypt a combined AES-GCM sealed box.
    public func decrypt(_ encryptedValue: String, using key: SymmetricKey) throws -> String {
        guard let data = Data(base64Encoded: encryptedValue) else {
            throw EncryptionError.invalidInput
        }
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        guard let value = String(data: decryptedData, encoding: .utf8) else {
            throw EncryptionError.decryptionFailed
        }
        return value
    }

    /// Generate a cryptographically secure hash of a string.
    public func hash(_ value: String) -> String {
        guard let data = value.data(using: .utf8) else { return "" }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
}

public enum EncryptionError: Error, Sendable {
    case invalidInput
    case encryptionFailed
    case decryptionFailed
}
