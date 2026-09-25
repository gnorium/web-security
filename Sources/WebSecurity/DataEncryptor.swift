import Crypto
import Foundation

/// Authenticated encryption of short strings (secrets kept in a database
/// column or a cookie) with AES-256-GCM, and keyed hashing with HMAC-SHA256.
///
/// Every sealed value is bound to a `context`, authenticated with it but not
/// stored in it: the column and row it belongs to (`"users.totp_secret:<id>"`),
/// or the cookie that carries it. A value copied to another row or cookie
/// fails to open, as does one sealed under another key or altered by a byte.
///
/// Keys come from one master secret, split by purpose with HKDF
/// (`derivedKey(from:purpose:)`), so the encryption keys and the hashing key
/// are never the same bytes.
public struct DataEncryptor: Sendable {

  public init() {}

  /// Seals `value` under `key`, bound to `context`.
  /// - Returns: The sealed box's combined form (nonce, ciphertext, tag),
  ///   base64url without padding, so it can sit in a cookie as it is.
  public func encrypt(_ value: String, using key: SymmetricKey, context: String) throws -> String {
    let sealedBox = try AES.GCM.seal(Data(value.utf8), using: key, authenticating: Data(context.utf8))
    guard let combined = sealedBox.combined else {
      throw EncryptionError.encryptionFailed
    }
    return Self.base64URL(combined)
  }

  /// Opens a value `encrypt` sealed under `key` for the same `context`.
  /// Throws for any other key, context, or a value altered in any way.
  public func decrypt(_ encryptedValue: String, using key: SymmetricKey, context: String) throws -> String {
    guard let data = Self.data(base64URL: encryptedValue) else {
      throw EncryptionError.invalidInput
    }
    let sealedBox = try AES.GCM.SealedBox(combined: data)
    let decryptedData = try AES.GCM.open(sealedBox, using: key, authenticating: Data(context.utf8))
    guard let value = String(data: decryptedData, encoding: .utf8) else {
      throw EncryptionError.decryptionFailed
    }
    return value
  }

  /// HMAC-SHA256 of `value` under `key`, as lowercase hex (64 characters).
  /// Without the key, the hash of a guessable value (an IP address) can't be
  /// recomputed, which an unsalted hash of it can be in seconds.
  public func keyedHash(_ value: String, using key: SymmetricKey) -> String {
    HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: key)
      .map { String(format: "%02x", $0) }.joined()
  }

  /// A 256-bit key for one `purpose`, derived from `master` with HKDF-SHA256.
  public static func derivedKey(from master: SymmetricKey, purpose: String) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: master, info: Data(purpose.utf8), outputByteCount: 32)
  }

  private static func base64URL(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private static func data(base64URL string: String) -> Data? {
    var base64 = string
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }
    return Data(base64Encoded: base64)
  }
}

public enum EncryptionError: Error, Sendable {
  case invalidInput
  case encryptionFailed
  case decryptionFailed
}
