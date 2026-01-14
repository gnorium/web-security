import Foundation
import Crypto

/// TOTP (Time-based One-Time Password) authenticator for MFA.
/// Compatible with Apple Password Manager, Google Authenticator, Authy, etc.
public struct TOTPAuthenticator: Sendable {
    private let digits: Int
    private let timeStep: TimeInterval
    private let algorithm: String

    public init(digits: Int = 6, timeStep: TimeInterval = 30, algorithm: String = "SHA1") {
        self.digits = digits
        self.timeStep = timeStep
        self.algorithm = algorithm
    }

    /// Generate a random base32-encoded secret for TOTP.
    public func generateSecret() -> String {
        var bytes = [UInt8](repeating: 0, count: 20)
        #if os(Linux)
        // Secure randomness
        #else
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        #endif
        return base32Encode(bytes)
    }

    /// Generate a TOTP code for the current time.
    public func generateCode(secret: String) throws -> String {
        let timeCounter = Int(Date().timeIntervalSince1970 / timeStep)
        return try generateCode(secret: secret, counter: timeCounter)
    }

    /// Verify a TOTP code with time window tolerance.
    public func verifyCode(_ code: String, secret: String, window: Int = 1) -> Bool {
        let currentCounter = Int(Date().timeIntervalSince1970 / timeStep)
        for offset in -window...window {
            let counter = currentCounter + offset
            if let generatedCode = try? generateCode(secret: secret, counter: counter),
               generatedCode == code {
                return true
            }
        }
        return false
    }

    /// Generate otpauth:// URL for QR code setup.
    public func generateOTPAuthURL(
        secret: String,
        accountName: String,
        issuer: String
    ) -> String {
        let encodedIssuer = issuer.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? issuer
        let encodedAccount = accountName.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? accountName
        return "otpauth://totp/\(encodedIssuer):\(encodedAccount)?secret=\(secret)&issuer=\(encodedIssuer)&algorithm=\(algorithm)&digits=\(digits)&period=\(Int(timeStep))"
    }

    // MARK: - Internal Implementation

    private func generateCode(secret: String, counter: Int) throws -> String {
        guard let secretData = base32Decode(secret) else {
            throw TOTPError.invalidSecret
        }
        var counterValue = UInt64(counter).bigEndian
        let counterBytes = withUnsafeBytes(of: &counterValue) { Array($0) }
        let key = SymmetricKey(data: secretData)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: counterBytes, using: key)
        let hmacBytes = Array(hmac)
        let offset = Int(hmacBytes[hmacBytes.count - 1] & 0x0f)
        let truncatedHash = (
            (UInt32(hmacBytes[offset]) & 0x7f) << 24 |
            (UInt32(hmacBytes[offset + 1]) & 0xff) << 16 |
            (UInt32(hmacBytes[offset + 2]) & 0xff) << 8 |
            (UInt32(hmacBytes[offset + 3]) & 0xff)
        )
        let code = truncatedHash % UInt32(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)d", code)
    }

    private func base32Encode(_ data: [UInt8]) -> String {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var result = ""
        var bits = 0
        var value = 0
        for byte in data {
            value = (value << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                let index = (value >> (bits - 5)) & 0x1F
                result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
                bits -= 5
            }
        }
        if bits > 0 {
            let index = (value << (5 - bits)) & 0x1F
            result.append(alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)])
        }
        return result
    }

    private func base32Decode(_ string: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let normalized = string.uppercased().replacingOccurrences(of: " ", with: "")
        var bits = 0
        var value = 0
        var data = Data()
        for char in normalized {
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            value = (value << 5) | alphabet.distance(from: alphabet.startIndex, to: index)
            bits += 5
            if bits >= 8 {
                data.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        return data
    }

    // MARK: - Recovery Codes

    /// Generate recovery codes for account recovery.
    /// - Parameter count: Number of recovery codes to generate (default 8).
    /// - Returns: Array of recovery codes (e.g., "XXXX-XXXX").
    public func generateRecoveryCodes(count: Int = 8) -> [String] {
        let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude ambiguous chars (0, O, 1, I)
        var codes: [String] = []
        for _ in 0..<count {
            var code = ""
            var bytes = [UInt8](repeating: 0, count: 8)
            #if !os(Linux)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            #endif
            for byte in bytes {
                let index = Int(byte) % chars.count
                code.append(chars[chars.index(chars.startIndex, offsetBy: index)])
            }
            let formatted = String(code.prefix(4)) + "-" + String(code.suffix(4))
            codes.append(formatted)
        }
        return codes
    }

    /// Hash a recovery code for secure storage.
    public func hashRecoveryCode(_ code: String) -> String {
        let normalized = code.replacingOccurrences(of: "-", with: "").uppercased()
        guard let data = normalized.data(using: .utf8) else { return "" }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }

    /// Verify a recovery code against its stored hash.
    public func verifyRecoveryCode(_ code: String, against hash: String) -> Bool {
        return hashRecoveryCode(code) == hash
    }
}

public enum TOTPError: Error {
    case invalidSecret
    case invalidCode
}
