import XCTest
@testable import WebSecurity
@testable import Argon2
import Crypto
import CryptoExtras

final class PasswordHasherTests: XCTestCase {
    func testArgon2idHashingAndVerification() throws {
        let hasher = PasswordHasher()
        let password = "gnorium-secure-password"
        
        // Test hashing
        let hash = try hasher.hash(password)
        XCTAssertTrue(hash.contains("$argon2id$v=19$"))
        
        // Test correct verification
        XCTAssertTrue(hasher.verify(password, against: hash), "Verification should succeed for correct password")
        
        // Test incorrect verification
        XCTAssertFalse(hasher.verify("wrong-password", against: hash), "Verification should fail for incorrect password")
    }
    
    func testInteractiveParameters() throws {
        let hasher = PasswordHasher(parameters: .interactive)
        let password = "quick-password"
        
        let hash = try hasher.hash(password)
        XCTAssertTrue(hash.contains("m=32768,t=2,p=1"))
        XCTAssertTrue(hasher.verify(password, against: hash))
    }
    
    func testStandardPHCFormatCompatibility() throws {
        // We want to ensure we can parse what we generate
        let hasher = PasswordHasher()
        let password = "format-compatibility"
        let hash = try hasher.hash(password)
        
        // The format should be: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
        let components = hash.split(separator: "$")
        XCTAssertEqual(components.count, 5)
        XCTAssertEqual(components[0], "argon2id")
        XCTAssertEqual(components[1], "v=19")
        XCTAssertEqual(components[2], "m=65536,t=3,p=4")
    }
    
    func testRFC9106Argon2idTestVector() throws {
        // From RFC 9106, Section 5.3
        let password = Data(repeating: 0x01, count: 32)
        let salt = Data(repeating: 0x02, count: 16)
        let secret = Data(repeating: 0x03, count: 8)
        let ad = Data(repeating: 0x04, count: 12)
        
        let key = try KDF.Argon2id.deriveKey(
            from: password,
            salt: salt,
            outputByteCount: 32,
            iterations: 3,
            memoryByteCount: 32 * 1024,
            parallelism: 4,
            secret: secret,
            associatedData: ad
        )
        
        let actualHash = key.withUnsafeBytes { Data($0) }
        
        // Expected Tag from RFC 9106, Section 5.3
        let expectedHash = Data([
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 
            0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9, 
            0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 
            0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
        ])
        
        XCTAssertEqual(actualHash, expectedHash, "Hash should match RFC 9106 test vector")
    }
}
