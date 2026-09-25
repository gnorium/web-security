import Crypto
import CryptoExtras
import XCTest

@testable import Argon2
@testable import WebSecurity

final class PasswordHasherTests: XCTestCase {
  func testArgon2idHashingAndVerification() throws {
    let hasher = PasswordHasher()
    let password = "gnorium-secure-password"

    // Test hashing
    let hash = try hasher.hash(password)
    XCTAssertTrue(hash.contains("$argon2id$v=19$"))

    // Test correct verification
    XCTAssertTrue(
      hasher.verify(password, against: hash), "Verification should succeed for correct password")

    // Test incorrect verification
    XCTAssertFalse(
      hasher.verify("wrong-password", against: hash),
      "Verification should fail for incorrect password")
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
}
