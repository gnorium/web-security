import Crypto
import XCTest

@testable import WebSecurity

final class DataEncryptorTests: XCTestCase {
  let encryptor = DataEncryptor()
  let key = SymmetricKey(size: .bits256)

  func testASealedValueOpensWithItsKeyAndContext() throws {
    let sealed = try encryptor.encrypt("JBSWY3DPEHPK3PXP", using: key, context: "users.totp_secret:1")
    XCTAssertFalse(sealed.contains("JBSWY3DPEHPK3PXP"))
    XCTAssertEqual(try encryptor.decrypt(sealed, using: key, context: "users.totp_secret:1"), "JBSWY3DPEHPK3PXP")
  }

  func testEachSealIsFresh() throws {
    let first = try encryptor.encrypt("same", using: key, context: "c")
    let second = try encryptor.encrypt("same", using: key, context: "c")
    XCTAssertNotEqual(first, second, "a fresh nonce every time")
  }

  func testTheSealedFormIsCookieSafe() throws {
    let sealed = try encryptor.encrypt(String(repeating: "x", count: 200), using: key, context: "cookie")
    XCTAssertNil(sealed.rangeOfCharacter(from: CharacterSet(charactersIn: "+/=;, ")))
  }

  func testAnotherContextDoesNotOpenIt() throws {
    let sealed = try encryptor.encrypt("secret", using: key, context: "users.totp_secret:1")
    XCTAssertThrowsError(try encryptor.decrypt(sealed, using: key, context: "users.totp_secret:2"))
  }

  func testAnotherKeyDoesNotOpenIt() throws {
    let sealed = try encryptor.encrypt("secret", using: key, context: "c")
    XCTAssertThrowsError(try encryptor.decrypt(sealed, using: SymmetricKey(size: .bits256), context: "c"))
  }

  func testAnAlteredValueDoesNotOpen() throws {
    let sealed = try encryptor.encrypt("secret", using: key, context: "c")
    var bytes = Array(sealed)
    let middle = bytes.count / 2
    bytes[middle] = bytes[middle] == "A" ? "B" : "A"
    XCTAssertThrowsError(try encryptor.decrypt(String(bytes), using: key, context: "c"))
    XCTAssertThrowsError(try encryptor.decrypt("not sealed", using: key, context: "c"))
  }

  func testAKeyedHashNeedsItsKey() {
    let hash = encryptor.keyedHash("203.0.113.7", using: key)
    XCTAssertEqual(hash.count, 64)
    XCTAssertEqual(hash, encryptor.keyedHash("203.0.113.7", using: key))
    XCTAssertNotEqual(hash, encryptor.keyedHash("203.0.113.7", using: SymmetricKey(size: .bits256)))
    let unsalted = SHA256.hash(data: Data("203.0.113.7".utf8)).map { String(format: "%02x", $0) }.joined()
    XCTAssertNotEqual(hash, unsalted)
  }

  func testDerivedKeysDifferByPurpose() {
    let master = SymmetricKey(size: .bits256)
    let a = DataEncryptor.derivedKey(from: master, purpose: "a")
    let b = DataEncryptor.derivedKey(from: master, purpose: "b")
    XCTAssertNotEqual(a.withUnsafeBytes { Data($0) }, b.withUnsafeBytes { Data($0) })
    XCTAssertEqual(
      a.withUnsafeBytes { Data($0) },
      DataEncryptor.derivedKey(from: master, purpose: "a").withUnsafeBytes { Data($0) })
  }
}
