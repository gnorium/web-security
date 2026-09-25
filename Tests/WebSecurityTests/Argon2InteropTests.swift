import Crypto
import CryptoExtras
import XCTest

@testable import Argon2
@testable import WebSecurity

/// Argon2 core and PHC-string interoperability against the reference implementation.
///
/// The RFC 9106 vectors (m=32 KiB, p=4) have a segment length of 2, so the first segment of the
/// first pass computes no blocks and cannot exercise the data-independent address generator's
/// column indexing. The reference vectors below use longer segments and were generated once with
/// libargon2 (the phc-winner-argon2 `argon2` CLI, which argon2-cffi wraps) and with
/// `cryptography`'s OpenSSL-backed Argon2id.
final class Argon2InteropTests: XCTestCase {
  private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  // MARK: - RFC 9106 section 5 (raw)

  private func rfc9106Tag(_ variant: Argon2NativeImplementation.Variant) throws -> String {
    try hex(
      Argon2NativeImplementation.hash(
        password: Data(repeating: 0x01, count: 32),
        salt: Data(repeating: 0x02, count: 16),
        iterations: 3,
        memoryBytes: 32 * 1024,
        parallelism: 4,
        outputLength: 32,
        variant: variant,
        secret: Data(repeating: 0x03, count: 8),
        associatedData: Data(repeating: 0x04, count: 12)))
  }

  func testRFC9106Argon2d() throws {
    XCTAssertEqual(
      try rfc9106Tag(.d), "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
  }

  func testRFC9106Argon2i() throws {
    XCTAssertEqual(
      try rfc9106Tag(.i), "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
  }

  func testRFC9106Argon2id() throws {
    XCTAssertEqual(
      try rfc9106Tag(.id), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
  }

  // MARK: - Reference raw vectors (password "password", salt "somesaltsomesalt", 32-byte tag)

  func testReferenceRawArgon2id() throws {
    let vectors: [(t: Int, m: Int, p: Int, tag: String)] = [
      (3, 65536, 4, "81db97a7e67a891784a2599bc879f957cb3512d273984bd97d8a18fc59ff01e2"),
      (2, 32768, 1, "217f2b4eaa7477d3eedfb412ee5d48c74ea1c64b1a6aff44cb966da7e448452f"),
      (1, 64, 1, "e793d64ef75d58f503d4631b2b149f7f80127c5f3993d89b1c9b781e51d0b413"),
      (2, 64, 2, "c263317d002f84b5342fa66fa169e4bce6a356a13f19193346322ef3522e0702"),
      (1, 32, 4, "3c57781ce2b3a6865c42a6971f3c4a6d408d5dbfa55296279645b31e512f8ae4"),
    ]
    for v in vectors {
      let key = try KDF.Argon2id.deriveKey(
        from: Data("password".utf8),
        salt: Data("somesaltsomesalt".utf8),
        outputByteCount: 32,
        iterations: v.t,
        memoryByteCount: v.m * 1024,
        parallelism: v.p)
      XCTAssertEqual(key.withUnsafeBytes { hex(Data($0)) }, v.tag, "t=\(v.t) m=\(v.m) p=\(v.p)")
    }
  }

  // MARK: - Reference PHC strings

  private struct PHCVector {
    let password: String
    let salt: [UInt8]
    let parameters: PasswordHasher.Parameters?  // set when the tag is 32 bytes and ours can emit it
    let phc: String
  }

  private let phcVectors: [PHCVector] = [
    // Server parameters (PasswordHasher.Parameters.recommended), argon2 CLI.
    PHCVector(
      password: "correct horse battery staple", salt: Array("gnoriumsaltsalt1".utf8),
      parameters: .recommended,
      phc:
        "$argon2id$v=19$m=65536,t=3,p=4$Z25vcml1bXNhbHRzYWx0MQ$OkMRL/sdG6ccIU9aS1U9QFxfGsZPp4Pz/iSMBwYwSCM"
    ),
    // Parameters.interactive, argon2 CLI.
    PHCVector(
      password: "quick-password", salt: Array("interactivesalt2".utf8), parameters: .interactive,
      phc:
        "$argon2id$v=19$m=32768,t=2,p=1$aW50ZXJhY3RpdmVzYWx0Mg$mHPKMIkdTIlfB0JJD1FGlNmsAZtU6/sYnqM9DchGlc4"
    ),
    // Non-ASCII password, 8-byte salt, 16-byte tag, argon2 CLI.
    PHCVector(
      password: "पासवर्ड ünïcode", salt: Array("shortslt".utf8), parameters: nil,
      phc: "$argon2id$v=19$m=64,t=1,p=2$c2hvcnRzbHQ$+dGKCU5m3mEHUQ//9lftRg"),
    // Empty password, binary salt, 64-byte tag, p=3, cryptography.
    PHCVector(
      password: "", salt: Array(0xf0...0xff), parameters: nil,
      phc:
        "$argon2id$v=19$m=256,t=2,p=3$8PHy8/T19vf4+fr7/P3+/w$MJJF1Lhvq2QKOu4SiyyR4Y9zVdHzIfw3gyVxUfVy3120RJLp/PTteBKzAjRrOjxlEeLsFXyoP223vtAqS8CjBg"
    ),
    // Binary salt with '+' and '/' in its base64, cryptography.
    PHCVector(
      password: "pa$$w0rd", salt: [0xfb, 0xff, 0xbf, 0x3e, 0x00, 0x7f, 0x80, 0xfe],
      parameters: PasswordHasher.Parameters(memoryUsage: 8, iterations: 1, parallelism: 1),
      phc: "$argon2id$v=19$m=8,t=1,p=1$+/+/PgB/gP4$MefeY3UrZWVxYIz6QbU8z5ojkWbdueVbDFspDJJ41Ho"),
  ]

  func testVerifiesReferencePHCStrings() {
    for v in phcVectors {
      let hasher = PasswordHasher(parameters: v.parameters ?? .recommended)
      XCTAssertTrue(hasher.verify(v.password, against: v.phc), v.phc)
      XCTAssertFalse(hasher.verify(v.password + "x", against: v.phc), v.phc)
    }
  }

  func testProducesReferencePHCStrings() throws {
    for v in phcVectors {
      guard let parameters = v.parameters else { continue }
      XCTAssertEqual(try PasswordHasher(parameters: parameters).hash(v.password, salt: v.salt), v.phc)
    }
  }

  func testRejectsUnsupportedVersion() {
    // Argon2id v=16 (0x10) from the argon2 CLI; the core implements only v=19.
    XCTAssertFalse(
      PasswordHasher().verify(
        "password",
        against:
          "$argon2id$v=16$m=1024,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$gVsUT0yLjLzyTv/P1z3klZCUNuVm1KaPuMEegTbwyjE"
      ))
  }
}
