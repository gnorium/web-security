import Crypto
import CryptoExtras
import Foundation
import XCTest

@testable import Argon2

/// Wall-clock timing of Argon2id at the server parameters (m=65536 KiB, t=3, p=4).
///
/// Skipped unless `ARGON2_BENCH=1`, so the regular suite stays fast. Run it in both
/// configurations:
///
///     ARGON2_BENCH=1 swift test --filter Argon2BenchmarkTests
///     ARGON2_BENCH=1 swift test -c release -Xswiftc -enable-testing --filter Argon2BenchmarkTests
final class Argon2BenchmarkTests: XCTestCase {
  func testServerParametersTiming() throws {
    try XCTSkipUnless(
      ProcessInfo.processInfo.environment["ARGON2_BENCH"] == "1", "set ARGON2_BENCH=1 to run")
    let runs = Int(ProcessInfo.processInfo.environment["ARGON2_BENCH_RUNS"] ?? "") ?? 5
    var seconds: [Double] = []
    for _ in 0..<runs {
      let start = ContinuousClock.now
      let key = try KDF.Argon2id.deriveKey(
        from: Data("password".utf8),
        salt: Data("somesaltsomesalt".utf8),
        outputByteCount: 32,
        iterations: 3,
        memoryByteCount: 65536 * 1024,
        parallelism: 4)
      let elapsed = ContinuousClock.now - start
      seconds.append(
        Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18)
      XCTAssertEqual(
        key.withUnsafeBytes { Data($0).map { String(format: "%02x", $0) }.joined() },
        "81db97a7e67a891784a2599bc879f957cb3512d273984bd97d8a18fc59ff01e2")
    }
    let formatted = seconds.map { String(format: "%.3f", $0) }.joined(separator: ", ")
    print("ARGON2_BENCH m=65536 t=3 p=4 runs(s): [\(formatted)] min=\(seconds.min()!)")
  }
}
