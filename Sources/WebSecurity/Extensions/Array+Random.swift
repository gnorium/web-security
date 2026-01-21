import Foundation

extension Array where Element == UInt8 {
    /// Generates a cryptographically secure random sequence of bytes.
    /// Uses SystemRandomNumberGenerator, which is cross-platform (macOS/Linux).
    static func random(count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        var generator = SystemRandomNumberGenerator()
        for i in 0..<count {
            bytes[i] = UInt8.random(in: 0...255, using: &generator)
        }
        return bytes
    }
}
