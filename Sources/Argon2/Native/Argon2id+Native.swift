import Crypto
import Foundation

#if canImport(Dispatch)
  import Dispatch
#endif

internal enum Argon2NativeImplementation {
  enum Variant: Int, Sendable { case d = 0, i = 1, id = 2 }

  /// Words per 1 KiB block.
  static let blockWords = 128

  /// Pure Swift implementation of Argon2 (version 0x13) as defined in RFC 9106.
  /// See: https://www.rfc-editor.org/rfc/rfc9106.html
  ///
  /// All blocks live in one contiguous allocation (`Memory`); the compression function works on
  /// raw pointers with no per-block allocations, so the only heap traffic is the matrix itself and
  /// one scratch area per segment. When `parallelism > 1` the lanes of each slice are filled
  /// concurrently: a lane writes only its own segment and reads other lanes only outside the
  /// current slice, and slices are synchronisation points (RFC 9106, section 3.4).
  static func hash<P: DataProtocol, S: DataProtocol>(
    password: P, salt: S, iterations: Int, memoryBytes: Int, parallelism: Int, outputLength: Int,
    variant: Variant, secret: Data? = nil, associatedData: Data? = nil
  ) throws -> Data {
    let m = memoryBytes / 1024
    let p = parallelism
    let t = iterations
    let m_prime = 4 * p * (m / (4 * p))
    let q = m_prime / p

    var h0Input = Data()
    h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(p).littleEndian) { Data($0) })
    h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(outputLength).littleEndian) { Data($0) })
    h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(m).littleEndian) { Data($0) })
    h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(t).littleEndian) { Data($0) })
    h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(0x13).littleEndian) { Data($0) })
    h0Input.append(
      contentsOf: withUnsafeBytes(of: UInt32(variant.rawValue).littleEndian) { Data($0) })

    func appendData<D: DataProtocol>(_ d: D) {
      h0Input.append(contentsOf: withUnsafeBytes(of: UInt32(d.count).littleEndian) { Data($0) })
      h0Input.append(contentsOf: d)
    }

    appendData(password)
    appendData(salt)
    appendData(secret ?? Data())
    appendData(associatedData ?? Data())

    let h0 = Blake2b.hash(data: h0Input, outLength: 64)
    let memory = Memory(lanes: p, laneLength: q)
    defer { memory.deallocate() }

    for lane in 0..<p {
      for j in 0..<2 {
        var input = Data(h0)
        input.append(contentsOf: withUnsafeBytes(of: UInt32(j).littleEndian) { Data($0) })
        input.append(contentsOf: withUnsafeBytes(of: UInt32(lane).littleEndian) { Data($0) })
        load(hPrime(data: input, length: 1024), into: memory.block(lane: lane, column: j))
      }
    }

    let geometry = Geometry(
      lanes: p, laneLength: q, segmentLength: q / 4, m_prime: m_prime, iterations: t,
      variant: variant)
    for pass in 0..<t {
      for slice in 0..<4 {
        #if canImport(Dispatch)
          if p > 1 {
            DispatchQueue.concurrentPerform(iterations: p) { lane in
              fillSegment(memory, geometry, pass: pass, lane: lane, slice: slice)
            }
            continue
          }
        #endif
        for lane in 0..<p {
          fillSegment(memory, geometry, pass: pass, lane: lane, slice: slice)
        }
      }
    }

    var finalBlock = [UInt64](repeating: 0, count: blockWords)
    for lane in 0..<p {
      let last = memory.block(lane: lane, column: q - 1)
      for i in 0..<blockWords { finalBlock[i] ^= last[i] }
    }
    var finalBytes = Data(capacity: 1024)
    for word in finalBlock {
      withUnsafeBytes(of: word.littleEndian) { finalBytes.append(contentsOf: $0) }
    }
    return hPrime(data: finalBytes, length: outputLength)
  }

  // MARK: - Memory

  /// The block matrix: `lanes` rows of `laneLength` 1 KiB blocks in one contiguous allocation.
  ///
  /// `@unchecked Sendable` because lanes are filled concurrently through the same base pointer.
  /// That is sound only because of Argon2's segment discipline: during a slice each lane writes
  /// solely its own segment, and reads of other lanes never touch the current slice.
  private struct Memory: @unchecked Sendable {
    let words: UnsafeMutablePointer<UInt64>
    let laneLength: Int

    init(lanes: Int, laneLength: Int) {
      let count = lanes * laneLength * Argon2NativeImplementation.blockWords
      words = UnsafeMutablePointer<UInt64>.allocate(capacity: count)
      words.initialize(repeating: 0, count: count)
      self.laneLength = laneLength
    }

    func block(lane: Int, column: Int) -> UnsafeMutablePointer<UInt64> {
      words + (lane &* laneLength &+ column) &* Argon2NativeImplementation.blockWords
    }

    func deallocate() { words.deallocate() }
  }

  /// The fixed shape of one hash, shared by every segment fill.
  private struct Geometry: Sendable {
    let lanes: Int
    let laneLength: Int
    let segmentLength: Int
    let m_prime: Int
    let iterations: Int
    let variant: Variant
  }

  // MARK: - Segment filling

  /// Fills one segment (pass, lane, slice): computes its blocks in column order.
  ///
  /// Data-independent addressing (Argon2i, and the first half of the first pass of Argon2id)
  /// draws the pseudo-random pair for segment column `col` from word `col % 128` of address block
  /// `col / 128 + 1`, where address block k is G(0, G(0, input)) with the counter set to k.
  /// Columns are addressed by position, not consumed in order: in the first segment of the first
  /// pass columns 0 and 1 are not computed, yet their words are skipped (RFC 9106, section 3.4.2;
  /// libargon2 `fill_segment`).
  private static func fillSegment(
    _ memory: Memory, _ geometry: Geometry, pass: Int, lane: Int, slice: Int
  ) {
    let q = geometry.laneLength
    let segmentLength = geometry.segmentLength
    let variant = geometry.variant
    let dataIndependent = variant == .i || (variant == .id && pass == 0 && slice < 2)

    // Scratch: compression temporary, address input, address output, the zero block, and the
    // intermediate G(0, input).
    let scratch = UnsafeMutablePointer<UInt64>.allocate(capacity: 5 * blockWords)
    scratch.initialize(repeating: 0, count: 5 * blockWords)
    defer { scratch.deallocate() }
    let temporary = scratch
    let addressInput = scratch + blockWords
    let addresses = scratch + 2 * blockWords
    let zero = scratch + 3 * blockWords
    let intermediate = scratch + 4 * blockWords
    var addressCounter: UInt64 = 0
    if dataIndependent {
      addressInput[0] = UInt64(pass)
      addressInput[1] = UInt64(lane)
      addressInput[2] = UInt64(slice)
      addressInput[3] = UInt64(geometry.m_prime)
      addressInput[4] = UInt64(geometry.iterations)
      addressInput[5] = UInt64(variant.rawValue)
    }

    var col = (pass == 0 && slice == 0) ? 2 : 0
    while col < segmentLength {
      let j = slice &* segmentLength &+ col
      let prevCol = j == 0 ? q &- 1 : j &- 1
      let previous = memory.block(lane: lane, column: prevCol)

      let pseudoRandom: UInt64
      if dataIndependent {
        let needed = UInt64(col / blockWords &+ 1)
        if addressCounter != needed {
          addressCounter = needed
          addressInput[6] = needed
          compress(zero, addressInput, into: intermediate, xor: false, temporary: temporary)
          compress(zero, intermediate, into: addresses, xor: false, temporary: temporary)
        }
        pseudoRandom = addresses[col % blockWords]
      } else {
        pseudoRandom = previous[0]
      }
      let j1 = UInt32(truncatingIfNeeded: pseudoRandom)
      let j2 = UInt32(truncatingIfNeeded: pseudoRandom &>> 32)

      // Reference lane and reference-set size (RFC 9106, section 3.4.1).
      let l = (pass == 0 && slice == 0) ? lane : Int(j2 % UInt32(geometry.lanes))
      var refSize: Int
      if pass == 0 {
        refSize =
          (l == lane)
          ? (slice &* segmentLength &+ col &- 1) : (slice &* segmentLength &- (col == 0 ? 1 : 0))
      } else {
        refSize =
          (l == lane)
          ? (q &- segmentLength &+ col &- 1) : (q &- segmentLength &- (col == 0 ? 1 : 0))
      }
      if refSize < 1 { refSize = 1 }
      let x = (UInt64(j1) &* UInt64(j1)) &>> 32
      let z = (UInt64(refSize) &* x) &>> 32
      let relPos = refSize &- 1 &- Int(z)
      let absZ = (pass == 0) ? relPos : ((slice &+ 1) &* segmentLength &+ relPos) % q

      compress(
        previous, memory.block(lane: l, column: absZ), into: memory.block(lane: lane, column: j),
        xor: pass != 0, temporary: temporary)
      col &+= 1
    }
  }

  // MARK: - Compression

  /// The compression function G (RFC 9106, section 3.5): `out = P(x ^ y) ^ x ^ y`, additionally
  /// XORed with the previous contents of `out` when `xor` is set (passes after the first).
  ///
  /// `x ^ y` is formed in `temporary` before `out` is written, so `out` may alias `x` or `y`.
  private static func compress(
    _ x: UnsafePointer<UInt64>, _ y: UnsafePointer<UInt64>, into out: UnsafeMutablePointer<UInt64>,
    xor: Bool, temporary r: UnsafeMutablePointer<UInt64>
  ) {
    var i = 0
    while i < blockWords {
      r[i] = x[i] ^ y[i]
      i &+= 1
    }
    i = 0
    if xor {
      while i < blockWords {
        out[i] ^= r[i]
        i &+= 1
      }
    } else {
      while i < blockWords {
        out[i] = r[i]
        i &+= 1
      }
    }

    // P over the eight rows (16 consecutive words each), then the eight columns (word pairs
    // 2i, 2i+1 of every row).
    var k = 0
    while k < 8 {
      let b = 16 &* k
      permute(
        r, b, b &+ 1, b &+ 2, b &+ 3, b &+ 4, b &+ 5, b &+ 6, b &+ 7, b &+ 8, b &+ 9, b &+ 10,
        b &+ 11, b &+ 12, b &+ 13, b &+ 14, b &+ 15)
      k &+= 1
    }
    k = 0
    while k < 8 {
      let b = 2 &* k
      permute(
        r, b, b &+ 1, b &+ 16, b &+ 17, b &+ 32, b &+ 33, b &+ 48, b &+ 49, b &+ 64, b &+ 65,
        b &+ 80, b &+ 81, b &+ 96, b &+ 97, b &+ 112, b &+ 113)
      k &+= 1
    }

    i = 0
    while i < blockWords {
      out[i] ^= r[i]
      i &+= 1
    }
  }

  /// The permutation P on sixteen words of `v` (RFC 9106, section 3.6): the BLAKE2b round with
  /// the BlaMka multiply-add, on columns then diagonals of the 4×4 word matrix.
  private static func permute(
    _ v: UnsafeMutablePointer<UInt64>,
    _ i0: Int, _ i1: Int, _ i2: Int, _ i3: Int, _ i4: Int, _ i5: Int, _ i6: Int, _ i7: Int,
    _ i8: Int, _ i9: Int, _ i10: Int, _ i11: Int, _ i12: Int, _ i13: Int, _ i14: Int, _ i15: Int
  ) {
    var v0 = v[i0]
    var v1 = v[i1]
    var v2 = v[i2]
    var v3 = v[i3]
    var v4 = v[i4]
    var v5 = v[i5]
    var v6 = v[i6]
    var v7 = v[i7]
    var v8 = v[i8]
    var v9 = v[i9]
    var v10 = v[i10]
    var v11 = v[i11]
    var v12 = v[i12]
    var v13 = v[i13]
    var v14 = v[i14]
    var v15 = v[i15]

    gb(&v0, &v4, &v8, &v12)
    gb(&v1, &v5, &v9, &v13)
    gb(&v2, &v6, &v10, &v14)
    gb(&v3, &v7, &v11, &v15)

    gb(&v0, &v5, &v10, &v15)
    gb(&v1, &v6, &v11, &v12)
    gb(&v2, &v7, &v8, &v13)
    gb(&v3, &v4, &v9, &v14)

    v[i0] = v0
    v[i1] = v1
    v[i2] = v2
    v[i3] = v3
    v[i4] = v4
    v[i5] = v5
    v[i6] = v6
    v[i7] = v7
    v[i8] = v8
    v[i9] = v9
    v[i10] = v10
    v[i11] = v11
    v[i12] = v12
    v[i13] = v13
    v[i14] = v14
    v[i15] = v15
  }

  /// GB (RFC 9106, section 3.6): the BLAKE2b G function with each addition `a + b` replaced by
  /// the BlaMka `a + b + 2 * lo32(a) * lo32(b)`, all modulo 2^64.
  @inline(__always)
  private static func gb(
    _ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64
  ) {
    a = a &+ b &+ 2 &* (a & 0xFFFF_FFFF) &* (b & 0xFFFF_FFFF)
    d = rotateRight(d ^ a, 32)
    c = c &+ d &+ 2 &* (c & 0xFFFF_FFFF) &* (d & 0xFFFF_FFFF)
    b = rotateRight(b ^ c, 24)
    a = a &+ b &+ 2 &* (a & 0xFFFF_FFFF) &* (b & 0xFFFF_FFFF)
    d = rotateRight(d ^ a, 16)
    c = c &+ d &+ 2 &* (c & 0xFFFF_FFFF) &* (d & 0xFFFF_FFFF)
    b = rotateRight(b ^ c, 63)
  }

  @inline(__always)
  private static func rotateRight(_ value: UInt64, _ by: UInt64) -> UInt64 {
    (value &>> by) | (value &<< (64 &- by))
  }

  // MARK: - Variable-length hash and block encoding

  private static func hPrime(data: Data, length: Int) -> Data {
    if length <= 64 {
      return Blake2b.hash(
        data: withUnsafeBytes(of: UInt32(length).littleEndian) { Data($0) } + data,
        outLength: length)
    }
    let r = (length + 31) / 32 - 2
    var result = Data()
    var v = Blake2b.hash(
      data: withUnsafeBytes(of: UInt32(length).littleEndian) { Data($0) } + data, outLength: 64)
    result.append(v.prefix(32))
    for _ in 0..<r - 1 {
      v = Blake2b.hash(data: v, outLength: 64)
      result.append(v.prefix(32))
    }
    v = Blake2b.hash(data: v, outLength: length - 32 * r)
    result.append(v)
    return result
  }

  /// Loads 1024 bytes as 128 little-endian words into `block`.
  private static func load(_ data: Data, into block: UnsafeMutablePointer<UInt64>) {
    let bytes = [UInt8](data)
    for i in 0..<blockWords {
      let offset = i * 8
      var val: UInt64 = 0
      for k in 0..<8 { val |= UInt64(bytes[offset + k]) << (k * 8) }
      block[i] = val
    }
  }
}
