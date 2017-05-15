import Foundation

@_transparent
fileprivate
func hash16Bytes(_ low: UInt64, _ high: UInt64) -> UInt64 {
    // Murmur-inspired hashing.
    let mul: UInt64 = 0x9ddfea08eb382d69
    var a: UInt64 = (low ^ high) &* mul
    a ^= (a >> 47)
    var b: UInt64 = (high ^ a) &* mul
    b ^= (b >> 47)
    b = b &* mul
    return b
}

@_transparent
fileprivate
func _roundUpToPowerOf2Int32(_ val: Int32) -> Int32 {
    var v = val - 1
    v |= v >> 1
    v |= v >> 2
    v |= v >> 4
    v |= v >> 8
    v |= v >> 16
    return v + 1
}

@_transparent
fileprivate
func _roundUpToPowerOf2Int64(_ val: Int64) -> Int64 {
    var v = val - 1
    v |= v >> 1
    v |= v >> 2
    v |= v >> 4
    v |= v >> 8
    v |= v >> 16
    v |= v >> 32
    return v + 1
}

@_transparent
fileprivate
func _roundUpToPowerOf2(_ val: Int) -> Int {
#if arch(i386) || arch(arm)
    return Int(_roundUpToPowerOf2Int32(Int32(val)))
#elseif arch(x86_64) || arch(arm64) || arch(powerpc64) || arch(powerpc64le) || arch(s390x)
    return Int(_roundUpToPowerOf2Int64(Int64(val)))
#endif
}

//
// API functions.
//

//
// _mix*() functions all have type (T) -> T.  These functions don't compress
// their inputs and just exhibit avalanche effect.
//

@_transparent
fileprivate // @testable
func _mixUInt32(_ value: UInt32) -> UInt32 {
    // Zero-extend to 64 bits, hash, select 32 bits from the hash.
    //
    // NOTE: this differs from LLVM's implementation, which selects the lower
    // 32 bits.  According to the statistical tests, the 3 lowest bits have
    // weaker avalanche properties.
    let extendedValue = UInt64(value)
    let extendedResult = _mixUInt64(extendedValue)
    return UInt32((extendedResult >> 3) & 0xffff_ffff)
}

@_transparent
fileprivate // @testable
func _mixInt32(_ value: Int32) -> Int32 {
    return Int32(bitPattern: _mixUInt32(UInt32(bitPattern: value)))
}

@_transparent
fileprivate // @testable
func _mixUInt64(_ value: UInt64) -> UInt64 {
    // Similar to hash_4to8_bytes but using a seed instead of length.
    let seed: UInt64 = 0xff51afd7ed558ccd
    let low: UInt64 = value & 0xffff_ffff
    let high: UInt64 = value >> 32
    return hash16Bytes(seed &+ (low << 3), high)
}

@_transparent
fileprivate // @testable
func _mixInt64(_ value: Int64) -> Int64 {
    return Int64(bitPattern: _mixUInt64(UInt64(bitPattern: value)))
}

@_transparent
fileprivate // @testable
func _mixInt(_ value: Int) -> Int {
#if arch(i386) || arch(arm)
    return Int(_mixInt32(Int32(value)))
#elseif arch(x86_64) || arch(arm64) || arch(powerpc64) || arch(powerpc64le) || arch(s390x)
    return Int(_mixInt64(Int64(value)))
#endif
}

/// Given a hash value, returns an integer value in the range of
/// 0..<`upperBound` that corresponds to a hash value.
///
/// The `upperBound` must be positive and a power of 2.
///
/// This function is superior to computing the remainder of `hashValue` by
/// the range length.  Some types have bad hash functions; sometimes simple
/// patterns in data sets create patterns in hash values and applying the
/// remainder operation just throws away even more information and invites
/// even more hash collisions.  This effect is especially bad because the
/// range is a power of two, which means to throws away high bits of the hash
/// (which would not be a problem if the hash was known to be good). This
/// function mixes the bits in the hash value to compensate for such cases.
///
/// Of course, this function is a compressing function, and applying it to a
/// hash value does not change anything fundamentally: collisions are still
/// possible, and it does not prevent malicious users from constructing data
/// sets that will exhibit pathological collisions.
fileprivate // @testable
func _squeezeHashValue(_ hashValue: Int, _ upperBound: Int) -> Int {
    _sanityCheck(_isPowerOf2(upperBound))
    let mixedHashValue = _mixInt(hashValue)
    
    // As `upperBound` is a power of two we can do a bitwise-and to calculate
    // mixedHashValue % upperBound.
    return mixedHashValue & (upperBound &- 1)
}

extension Integer {
    static func bitSize() -> Int {
        return 8 * MemoryLayout<Self>.size / MemoryLayout<UInt8>.size
    }
}

extension Int {
    func round(with alignment: Int) -> Int {
        precondition(alignment != 0)
        guard alignment > 1 else {
            return self
        }
        
        assert(alignment & 1 == 0)
        return (self + alignment - 1) & ~(alignment - 1)
    }
}

/// A wrapper around a bitmap storage with room for at least `bitCount` bits.
public // @testable
struct _UnsafeBitMap {
    public // @testable
    let values: UnsafeMutablePointer<UInt>
    
    public // @testable
    let bitCount: Int
    
    public // @testable
    static func wordIndex(_ i: Int) -> Int {
        // Note: We perform the operation on UInts to get faster unsigned math
        // (shifts).
        return Int(bitPattern: UInt(bitPattern: i) / UInt(UInt.bitSize()))
    }
    
    public // @testable
    static func bitIndex(_ i: Int) -> UInt {
        // Note: We perform the operation on UInts to get faster unsigned math
        // (shifts).
        return UInt(bitPattern: i) % UInt(UInt.bitSize())
    }
    
    public // @testable
    static func sizeInWords(forSizeInBits bitCount: Int) -> Int {
        return (bitCount + Int.bitSize() - 1) / Int.bitSize()
    }
    
    public // @testable
    init(storage: UnsafeMutablePointer<UInt>, bitCount: Int) {
        self.bitCount = bitCount
        self.values = storage
    }
    
    public // @testable
    var numberOfWords: Int {
        return _UnsafeBitMap.sizeInWords(forSizeInBits: bitCount)
    }
    
    public // @testable
    func initializeToZero() {
        values.initialize(to: 0, count: numberOfWords)
    }
    
    public // @testable
    subscript(i: Int) -> Bool {
        get {
            _sanityCheck(i < Int(bitCount) && i >= 0, "index out of bounds")
            let word = values[_UnsafeBitMap.wordIndex(i)]
            let bit = word & (1 << _UnsafeBitMap.bitIndex(i))
            return bit != 0
        }
        nonmutating set {
            _sanityCheck(i < Int(bitCount) && i >= 0, "index out of bounds")
            let wordIdx = _UnsafeBitMap.wordIndex(i)
            let bitMask = 1 << _UnsafeBitMap.bitIndex(i)
            if newValue {
                values[wordIdx] = values[wordIdx] | bitMask
            } else {
                values[wordIdx] = values[wordIdx] & ~bitMask
            }
        }
    }
}

internal struct _OrderedSetKey {
    var offset: Int
}

fileprivate struct _OrderedSetHeader<Element : Hashable> {
    fileprivate let bitmapCapacity: Int
    fileprivate let hashesAreaCapacity: Int
    fileprivate let contiguousBufferCapacity: Int
    fileprivate var count: Int = 0
    
    fileprivate init(bitmapCapacity: Int, hashesAreaCapacity: Int, contiguousBufferCapacity: Int) {
        self.bitmapCapacity = bitmapCapacity
        self.hashesAreaCapacity = hashesAreaCapacity
        self.contiguousBufferCapacity = contiguousBufferCapacity
    }
    
    fileprivate var capacity: Int {
        return (contiguousBufferCapacity * MemoryLayout<UInt>.stride) / MemoryLayout<Element>.stride
    }
    
    fileprivate func bitmap(in storage: UnsafeMutablePointer<UInt>) -> _UnsafeBitMap {
        return _UnsafeBitMap(storage: storage, bitCount: bitmapCapacity * type(of: bitmapCapacity).bitSize())
    }
    
    fileprivate func hashesArea(in storage: UnsafeMutablePointer<UInt>) -> UnsafeMutablePointer<_OrderedSetKey> {
        return storage.advanced(by: bitmapCapacity).withMemoryRebound(to: _OrderedSetKey.self, capacity: hashesAreaCapacity / MemoryLayout<_OrderedSetKey>.stride, { $0 })
    }
    
    fileprivate func contiguousBuffer(in storage: UnsafeMutablePointer<UInt>) -> UnsafeMutablePointer<Element> {
        return storage.advanced(by: hashesAreaCapacity + bitmapCapacity).withMemoryRebound(to: Element.self, capacity: capacity, { $0 })
    }
    
    internal var _bucketMask: Int {
        // The capacity is not negative, therefore subtracting 1 will not overflow.
        return capacity &- 1
    }
    
    @inline(__always) // For performance reasons.
    fileprivate func _bucket(_ k: Element) -> Int {
        return _squeezeHashValue(k.hashValue, capacity)
    }
    
    fileprivate func _index(after bucket: Int) -> Int {
        // Bucket is within 0 and capacity. Therefore adding 1 does not overflow.
        return (bucket &+ 1) & _bucketMask
    }
    
    fileprivate func _prev(_ bucket: Int) -> Int {
        // Bucket is not negative. Therefore subtracting 1 does not overflow.
        return (bucket &- 1) & _bucketMask
    }
    
    /// Search for a given key starting from the specified bucket.
    ///
    /// If the key is not present, returns the position where it could be
    /// inserted.
    @inline(__always)
    fileprivate func _find(_ element: Element, startBucket: Int, in storage: UnsafeMutablePointer<UInt>) -> (pos: Int, found: Bool) {
        let bitmap = self.bitmap(in: storage)
        let hptr = hashesArea(in: storage)
        let eptr = contiguousBuffer(in: storage)
        
        var bucket = startBucket
        
        // The invariant guarantees there's always a hole, so we just loop
        // until we find one
        while true {
            let isHole = !bitmap[bucket]
            if isHole {
                return (bucket, false)
            }
            if eptr[hptr[bucket].offset] == element {
                return (bucket, true)
            }
            bucket = _index(after: bucket)
        }
    }
}

internal class _OrderedSetBuffer<Element: Hashable>: ManagedBuffer<_OrderedSetHeader<Element>, UInt> {
    fileprivate var count: Int {
        return self.header.count
    }
    
    static func create(minimumCapacity: Int = 32) -> _OrderedSetBuffer<Element> {
        let minimumCapacity = _roundUpToPowerOf2(minimumCapacity)
        let bitmapCapacity = ((minimumCapacity + UInt.bitSize() - 1) / UInt.bitSize()).round(with: MemoryLayout<_OrderedSetKey>.alignment)
        let hashesAreaCapacity = ((MemoryLayout<_OrderedSetKey>.stride * minimumCapacity + MemoryLayout<UInt>.stride - 1) / MemoryLayout<UInt>.stride).round(with: MemoryLayout<Element>.alignment)
        let contiguousBufferCapacity = (MemoryLayout<Element>.stride * minimumCapacity + MemoryLayout<UInt>.stride - 1) / MemoryLayout<UInt>.stride
        
        let fullCapacity = bitmapCapacity + hashesAreaCapacity + contiguousBufferCapacity
        let buffer = create(minimumCapacity: fullCapacity) { (buffer) -> _OrderedSetHeader<Element> in
            return _OrderedSetHeader(bitmapCapacity: bitmapCapacity, hashesAreaCapacity: hashesAreaCapacity, contiguousBufferCapacity: contiguousBufferCapacity)
        }
        buffer.withUnsafeMutablePointers { hptr, eptr in
            let bitmap = hptr.pointee.bitmap(in: eptr)
            bitmap.initializeToZero()
        }
        return unsafeDowncast(buffer, to: self)
    }
    
    deinit {
        withUnsafeMutablePointers { hptr, eptr in
            /// bitmap and hashes are POD types, hence trivially destructible
            hptr.pointee.contiguousBuffer(in: eptr).deinitialize(count: count)
            hptr.deinitialize()
        }
    }
    
    fileprivate func at(index: Int) -> Element {
        assert((0..<count).contains(index))
        
        return withUnsafeMutablePointers { hptr, eptr in
            let eptr = hptr.pointee.contiguousBuffer(in: eptr)
            return eptr[index]
        }
    }
    
    fileprivate func find(_ element: Element) -> Int? {
        return withUnsafeMutablePointers{ hptr, buffer in
            let hashes = hptr.pointee.hashesArea(in: buffer)
            let (bucket, found) = hptr.pointee._find(element, startBucket: hptr.pointee._bucket(element), in: buffer)
            return found ? hashes[bucket].offset : nil
        }
    }
    
    fileprivate func add(element: Element) -> Int {
        return withUnsafeMutablePointers { hptr, buffer in
            let bitmap = hptr.pointee.bitmap(in: buffer)
            let hashes = hptr.pointee.hashesArea(in: buffer)
            let eptr = hptr.pointee.contiguousBuffer(in: buffer)
            
            let (bucket, found) = hptr.pointee._find(element, startBucket: hptr.pointee._bucket(element), in: buffer)
            
            if !found {
                let idx = hptr.pointee.count
                hptr.pointee.count = idx + 1
                eptr.advanced(by: idx).initialize(to: element)
                hashes.advanced(by: bucket).initialize(to: _OrderedSetKey(offset: idx))
                bitmap[bucket] = true
                return idx
            }
            else {
                let off = hashes[bucket].offset
                assert(off < count)
                
                eptr.advanced(by: off).moveAssign(from: eptr.advanced(by: off + 1), count: hptr.pointee.count - off - 1)
                eptr.advanced(by: hptr.pointee.count - 1).initialize(to: element)
                
                hashes[bucket].offset = hptr.pointee.count - 1
                return hptr.pointee.count - 1
            }
        }
    }
    
    fileprivate func remove(element: Element) -> Int? {
        return withUnsafeMutablePointers { hptr, buffer in
            let bitmap = hptr.pointee.bitmap(in: buffer)
            let hashes = hptr.pointee.hashesArea(in: buffer)
            let eptr = hptr.pointee.contiguousBuffer(in: buffer)
            
            var idealBucket = hptr.pointee._bucket(element)
            var (bucket, found) = hptr.pointee._find(element, startBucket: idealBucket, in: buffer)
            
            // Fast path: if the key is not present, we will not mutate the set,
            // so don't force unique buffer.
            if !found {
                return nil
            }
            
            let off = hashes[bucket].offset
            assert(off < count)
            eptr.advanced(by: off).moveAssign(from: eptr.advanced(by: off + 1), count: hptr.pointee.count - off - 1)
            hptr.pointee.count -= 1
            
            // If we've put a hole in a chain of contiguous elements, some
            // element after the hole may belong where the new hole is.
            var hole = bucket
            
            // Find the first bucket in the contiguous chain
            var start = idealBucket
            while bitmap[hptr.pointee._prev(start)] {
                start = hptr.pointee._prev(start)
            }
            
            // Find the last bucket in the contiguous chain
            var lastInChain = hole
            var b = hptr.pointee._index(after: lastInChain)
            while bitmap[b] {
                lastInChain = b
                b = hptr.pointee._index(after: b)
            }
            
            while hole != lastInChain {
                // Walk backwards from the end of the chain looking for
                // something out-of-place.
                var b = lastInChain
                while b != hole {
                    let idealBucket = hptr.pointee._bucket(eptr[hashes[b].offset])
                    
                    // Does this element belong between start and hole?  We need
                    // two separate tests depending on whether [start, hole] wraps
                    // around the end of the storage
                    let c0 = idealBucket >= start
                    let c1 = idealBucket <= hole
                    if start <= hole ? (c0 && c1) : (c0 || c1) {
                        break // Found it
                    }
                    b = hptr.pointee._prev(b)
                }
                
                if b == hole { // No out-of-place elements found; we're done adjusting
                    break
                }
                
                // Move the found element into the hole
                
//                nativeBuffer.moveInitializeEntry(
//                    from: nativeBuffer,
//                    at: b,
//                    toEntryAt: hole)
                hole = b
            }

            
            return bucket
        }
    }
    
    fileprivate func copyContents(_ other: _OrderedSetBuffer<Element>) {
        assert(capacity >= other.capacity)
        assert(count == 0)
        
        withUnsafeMutablePointers { hptr, buffer in
            let bitmap = hptr.pointee.bitmap(in: buffer)
            let hashes = hptr.pointee.hashesArea(in: buffer)
            let eptr = hptr.pointee.contiguousBuffer(in: buffer)

            for i in 0..<other.count {
                let el = other.at(index: i)
                let (bucket, found) = hptr.pointee._find(el, startBucket: hptr.pointee._bucket(el), in: buffer)
                
                precondition(!found, "duplicate values while copying content")
                
                eptr.advanced(by: i).initialize(to: el)
                hashes.advanced(by: bucket).initialize(to: _OrderedSetKey(offset: i))
                bitmap[bucket] = true
            }
            hptr.pointee.count = other.count
        }
    }
}

struct OrderedSet<Element : Hashable> {
    private var _buffer : _OrderedSetBuffer<Element>
    
    public init() {
        self._buffer = _OrderedSetBuffer.create()
    }
    
    public init(minimumCapacity: Int) {
        self._buffer = _OrderedSetBuffer.create(minimumCapacity: minimumCapacity)
    }
    
    /// The number of elements in the set.
    public var count: Int {
        return self._buffer.count
    }
    
    public var capacity: Int {
        return _buffer.header.capacity
    }
    
    public var startIndex: Int {
        return 0
    }
    
    public var endIndex: Int {
        return count
    }
    
    private mutating func requestUniqueMutableBackingBuffer(minimumCapacity: Int) -> _OrderedSetBuffer<Element>? {
        if _fastPath(isKnownUniquelyReferenced(&self._buffer) && capacity >= minimumCapacity) {
            return self._buffer
        }
        return nil
    }
    
    public mutating func reserveCapacity(_ minimumCapacity: Int){
        if requestUniqueMutableBackingBuffer(minimumCapacity: minimumCapacity) == nil {
            let newBuffer = _OrderedSetBuffer<Element>.create(minimumCapacity: minimumCapacity)
            newBuffer.copyContents(self._buffer)
            self._buffer = newBuffer
        }
        
        assert(capacity >= minimumCapacity)
    }
    
    public func contains(_ element: Element) -> Bool {
        return index(of: element) != nil
    }
    
    public func index(of element: Element) -> Int? {
        guard count > 0 else {
            return nil
        }
        
        return self._buffer.find(element)
    }
    
    @discardableResult
    public mutating func add(_ element: Element) -> Int {
        reserveCapacity(count + 1)
        return self._buffer.add(element: element)
    }
}


/// Examples:
/// 1. simple create
do {
    let set = OrderedSet<String>()
    assert(set.count == 0)
    assert(set.capacity >= 0)
}

/// 2. create with capacity
do {
    let set = OrderedSet<String>(minimumCapacity: 128)
    assert(set.count == 0)
    assert(set.capacity >= 128)
}

/// 3. reserveCapacity on empty set
do {
    var set = OrderedSet<String>()
    assert(set.count == 0)
    assert(set.capacity >= 0)
    
    set.reserveCapacity(128)
    assert(set.count == 0)
    assert(set.capacity >= 128)
}

/// 4. check contains
do {
    let set = OrderedSet<String>()
    assert(!set.contains("abc"))
}

/// 5. add and contains
do {
    var set = OrderedSet<String>()
    assert(!set.contains("abc"))
    let idx = set.add("abc")
    assert(set.contains("abc"))
    assert(!set.contains("bcd"))
    
    assert(idx == set.index(of: "abc"))
}

/// 6. add (replace) existing value
do {
    var set = OrderedSet<String>()
    assert(!set.contains("abc"))
    let idx1 = set.add("abc")
    set.add("bcd")
    assert(set.contains("abc"))
    let idx2 = set.add("abc")
    assert(set.contains("abc"))
    assert(idx1 < idx2)
}

