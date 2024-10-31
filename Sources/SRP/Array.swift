
extension Array where Element: FixedWidthInteger {
    /// create array of random bytes
    static func random(count: Int) -> [Element] {
        var array = self.init()
        for _ in 0 ..< count {
            array.append(.random(in: Element.min ..< Element.max))
        }
        return array
    }

    /// generate a hexdigest of the array of bytes
    func hexdigest() -> String {
        return map {
            let characters = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
            return "\(characters[Int($0 >> 4)])\(characters[Int($0 & 0xF)])"
        }.joined()
    }
}

extension Array where Element == UInt8 {
    func pad(to size: Int) -> [UInt8] {
        let padSize = size - count
        guard padSize > 0 else { return self }
        // create prefix and return prefix + data
        let prefix: [UInt8] = (1 ... padSize).reduce([]) { result, _ in result + [0] }
        return prefix + self
    }
}

/// xor together the contents of two byte arrays
func ^ (lhs: [UInt8], rhs: [UInt8]) -> [UInt8] {
    precondition(lhs.count == rhs.count, "Arrays are required to be the same size")
    var result = lhs
    for i in 0 ..< lhs.count {
        result[i] = result[i] ^ rhs[i]
    }
    return result
}
