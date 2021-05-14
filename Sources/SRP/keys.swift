import BigNum

/// Wrapper for keys used by SRP
public struct SRPKey {
    public let number: BigNum
    public var bytes: [UInt8] { number.bytes }
    public var hex: String { number.hex }

    public init(_ bytes: [UInt8]) {
        self.number = BigNum(bytes: bytes)
    }
    
    public init(_ number: BigNum) {
        self.number = number
    }
    
    public init?(hex: String) {
        guard let number = BigNum(hex: hex) else { return nil }
        self.number = number
    }
}

extension SRPKey: Equatable { }

/// contains a private and a public key
public struct SRPKeyPair {
    public let `public`: SRPKey
    public let `private`: SRPKey
}

