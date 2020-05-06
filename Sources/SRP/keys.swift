import BigNum

/// Wrapper for keys used by SRP
public struct SRPKey {
    public var bytes: [UInt8] { number.bytes }
    public let number: BigNum
    
    public init(_ bytes: [UInt8]) {
        self.number = BigNum(bytes: bytes)
    }
    
    public init(_ number: BigNum) {
        self.number = number
    }
}

extension SRPKey: Equatable { }

/// contains a private and a public key
public struct SRPKeyPair {
    public let `public`: SRPKey
    public let `private`: SRPKey
}

