import BigNum

/// Wrapper for keys used by SRP
public struct SRPKey {
    /// SRPKey internal storage
    public let number: BigNum
    /// Representation as a byte array
    public var bytes: [UInt8] { number.bytes }
    /// Representation as a hex string
    public var hex: String { number.hex }
    /// Representation as a byte array with padding
    public func bytes(padding: Int) -> [UInt8] { number.bytes.pad(to: padding) }
    /// Representation as a hex string with padding
    public func hex(padding: Int) -> String { number.bytes.pad(to: padding).hexdigest() }

    /// Initialize with an array of bytes
    public init(_ bytes: [UInt8]) {
        self.number = BigNum(bytes: bytes)
    }
    
    /// Initialize with a BigNum
    public init(_ number: BigNum) {
        self.number = number
    }
    
    /// Initialize with a hex string
    public init?(hex: String) {
        guard let number = BigNum(hex: hex) else { return nil }
        self.number = number
    }
}

extension SRPKey: Equatable { }

/// Contains a private and a public key
public struct SRPKeyPair {
    public let `public`: SRPKey
    public let `private`: SRPKey


    /// Initialise a SRPKeyPair object
    /// - Parameters:
    ///   - public: The public key of the key pair
    ///   - private: The private key of the key pair
    public init(`public`: SRPKey, `private`: SRPKey) {
        self.private = `private`
        self.public = `public`
    }
}

