import BigNum
import Crypto
import Foundation

/// Wrapper for keys used by SRP
public struct SRPKey {
    /// SRPKey internal storage
    public let number: BigNum
    /// padding
    public let padding: Int
    /// Representation as a byte array
    public var bytes: [UInt8] { number.bytes.pad(to: padding) }
    /// Representation as a hex string
    public var hex: String { number.bytes.pad(to: padding).hexdigest() }

    /// Initialize with an array of bytes
    @inlinable public init<C: Collection & ContiguousBytes>(_ bytes: C, padding: Int? = nil) {
        number = BigNum(bytes: bytes)
        self.padding = padding ?? bytes.count
    }

    /// Initialize with a crypto digest
    @inlinable public init<D: Digest>(_ digest: D, padding: Int? = nil) {
        number = BigNum(bytes: digest)
        self.padding = padding ?? D.byteCount
    }

    /// Initialize with a hex string
    @inlinable public init?(hex: String, padding: Int? = nil) {
        guard let number = BigNum(hex: hex) else { return nil }
        self.number = number
        self.padding = padding ?? (hex.count + 1) / 2
    }

    /// Initialize with a BigNum
    @usableFromInline init(_ number: BigNum, padding: Int = 0) {
        self.number = number
        self.padding = padding
    }

    /// Return SRPKey with padding
    func with(padding: Int) -> SRPKey {
        .init(number, padding: padding)
    }
}

extension SRPKey: Equatable {}

/// Contains a private and a public key
public struct SRPKeyPair {
    public let `public`: SRPKey
    public let `private`: SRPKey

    /// Initialise a SRPKeyPair object
    /// - Parameters:
    ///   - public: The public key of the key pair
    ///   - private: The private key of the key pair
    init(public: SRPKey, private: SRPKey) {
        self.private = `private`
        self.public = `public`
    }
}
