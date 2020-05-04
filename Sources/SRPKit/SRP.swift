import BigNum
import Crypto
import Foundation

/// Wrapper for keys used by SRP
public struct SRPKey {
    public let bytes: [UInt8]
    public var number: BigNum? { return BigNum(bytes: bytes) }
    
    public init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }
    
    public init(_ number: BigNum) {
        self.bytes = number.bytes
    }
}

/// Contains common code used by both client and server SRP code
struct SRP<H: HashFunction> {
    /// pad buffer before hashing
    static func pad(_ data: [UInt8]) -> [UInt8] {
        if data[0] > 0x7f {
            return [0] + data
        }
        return data
    }

    /// Calculate client verification code
    static func calculateClientVerification(configuration: SRPConfiguration<H>, username: String, salt: [UInt8], clientPublicKey: SRPKey, serverPublicKey: SRPKey, sharedSecret: [UInt8]) -> [UInt8] {
        // calculate shared secret proof
        let N_xor_g = [UInt8](H.hash(data: SRP<H>.pad(configuration.N.bytes))) ^ [UInt8](H.hash(data: SRP<H>.pad(configuration.g.bytes)))
        let M = H.hash(data: [UInt8](N_xor_g) + [UInt8](username.utf8) + salt + clientPublicKey.bytes + serverPublicKey.bytes + sharedSecret)
        return [UInt8](M)
    }

    /// Calculate server verification code
    static func calculateServerVerification(clientPublicKey: SRPKey, clientVerifyCode: [UInt8], sharedSecret: [UInt8]) -> [UInt8] {
        let HAMK = H.hash(data: clientPublicKey.bytes + clientVerifyCode + sharedSecret)
        return [UInt8](HAMK)
    }
}
