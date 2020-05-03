import BigNum
import Crypto
import Foundation

struct SRP<H: HashFunction> {
    /// pad buffer before hashing
    static func pad(_ data: [UInt8]) -> [UInt8] {
        if data[0] > 0x7f {
            return [0] + data
        }
        return data
    }

    /// HKDF calculation 
    static func HKDF<Seed: DataProtocol, Info: DataProtocol, Salt: ContiguousBytes>(seed: Seed, info: Info, salt: Salt, count: Int) -> [UInt8] {
        let prk = HMAC<H>.authenticationCode(for:seed, using: SymmetricKey(data: salt))
        let iterations = Int(ceil(Double(count) / Double(H.Digest.byteCount)))
        
        var t: [UInt8] = []
        var result: [UInt8] = []
        for i in 1...iterations {
            var hmac = HMAC<H>(key: SymmetricKey(data: prk))
            hmac.update(data: t)
            hmac.update(data: info)
            hmac.update(data: [UInt8(i)])
            t = [UInt8](hmac.finalize())
            result += t
        }
        return [UInt8](result[0..<count])
    }
    
    /// Calculate client verification code
    static func calculateClientVerification(configuration: SRPConfiguration<H>, username: String, salt: [UInt8], clientPublicKey: BigNum, serverPublicKey: BigNum, sharedSecret: [UInt8]) -> [UInt8] {
        // calculate shared secret proof
        let N_xor_g = [UInt8](H.hash(data: SRP<H>.pad(configuration.N.bytes))) ^ [UInt8](H.hash(data: SRP<H>.pad(configuration.g.bytes)))
        let M = H.hash(data: [UInt8](N_xor_g) + [UInt8](username.utf8) + salt + clientPublicKey.bytes + serverPublicKey.bytes + sharedSecret)
        return [UInt8](M)
    }

    /// Calculate server verification code
    static func calculateServerVerification(clientPublicKey: BigNum, clientVerifyCode: [UInt8], sharedSecret: [UInt8]) -> [UInt8] {
        let HAMK = H.hash(data: clientPublicKey.bytes + clientVerifyCode + sharedSecret)
        return [UInt8](HAMK)
    }
}
