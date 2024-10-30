import BigNum
import Crypto

/// Contains common code used by both client and server SRP code
public struct SRP<H: HashFunction> {

    /// calculate u = H(clientPublicKey | serverPublicKey)
    static func calculateU(clientPublicKey: [UInt8], serverPublicKey: [UInt8]) -> BigNum {
        BigNum(bytes: [UInt8].init(H.hash(data: clientPublicKey + serverPublicKey)))
    }
    
    /// Calculate client verification code H(H(N)^ H(g)) | H(username) | salt | A | B | H(S))
    static func calculateClientProof(
        configuration: SRPConfiguration<H>,
        username: String,
        salt: [UInt8],
        clientPublicKey: SRPKey,
        serverPublicKey: SRPKey,
        hashSharedSecret: [UInt8]
    ) -> [UInt8] {
        // M = H(H(N)^ H(g)) | H(username) | salt | client key | server key | H(shared secret))
        let N_xor_g = [UInt8](H.hash(data: configuration.N.bytes)) ^ [UInt8](H.hash(data: configuration.g.bytes))
        let hashUser = H.hash(data: [UInt8](username.utf8))
        let M1 = [UInt8](N_xor_g) + hashUser + salt
        let M2 = clientPublicKey.bytes + serverPublicKey.bytes + hashSharedSecret
        let M = H.hash(data: M1 + M2)
        return [UInt8](M)
    }

    /// Calculate server verification code H(A | M1 | K)
    static func calculateServerVerification(clientPublicKey: SRPKey, clientProof: [UInt8], hashSharedSecret: [UInt8]) -> [UInt8] {
        let HAMK = H.hash(data: clientPublicKey.bytes + clientProof + hashSharedSecret)
        return [UInt8](HAMK)
    }
}
