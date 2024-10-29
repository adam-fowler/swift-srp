import BigNum
import Crypto

extension Array where Element == UInt8 {
    func pad(to size: Int) -> [UInt8] {
        let padSize = size - self.count
        guard padSize > 0 else { return self }
        // create prefix and return prefix + data
        let prefix: [UInt8] = (1...padSize).reduce([]) { result,_ in return result + [0] }
        return prefix + self
    }
}

/// Contains common code used by both client and server SRP code
public struct SRP<H: HashFunction> {

    /// calculate u = H(clientPublicKey | serverPublicKey)
    public static func calculateU(clientPublicKey: [UInt8], serverPublicKey: [UInt8]) -> BigNum {
        BigNum(bytes: [UInt8].init(H.hash(data: clientPublicKey + serverPublicKey)))
    }
    
    /// Calculate a simpler client verification code H(A | B | S)
    static func calculateSimpleClientProof(
        clientPublicKey: SRPKey,
        serverPublicKey: SRPKey,
        sharedSecret: SRPKey,
        padding: Int
    ) -> [UInt8] {
        let HABK = H.hash(data: clientPublicKey.bytes(padding: padding) + serverPublicKey.bytes(padding: padding) + sharedSecret.bytes(padding: padding))
        return [UInt8](HABK)
    }
    
    /// Calculate a simpler client verification code H(A | M1 | S)
    static func calculateSimpleServerVerification(
        clientPublicKey: SRPKey,
        clientProof: [UInt8],
        sharedSecret: SRPKey,
        padding: Int
    ) -> [UInt8] {
        let HABK = H.hash(data: clientPublicKey.bytes(padding: padding) + clientProof + sharedSecret.bytes(padding: padding))
        return [UInt8](HABK)
    }

    /// Calculate client verification code H(H(N)^ H(g)) | H(username) | salt | A | B | H(S))
    static func calculateClientProof(
        configuration: SRPConfiguration<H>,
        username: String,
        salt: [UInt8],
        clientPublicKey: SRPKey,
        serverPublicKey: SRPKey,
        hashSharedSecret: [UInt8],
        padding: Int
    ) -> [UInt8] {
        // M = H(H(N)^ H(g)) | H(username) | salt | client key | server key | H(shared secret))
        let N_xor_g = [UInt8](H.hash(data: configuration.N.bytes.pad(to: padding))) ^ [UInt8](H.hash(data: configuration.g.bytes.pad(to: padding)))
        let hashUser = H.hash(data: [UInt8](username.utf8))
        let M1 = [UInt8](N_xor_g) + hashUser + salt
        let M2 = clientPublicKey.bytes(padding: padding) + serverPublicKey.bytes(padding: padding) + hashSharedSecret
        let M = H.hash(data: M1 + M2)
        return [UInt8](M)
    }

    /// Calculate server verification code H(A | M1 | K)
    static func calculateServerVerification(clientPublicKey: SRPKey, clientProof: [UInt8], sharedSecret: [UInt8], padding: Int) -> [UInt8] {
        let HAMK = H.hash(data: clientPublicKey.bytes(padding: padding) + clientProof + sharedSecret)
        return [UInt8](HAMK)
    }
}
