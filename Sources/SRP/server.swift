import BigNum
import Crypto
import Foundation

/// Manages the server side of Secure Remote Password.
///
/// Secure Remote Password (SRP) provides username and password authentication without needing to provide your password to the server. The server
/// has a cryptographic verifier that is derived from the password and a salt that was used to generate this verifier. Both client and server
/// generate a shared secret then the client sends a proof they have the secret and if it is correct the server will do the same to verify the
/// server as well.
///
/// This version is compliant with SRP version  6a and RFC 5054.
///
/// Reference reading
/// - https://tools.ietf.org/html/rfc2945
/// - https://tools.ietf.org/html/rfc5054
///
public struct SRPServer<H: HashFunction> {
    /// configuration has to be the same as the client configuration
    public let configuration: SRPConfiguration<H>

    /// Initialise SRPServer
    /// - Parameter configuration: configuration to use
    public init(configuration: SRPConfiguration<H>) {
        self.configuration = configuration
    }

    /// generate public and private keys to be used in srp authentication
    /// - Parameter verifier: password verifier used to generate key pair
    /// - Returns: return public/private key pair
    public func generateKeys(verifier: SRPKey) -> SRPKeyPair {
        var b: BigNum
        var B: BigNum
        repeat {
            b = BigNum(bytes: SymmetricKey(size: .bits256))
            B = (configuration.k * verifier.number + configuration.g.power(b, modulus: configuration.N)) % configuration.N
        } while B % configuration.N == BigNum(0)

        return SRPKeyPair(public: SRPKey(B, padding: configuration.sizeN), private: SRPKey(b))
    }

    /// calculate the shared secret
    /// - Parameters:
    ///   - clientPublicKey: Public key received from client
    ///   - serverKeys: Server key pair
    ///   - verifier: Password verifier
    /// - Returns: shared secret
    public func calculateSharedSecret(
        clientPublicKey: SRPKey,
        serverKeys: SRPKeyPair,
        verifier: SRPKey
    ) throws -> SRPKey {
        let clientPublicKey = clientPublicKey.with(padding: configuration.sizeN)
        guard clientPublicKey.number % configuration.N != BigNum(0) else { throw SRPServerError.nullClientKey }

        // calculate u = H(clientPublicKey | serverPublicKey)
        let u = SRP<H>.calculateU(clientPublicKey: clientPublicKey.bytes, serverPublicKey: serverKeys.public.bytes)

        // calculate S
        let S = ((clientPublicKey.number * verifier.number.power(u, modulus: configuration.N)).power(serverKeys.private.number, modulus: configuration.N))

        return SRPKey(S, padding: configuration.sizeN)
    }

    /// verify proof that client has shared secret and return a server verification proof. If verification fails a `invalidClientCode` error is thrown
    ///
    /// - Parameters:
    ///   - code: verification code sent by user
    ///   - username: Username
    ///   - salt: Salt stored with user
    ///   - clientPublicKey: Client public key
    ///   - serverPublicKey: Server public key
    ///   - sharedSecret: Shared secret
    /// - Throws: invalidClientCode
    /// - Returns: The server verification code
    public func verifyClientProof(
        proof: [UInt8],
        username: String,
        salt: [UInt8],
        clientPublicKey: SRPKey,
        serverPublicKey: SRPKey,
        sharedSecret: SRPKey
    ) throws -> [UInt8] {
        let clientPublicKey = clientPublicKey.with(padding: configuration.sizeN)
        let serverPublicKey = serverPublicKey.with(padding: configuration.sizeN)
        let sharedSecret = sharedSecret.with(padding: configuration.sizeN)
        let hashSharedSecret = [UInt8](H.hash(data: sharedSecret.bytes))

        let clientProof = SRP<H>.calculateClientProof(
            configuration: configuration,
            username: username,
            salt: salt,
            clientPublicKey: clientPublicKey,
            serverPublicKey: serverPublicKey,
            hashSharedSecret: hashSharedSecret
        )
        guard constantTimeEqual(clientProof, proof) else { throw SRPServerError.invalidClientProof }
        return SRP<H>.calculateServerVerification(clientPublicKey: clientPublicKey, clientProof: clientProof, hashSharedSecret: hashSharedSecret)
    }

    ///  Hash data using same hash function that SRP uses
    /// - Parameter data: Data to be hashed
    /// - Returns: Hashed data
    @inlinable public func hash<D>(data: D) -> H.Digest where D: DataProtocol {
        H.hash(data: data)
    }
}
