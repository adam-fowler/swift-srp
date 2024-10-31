import BigNum
import Crypto
import Foundation

/// Manages the client side of Secure Remote Password
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
public struct SRPClient<H: HashFunction> {
    /// configuration. This needs to be the same as the server configuration
    public let configuration: SRPConfiguration<H>

    /// Initialise a SRPClient object
    /// - Parameter configuration: configuration to use
    public init(configuration: SRPConfiguration<H>) {
        self.configuration = configuration
    }

    /// Initiate the authentication process
    /// - Returns: An authentication state. The A value from this state should be sent to the server
    public func generateKeys() -> SRPKeyPair {
        var a: BigNum
        var A: BigNum
        repeat {
            a = BigNum(bytes: SymmetricKey(size: .bits256))
            A = configuration.g.power(a, modulus: configuration.N)
        } while A % configuration.N == BigNum(0)

        return SRPKeyPair(public: SRPKey(A, padding: configuration.sizeN), private: SRPKey(a))
    }

    /// return shared secret given the username, password, B value and salt from the server
    /// - Parameters:
    ///   - username: user identifier
    ///   - password: password
    ///   - salt: salt
    ///   - clientKeys: client public/private keys
    ///   - serverPublicKey: server public key
    /// - Throws: `nullServerKey`
    /// - Returns: shared secret
    public func calculateSharedSecret(
        username: String,
        password: String,
        salt: [UInt8],
        clientKeys: SRPKeyPair,
        serverPublicKey: SRPKey
    ) throws -> SRPKey {
        let message = [UInt8]("\(username):\(password)".utf8)
        return try calculateSharedSecret(message: message, salt: salt, clientKeys: clientKeys, serverPublicKey: serverPublicKey)
    }

    /// return shared secret given a binary password, B value and salt from the server
    /// - Parameters:
    ///   - password: password
    ///   - salt: salt
    ///   - clientKeys: client public/private keys
    ///   - serverPublicKey: server public key
    /// - Throws: `nullServerKey`
    /// - Returns: shared secret
    public func calculateSharedSecret(
        password: [UInt8],
        salt: [UInt8],
        clientKeys: SRPKeyPair,
        serverPublicKey: SRPKey
    ) throws -> SRPKey {
        let message = [0x3A] + password
        return try calculateSharedSecret(message: message, salt: salt, clientKeys: clientKeys, serverPublicKey: serverPublicKey)
    }

    /// Calculate proof of shared secret to send to server.
    ///
    /// This uses the method detailed in https://tools.ietf.org/html/rfc2945#section-3
    ///
    /// - Parameters:
    ///   - username: Username
    ///   - salt: The salt value associated with the user returned by the server
    ///   - clientPublicKey: Client public key
    ///   - serverPublicKey: server public key
    ///   - sharedSecret: shared secret
    /// - Returns: The client verification code which should be passed to the server
    public func calculateClientProof(
        username: String,
        salt: [UInt8],
        clientPublicKey: SRPKey,
        serverPublicKey: SRPKey,
        sharedSecret: SRPKey
    ) -> [UInt8] {
        let clientPublicKey = clientPublicKey.with(padding: configuration.sizeN)
        let serverPublicKey = serverPublicKey.with(padding: configuration.sizeN)
        let hashSharedSecret = [UInt8](H.hash(data: sharedSecret.bytes))
        // get verification code
        return SRP<H>.calculateClientProof(
            configuration: configuration,
            username: username,
            salt: salt,
            clientPublicKey: clientPublicKey,
            serverPublicKey: serverPublicKey,
            hashSharedSecret: hashSharedSecret
        )
    }

    /// If the server returns that the client verification code was valid it will also return a server
    /// verification code that the client can use to verify the server is correct. This is the calculation
    /// to verify it is correct
    ///
    /// - Parameters:
    ///   - clientPublicKey: Client public key
    ///   - clientProof: Client proof
    ///   - sharedSecret: Shared secret
    public func calculateServerProof(
        clientPublicKey: SRPKey,
        clientProof: [UInt8],
        sharedSecret: SRPKey
    ) -> [UInt8] {
        let clientPublicKey = clientPublicKey.with(padding: configuration.sizeN)
        let sharedSecret = sharedSecret.with(padding: configuration.sizeN)
        let hashSharedSecret = [UInt8](H.hash(data: sharedSecret.bytes))
        // get out version of server proof
        return SRP<H>.calculateServerVerification(
            clientPublicKey: clientPublicKey,
            clientProof: clientProof,
            hashSharedSecret: hashSharedSecret
        )
    }

    /// If the server returns that the client verification code was valid it will also return a server
    /// verification code that the client can use to verify the server is correct
    ///
    /// This uses the method detailed in https://tools.ietf.org/html/rfc2945#section-3
    ///
    /// - Parameters:
    ///   - serverProof: Server proof
    ///   - clientProof: Client proof
    ///   - clientPublicKey: Client public key
    ///   - sharedSecret: Shared secret
    /// - Throws: `requiresVerificationKey`, `invalidServerCode`
    public func verifyServerProof(
        serverProof: [UInt8],
        clientProof: [UInt8],
        clientPublicKey: SRPKey,
        sharedSecret: SRPKey
    ) throws {
        // get our version of server proof
        let HAMK = calculateServerProof(clientPublicKey: clientPublicKey, clientProof: clientProof, sharedSecret: sharedSecret)
        // is it the same
        guard serverProof == HAMK else { throw SRPClientError.invalidServerCode }
    }

    /// Generate salt and password verifier from username and password. When creating your user instead of
    /// passing your password to the server, you pass the salt and password verifier values. In this way the
    /// server never knows your password so can never leak it.
    ///
    /// - Parameters:
    ///   - username: username
    ///   - password: user password
    /// - Returns: tuple containing salt and password verifier
    public func generateSaltAndVerifier(username: String, password: String) -> (salt: [UInt8], verifier: SRPKey) {
        let salt = [UInt8].random(count: 16)
        let verifier = generatePasswordVerifier(username: username, password: password, salt: salt)
        return (salt: salt, verifier: SRPKey(verifier, padding: configuration.sizeN))
    }

    ///  Hash data using same hash function that SRP uses
    /// - Parameter data: Data to be hashed
    /// - Returns: Hashed data
    @inlinable public func hash<D>(data: D) -> H.Digest where D: DataProtocol {
        H.hash(data: data)
    }
}

public extension SRPClient {
    /// return shared secret given the message (username:password), salt from server, client keys, and B value
    internal func calculateSharedSecret(
        message: [UInt8],
        salt: [UInt8],
        clientKeys: SRPKeyPair,
        serverPublicKey: SRPKey
    ) throws -> SRPKey {
        guard serverPublicKey.number % configuration.N != BigNum(0) else { throw SRPClientError.nullServerKey }

        // calculate u = H(clientPublicKey | serverPublicKey)
        let u = SRP<H>.calculateU(clientPublicKey: clientKeys.public.bytes, serverPublicKey: serverPublicKey.bytes)

        guard u != 0 else { throw SRPClientError.nullServerKey }

        let x = BigNum(bytes: [UInt8](H.hash(data: salt + H.hash(data: message))))

        // calculate S = (B - k*g^x)^(a+u*x)
        let S = (serverPublicKey.number - configuration.k * configuration.g.power(x, modulus: configuration.N)).power(clientKeys.private.number + u * x, modulus: configuration.N)

        return SRPKey(S, padding: configuration.sizeN)
    }

    /// generate password verifier
    func generatePasswordVerifier(username: String, password: String, salt: [UInt8]) -> BigNum {
        let message = "\(username):\(password)"
        return generatePasswordVerifier(message: [UInt8](message.utf8), salt: salt)
    }

    /// generate password verifier
    func generatePasswordVerifier(message: [UInt8], salt: [UInt8]) -> BigNum {
        let x = BigNum(bytes: [UInt8](H.hash(data: salt + H.hash(data: message))))
        let verifier = configuration.g.power(x, modulus: configuration.N)
        return verifier
    }
}
