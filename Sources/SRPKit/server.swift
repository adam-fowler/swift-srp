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
    ///Errors thrown by SRPServer
    enum Error: Swift.Error {
        /// the modulus of the client key and N generated a zero
        case nullClientKey
        /// the server key passed in was invalid
        case invalidServerKey
        /// client verification code was invalid or wrong
        case invalidClientCode
        /// password verifier code was invalid
        case invalidPasswordVerifier
    }
    
    /// Authentication state. Stores A,B and shared secret
    public struct AuthenticationState {
        let clientPublicKey: SRPKey
        let serverPublicKey: SRPKey
        var serverPrivateKey: SRPKey
    }
    
    /// configuration has to be the same as the client configuration
    public let configuration: SRPConfiguration<H>
    
    /// Initialise SRPServer
    /// - Parameter configuration: configuration to use
    public init(configuration: SRPConfiguration<H>) {
        self.configuration = configuration
    }
    
    /// initiate authentication with A value sent from client and password verifier stored with username
    /// - Parameters:
    ///   - A: A calculated by client
    ///   - verifier: Password verifier, stored with user instead of password
    /// - Throws: nullClientKey
    /// - Returns: The authentication state. The B value of the state should be returned to the client, the state should be stored for when the client responds
    public func initiateAuthentication(clientPublicKey: SRPKey, verifier: SRPKey) throws -> AuthenticationState {
        guard let verifierNumber = verifier.number else { throw Error.invalidClientCode }
        guard let clientPublicKeyNumber = clientPublicKey.number else { throw Error.invalidClientCode }
        guard clientPublicKeyNumber % configuration.N != BigNum(0) else { throw Error.nullClientKey }

        let (privateKey,publicKey) = generateKeys(v: verifierNumber)
        
        return AuthenticationState(clientPublicKey: clientPublicKey, serverPublicKey: SRPKey(publicKey), serverPrivateKey: SRPKey(privateKey))
    }
    
    /// verify code sent by client and return a server verification code. If verification fails a `invalidClientCode` error is thrown
    ///
    /// - Parameters:
    ///   - code: verification code sent by user
    ///   - username: username
    ///   - salt: salt stored with user
    ///   - state: authentication state.
    /// - Throws: invalidClientCode
    /// - Returns: The server verification code
    public func verifyClientCode(_ code: [UInt8], username: String, salt: [UInt8], verifier: SRPKey, state: AuthenticationState) throws -> [UInt8] {
        guard let verifierNumber = verifier.number else { throw Error.invalidClientCode }
        // calculate shared secret
        let sharedSecret = try getSharedSecret(
            clientPublicKey: state.clientPublicKey,
            serverPublicKey: state.serverPublicKey,
            serverPrivateKey: state.serverPrivateKey,
            verifier: verifierNumber
        )
        
        let hashSharedSecret = [UInt8](H.hash(data: sharedSecret.bytes))
        
        let clientCode = SRP<H>.calculateClientVerification(
            configuration: configuration,
            username: username,
            salt: salt,
            clientPublicKey: state.clientPublicKey,
            serverPublicKey: state.serverPublicKey,
            hashSharedSecret: hashSharedSecret
        )
        guard clientCode == code else { throw Error.invalidClientCode }
        return SRP<H>.calculateServerVerification(clientPublicKey: state.clientPublicKey, clientVerifyCode: clientCode, sharedSecret: hashSharedSecret)
    }
}

extension SRPServer {
    /// generate keys
    func generateKeys(v: BigNum) -> (privateKey: BigNum, publicKey: BigNum) {
        var privateKey = BigNum()
        var publicKey = BigNum()
        repeat {
            privateKey = BigNum(bytes: SymmetricKey(size: .bits256))
            publicKey = (configuration.k * v + configuration.g.power(privateKey, modulus: configuration.N)) % configuration.N
        } while publicKey % configuration.N == BigNum(0)
        
        return (privateKey:privateKey, publicKey:publicKey)
    }
    
    /// get shared secret
    func getSharedSecret(clientPublicKey: SRPKey, serverPublicKey: SRPKey, serverPrivateKey: SRPKey, verifier: BigNum) throws -> BigNum {
        guard let serverPrivateKeyNumber = serverPrivateKey.number else { throw Error.invalidServerKey }
        guard let clientPublicKeyNumber = clientPublicKey.number else { throw Error.invalidClientCode }

        // calculate u = H(clientPublicKey | serverPublicKey)
        let u = SRP<H>.calculateU(clientPublicKey: clientPublicKey.bytes, serverPublicKey: serverPublicKey.bytes, pad: configuration.sizeN)

        // calculate S
        let S = ((clientPublicKeyNumber * verifier.power(u, modulus: configuration.N)).power(serverPrivateKeyNumber, modulus: configuration.N))
        
        return S
    }
}
