import BigNum
import Crypto
import Foundation

/// Struct managing the server side of Secure Remote Password.
public struct SRPServer<H: HashFunction> {
    ///Errors thrown by SRPServer
    enum Error: Swift.Error {
        /// the modulus of the client key and N generated a zero
        case nullClientKey
        /// client verification code was wrong
        case invalidClientCode
    }
    
    /// Authentication state. Stores A,B and shared secret
    public struct AuthenticationState {
        let clientPublicKey: BigNum
        let serverPublicKey: BigNum
        var sharedSecret: [UInt8]
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
    public func initiateAuthentication(clientPublicKey: BigNum, verifier: BigNum) throws -> AuthenticationState {
        guard clientPublicKey % configuration.N != BigNum(0) else { throw Error.nullClientKey }

        let (privateKey,publicKey) = generateKeys(v: verifier)
        
        // calculate u = H(clientPublicKey | serverPublicKey)
        let u = BigNum(data: [UInt8].init(H.hash(data: SRP<H>.pad(clientPublicKey.bytes) + SRP<H>.pad(publicKey.bytes))))
        
        // calculate S
        let S = (clientPublicKey * verifier.power(u, modulus: configuration.N)).power(privateKey, modulus: configuration.N)
        
        let sharedSecret = H.hash(data: SRP<H>.pad(S.bytes))
        
        return AuthenticationState(clientPublicKey: clientPublicKey, serverPublicKey: publicKey, sharedSecret: [UInt8](sharedSecret))
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
    public func verifyClientCode(_ code: [UInt8], username: String, salt: [UInt8], state: AuthenticationState) throws -> [UInt8] {
        let clientCode = SRP<H>.calculateClientVerification(configuration: configuration, username: username, salt: salt, clientPublicKey: state.clientPublicKey, serverPublicKey: state.serverPublicKey, sharedSecret: state.sharedSecret)
        guard clientCode == code else { throw Error.invalidClientCode }
        return SRP<H>.calculateServerVerification(clientPublicKey: state.clientPublicKey, clientVerifyCode: clientCode, sharedSecret: state.sharedSecret)
    }
}

extension SRPServer {
    /// generate keys
    func generateKeys(v: BigNum) -> (privateKey: BigNum, publicKey: BigNum) {
        var privateKey = BigNum()
        var publicKey = BigNum()
        repeat {
            privateKey = BigNum(data: SRP<H>.HKDF(seed: Data([UInt8].random(count: 128)), info: configuration.infoKey, salt: Data(), count: 128))
            publicKey = configuration.k * v + configuration.g.power(privateKey, modulus: configuration.N)
        } while publicKey % configuration.N == BigNum(0)
        
        return (privateKey:privateKey, publicKey:publicKey)
    }
}
