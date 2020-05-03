import BigNum
import Crypto
import Foundation

/// struct managing the client side of Secure Remote Password
public struct SRPClient<H: HashFunction> {
    /// Errors thrown by SRPClient
    enum Error: Swift.Error {
        /// the key returned by server is invalid, in that either it modulo N is zero or the hash(A,B) is zero
        case nullServerKey
        /// server verification code was wrong
        case invalidServerCode
        /// you called verifyServerCode without a verification key
        case requiresVerificationKey
    }
    
    /// Authentication state, keeps a record of the variables needed throughout the process
    public struct AuthenticationState {
        let privateKey: BigNum
        let publicKey: BigNum
        var sharedSecret: [UInt8]? = nil
        var verifyCode: [UInt8]? = nil
    }
    
    /// configuration. This needs to be the same as the server configuration
    let configuration: SRPConfiguration<H>
    
    /// Initialise a SRPClient object
    /// - Parameter configuration: configuration to use
    public init(configuration: SRPConfiguration<H>) {
        self.configuration = configuration
    }
    
    /// Initiate the authentication process
    /// - Returns: An authentication state. The A value from this state should be sent to the server
    public func initiateAuthentication() -> AuthenticationState {
        var a = BigNum()
        var A = BigNum()
        repeat {
            a = BigNum(data: SRP<H>.HKDF(seed: Data([UInt8].random(count: 128)), info: configuration.infoKey, salt: Data(), count: 128))
            A = configuration.g.power(a, modulus: configuration.N)
        } while A % configuration.N == BigNum(0)

        return AuthenticationState(privateKey:a, publicKey:A)
    }
    
    /// calculate verification code to send to server once it has responded with the B value and the salt associated with the user
    /// - Parameters:
    ///   - username: username
    ///   - password: users password
    ///   - state: the authentication state
    ///   - B: The B value returned by the server
    ///   - salt: The salt value associated with the user returned by the server
    /// - Throws: `nullServerKey`
    /// - Returns: The client verification code which should be passed to the server
    public func calculateClientVerificationCode(username: String, password: String, state: inout AuthenticationState, serverPublicKey: BigNum, salt: [UInt8]) throws -> [UInt8] {
        let sharedSecret = try getSharedSecret(username: username, password: password, state: state, serverPublicKey: serverPublicKey, salt: salt)
        state.sharedSecret = sharedSecret
        let verificationCode = SRP<H>.calculateClientVerification(configuration: configuration, username: username, salt: salt, clientPublicKey: state.publicKey, serverPublicKey: serverPublicKey, sharedSecret: sharedSecret)
        state.verifyCode = verificationCode
        return verificationCode
    }
    
    /// If the server returns that the client verification code was valiid it will also return a server verification code that the client can use to verify the server is correct
    ///
    /// - Parameters:
    ///   - code: Verification code returned by server
    ///   - state: Authentication state
    /// - Throws: `requiresVerificationKey`, `invalidServerCode`
    public func verifyServerCode(_ serverVerifyCode: [UInt8], state: AuthenticationState) throws {
        guard let clientVerifyCode = state.verifyCode, let sharedSecret = state.sharedSecret else { throw Error.requiresVerificationKey }
        let HAMK = SRP<H>.calculateServerVerification(clientPublicKey: state.publicKey, clientVerifyCode: clientVerifyCode, sharedSecret: sharedSecret)
        guard serverVerifyCode == HAMK else { throw Error.invalidServerCode }
    }
    
    /// Generate salt and password verifier from username and password. When creating your user instead of passing your password to the server, you
    /// pass the salt and password verifier values. In this way the server never knows your password so can never leak it.
    ///
    /// - Parameters:
    ///   - username: username
    ///   - password: user password
    /// - Returns: tuple containing salt and password verifier
    public func generateSaltAndVerifier(username: String, password: String) -> (salt: [UInt8], verifier: BigNum) {
        let salt = [UInt8].random(count: 16)
        let message = [UInt8]("\(username):\(password)".utf8)
        let x = BigNum(data: [UInt8](H.hash(data: SRP<H>.pad(salt) + H.hash(data: message))))
        let verifier = configuration.g.power(x, modulus: configuration.N)
        return (salt: salt, verifier: verifier)
    }
}

extension SRPClient {
    /// return shared secret given the username, password, B value and salt from the server
    func getSharedSecret(username: String, password: String, state: AuthenticationState, serverPublicKey: BigNum, salt: [UInt8]) throws -> [UInt8] {

        guard serverPublicKey % configuration.N != BigNum(0) else { throw Error.nullServerKey }

        // calculate u = H(clientPublicKey | serverPublicKey)
        let u = BigNum(data: [UInt8].init(H.hash(data: SRP<H>.pad(state.publicKey.bytes) + SRP<H>.pad(serverPublicKey.bytes))))
        
        guard u != 0 else { throw Error.nullServerKey }
        
        // calculate x = H(salt | H(poolName | userId | ":" | password))
        let message = Data("\(username):\(password)".utf8)
        let x = BigNum(data: [UInt8].init(H.hash(data: SRP<H>.pad(salt) + H.hash(data: message))))
        
        // calculate S = (B - k*g^x)^(a+u*x)
        let S = (serverPublicKey - configuration.k * configuration.g.power(x, modulus: configuration.N)).power(state.privateKey + u * x, modulus: configuration.N)
        
        return [UInt8](H.hash(data: SRP<H>.pad(S.bytes)))
    }
}
