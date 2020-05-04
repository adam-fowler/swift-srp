import XCTest
import BigNum
import Crypto
@testable import SRPKit

final class srpTests: XCTestCase {

    func testSRPSharedSecret() {
        let username = "adamfowler"
        let password = "testpassword"
        let configuration = SRPConfiguration<SHA256>(.N2048)
        let client = SRPClient<SHA256>(configuration: configuration)
        let server = SRPServer<SHA256>(configuration: configuration)
        
        let values = client.generateSaltAndVerifier(username: username, password: password)
        
        let clientState = client.initiateAuthentication()
        
        do {
            let serverValues = try server.initiateAuthentication(clientPublicKey: clientState.publicKey, verifier: values.verifier)

            let sharedSecret = try client.getSharedSecret(username: username, password: password, state: clientState, serverPublicKey: serverValues.serverPublicKey.number!, salt: values.salt)

            XCTAssertEqual(sharedSecret, serverValues.sharedSecret)
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testVerifySRP() {
        let username = "adamfowler"
        let password = "testpassword"
        let configuration = SRPConfiguration<SHA256>(.N2048)
        let client = SRPClient<SHA256>(configuration: configuration)
        let server = SRPServer<SHA256>(configuration: configuration)
        
        let values = client.generateSaltAndVerifier(username: username, password: password)
        
        do {
            // client initiates authentication
            var clientState = client.initiateAuthentication()
            // provides the server with an A value and username from which it gets the password verifier.
            // server initiates authentication
            let serverState = try server.initiateAuthentication(clientPublicKey: clientState.publicKey, verifier: values.verifier)
            // server passes back B value and a salt which was attached to the user
            // client calculates verification code from username, password, current authenticator state, B and salt
            let clientCode = try client.calculateClientVerificationCode(username: username, password: password, state: &clientState, serverPublicKey: serverState.serverPublicKey, salt: values.salt)
            // client passes verification key to server
            // server validates the key and then returns a server validation key
            let serverCode = try server.verifyClientCode(clientCode, username: username, salt: values.salt, state: serverState)
            // client verifies server validation key
            try client.verifyServerCode(serverCode, state: clientState)
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testIsSafePrime( _ number: BigNum) {
        XCTAssertTrue(number.isPrime(numChecks: 10000))
        XCTAssertTrue(((number-1)/2).isPrime(numChecks: 10000))
    }
    func testIsPrime() {
        print(512)
        testIsSafePrime(SRPConfiguration<SHA256>.Prime.N512.number)
        print(1024)
        testIsSafePrime(SRPConfiguration<SHA256>.Prime.N1024.number)
        print(1536)
        testIsSafePrime(SRPConfiguration<SHA256>.Prime.N1536.number)
        print(2048)
        testIsSafePrime(SRPConfiguration<SHA256>.Prime.N2048.number)
        print(3072)
        testIsSafePrime(SRPConfiguration<SHA256>.Prime.N3072.number)
        print(4096)
        testIsSafePrime(SRPConfiguration<SHA256>.Prime.N4096.number)
    }
    
    static var allTests = [
        ("testSRPSharedSecret", testSRPSharedSecret),
        ("testVerifySRP", testVerifySRP),
    ]
}
