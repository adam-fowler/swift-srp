import XCTest
import BigNum
import Crypto
@testable import SRPKit

final class srpTests: XCTestCase {

    func testSRPSharedSecret() {
        let username = "adamfowler"
        let password = "testpassword"
        let configuration = SRPConfiguration<Insecure.SHA1>(.N2048)
        let client = SRPClient<Insecure.SHA1>(configuration: configuration)
        let server = SRPServer<Insecure.SHA1>(configuration: configuration)
        
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
        let configuration = SRPConfiguration<SHA256>(.N1024)
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
    
/*    func testRFC5054() {
        let I = "alice"
        let password = "password123"
        let salt = "BEB25379D1A8581EB5A727673A2441EE"
        let configuration = SRPConfiguration<Insecure.SHA1>(.N1024)
        print(configuration.N.hex)
        print(configuration.g.hex)
        XCTAssertEqual(configuration.k.hex, "7556AA045AEF2CDD07ABAF0F665C3E818913186F")
    }*/
    
    static var allTests = [
        ("testSRPSharedSecret", testSRPSharedSecret),
        ("testVerifySRP", testVerifySRP),
    ]
}
