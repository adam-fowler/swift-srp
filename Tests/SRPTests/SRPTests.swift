import XCTest
import BigNum
import Crypto
@testable import SRPKit

final class SRPTests: XCTestCase {

    func testSRPSharedSecret() {
        let username = "adamfowler"
        let password = "testpassword"
        let configuration = SRPConfiguration<Insecure.SHA1>(.N2048)
        let client = SRPClient<Insecure.SHA1>(configuration: configuration)
        let server = SRPServer<Insecure.SHA1>(configuration: configuration)

        let (salt, verifier) = client.generateSaltAndVerifier(username: username, password: password)

        let clientState = client.initiateAuthentication()

        do {
            let serverValues = server.generateKeys(v: verifier.number!)
            let sharedSecret = try client.getSharedSecret(
                username: username,
                password: password,
                clientPublicKey: clientState.publicKey,
                clientPrivateKey: clientState.privateKey,
                serverPublicKey: serverValues.publicKey,
                salt: salt)

            let serverSharedSecret = try server.getSharedSecret(
                clientPublicKey: clientState.publicKey,
                serverPublicKey: SRPKey(serverValues.publicKey),
                serverPrivateKey: SRPKey(serverValues.privateKey),
                verifier: verifier.number!)

            XCTAssertEqual(sharedSecret, serverSharedSecret)
        } catch {
            XCTFail("\(error)")
        }
    }

    func testVerifySRP<H: HashFunction>(configuration: SRPConfiguration<H>) {
        let username = "adamfowler"
        let password = "testpassword"
        let client = SRPClient<H>(configuration: configuration)
        let server = SRPServer<H>(configuration: configuration)

        let (salt, verifier) = client.generateSaltAndVerifier(username: username, password: password)

        do {
            // client initiates authentication
            var clientState = client.initiateAuthentication()
            // provides the server with an A value and username from which it gets the password verifier.
            // server initiates authentication
            let serverState = try server.initiateAuthentication(clientPublicKey: clientState.publicKey, verifier: verifier)
            // server passes back B value and a salt which was attached to the user
            // client calculates verification code from username, password, current authenticator state, B and salt
            let clientCode = try client.calculateClientVerificationCode(username: username, password: password, state: &clientState, serverPublicKey: serverState.serverPublicKey, salt: salt)
            // client passes verification key to server
            // server validates the key and then returns a server validation key
            let serverCode = try server.verifyClientCode(clientCode, username: username, salt: salt, verifier: verifier, state: serverState)
            // client verifies server validation key
            try client.verifyServerCode(serverCode, state: clientState)
        } catch {
            XCTFail("\(error)")
        }
    }

    func testVerifySRP() {
        testVerifySRP(configuration: SRPConfiguration<SHA256>(.N1024))
        testVerifySRP(configuration: SRPConfiguration<SHA256>(.N1536))
        testVerifySRP(configuration: SRPConfiguration<SHA256>(.N2048))
        testVerifySRP(configuration: SRPConfiguration<SHA256>(.N3072))
        testVerifySRP(configuration: SRPConfiguration<Insecure.SHA1>(.N4096))
        testVerifySRP(configuration: SRPConfiguration<Insecure.SHA1>(.N6144))
        testVerifySRP(configuration: SRPConfiguration<Insecure.SHA1>(.N8192))
    }

    func testVerifySRPCustomConfiguration() {
        testVerifySRP(configuration: SRPConfiguration<SHA384>(N: BigNum(37), g: BigNum(3)))
    }

    func testClientSessionProof() {
        let configuration = SRPConfiguration<Insecure.SHA1>(.N1024)
        let username = "alice"
        let salt = "bafa3be2813c9326".bytes(using: .hexadecimal)!
        let A = BigNum(hex: "b525e8fe2eac8f5da6b3220e66a0ab6f833a59d5f079fe9ddcdf111a22eaec95850374d9d7597f45497eb429bcde5057a450948de7d48edc034264916a01e6c0690e14b0a527f107d3207fd2214653c9162f5745e7cbeb19a550a072d4600ce8f4ef778f6d6899ba718adf0a462e7d981ed689de93ea1bda773333f23ebb4a9b")!
        let B = BigNum(hex: "2bfc8559a022497f1254af3c76786b95cb0dfb449af15501aa51eefe78947d7ef06df4fcc07a899bcaae0e552ca72c7a1f3016f3ec357a86a1428dad9f98cb8a69d405404e57e9aaf01e51a46a73b3fc7bc1d212569e4a882ae6d878599e098c89033838ec069fe368a49461f531e5b4662700d56d8c252d0aea9da6abe9b014")!
        let secret = "b6288955afd690a13686d65886b5f82018515df3".bytes(using: .hexadecimal)!
        let clientProof = SRP<Insecure.SHA1>.calculateClientVerification(configuration: configuration, username: username, salt: salt, clientPublicKey: SRPKey(A), serverPublicKey: SRPKey(B), hashSharedSecret: secret)

        XCTAssertEqual(clientProof.hexdigest(), "e4c5c2e145ea2de18d0cc1ac9dc2a0d0988706d6")
    }

    func testServerSessionProof() {
        let A = BigNum(hex: "eade4992a46182e9ffe2e69f3e2639ca5f8c29b2868083c45d0972b72bb6003911b64a7ea6738061d705d368ddbe2bdb251bec63184db09b8990d8a7415dc449fbab720626fc25d6bd33c32234973c1e41c25b18d1824590c807c491221be5493878bd27a5ca507fd3963c849b07a9ec413e13253c6c61e7f3219b247cfa574a")!
        let secret = "d89740e18a9fb597aef8f2ecc0e66f4b31c2ae08".bytes(using: .hexadecimal)!
        let clientProof = "e1a8629a723039a61be91a173ab6260fc582192f".bytes(using: .hexadecimal)!

        let serverProof = SRP<Insecure.SHA1>.calculateServerVerification(clientPublicKey: SRPKey(A), clientVerifyCode: clientProof, sharedSecret: secret)

        XCTAssertEqual(serverProof.hexdigest(), "8342bd06bdf4d263de2df9a56da8e581fb38c769")
    }

    // Test results against RFC5054 Appendix B
    func testRFC5054Appendix() throws {
        let username = "alice"
        let password = "password123"
        let salt = "BEB25379D1A8581EB5A727673A2441EE".bytes(using: .hexadecimal)!
        let configuration = SRPConfiguration<Insecure.SHA1>(.N1024)
        let client = SRPClient<Insecure.SHA1>(configuration: configuration)

        XCTAssertEqual(configuration.k.hex, "7556AA045AEF2CDD07ABAF0F665C3E818913186F".lowercased())

        let verifier = client.generatePasswordVerifier(username: username, password: password, salt: salt)

        XCTAssertEqual(verifier.hex, "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB".lowercased())

        let a = BigNum(hex: "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393")!
        // copied from client.swift
        let A = configuration.g.power(a, modulus: configuration.N)

        XCTAssertEqual(A.hex, "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B".lowercased())

        let b = BigNum(hex: "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20")!
        // copied from server.swift
        let B = (configuration.k * verifier + configuration.g.power(b, modulus: configuration.N)) % configuration.N

        XCTAssertEqual(B.hex, "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58".lowercased())

        let u = SRP<Insecure.SHA1>.calculateU(clientPublicKey: A.bytes, serverPublicKey: B.bytes, pad: configuration.sizeN)

        XCTAssertEqual(u.hex, "CE38B9593487DA98554ED47D70A7AE5F462EF019".lowercased())

        let sharedSecret = try client.getSharedSecret(username: username, password: password, clientPublicKey: SRPKey(A), clientPrivateKey: SRPKey(a), serverPublicKey: B, salt: salt)

        XCTAssertEqual(sharedSecret.hex, "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A".lowercased())
    }

    static var allTests = [
        ("testSRPSharedSecret", testSRPSharedSecret),
        ("testVerifySRP", testVerifySRP),
        ("testVerifySRPCustomConfiguration", testVerifySRPCustomConfiguration),
        ("testClientSessionProof", testClientSessionProof),
        ("testServerSessionProof", testServerSessionProof),
        ("testRFC5054Appendix", testRFC5054Appendix)        
    ]
}

extension String {
    enum ExtendedEncoding {
        case hexadecimal
    }

    func bytes(using encoding:ExtendedEncoding) -> [UInt8]? {
        guard self.count % 2 == 0 else { return nil }

        var bytes: [UInt8] = []

        var indexIsEven = true
        for i in self.indices {
            if indexIsEven {
                let byteRange = i...self.index(after: i)
                guard let byte = UInt8(self[byteRange], radix: 16) else { return nil }
                bytes.append(byte)
            }
            indexIsEven.toggle()
        }
        return bytes
    }
}
