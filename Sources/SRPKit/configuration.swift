import BigNum
import Crypto
import Foundation

/// SRP Configuration. The same configuration hast to be used by both client and server.
/// Contains a large safe prime N ie a prime where the value (N-1)/2 is also a prime
/// g the multiplicative group generator and the value k = Hash(N | g)
public struct SRPConfiguration<H: HashFunction> {
    public let N: BigNum
    public let g: BigNum
    public let k: BigNum
    
    /// Initialise SRPConfiguration with known safe prime
    /// - Parameter prime: enum indicating size of prime
    init(_ prime: Prime) {
        self.N = prime.number
        self.g = BigNum(2)
        self.k = BigNum(bytes: [UInt8](H.hash(data: SRP<H>.pad(self.N.bytes) + self.g.bytes)))
    }
    
    /// Initialise SRPConfiguration with your own prime and multiplicative group generator
    /// - Parameters:
    ///   - N: Large prime
    ///   - g: multiplicative group generator (usually 2)
    init(N: BigNum, g: BigNum) {
        self.N = N
        self.g = g
        self.k = BigNum(bytes: [UInt8](H.hash(data: SRP<H>.pad(self.N.bytes) + self.g.bytes)))
    }
    
    enum Prime {
        case N512
        case N1024
        case N1536
        case N2048
        case N3072
        case N4096
        
        var number: BigNum {
            switch self {
            case .N512:
                return BigNum(hex:
                    "008e6f683bb8c339498f67014cee70e076"
                    + "bc1c0f7710633100315be18bf771b6df"
                    + "a6b1dacb15e3217e1744d1f4749d8f3e"
                    + "b75bbfa6ae92e34fa5ff6e0f16d654d3")!

            case .N1024:
                return BigNum(hex:
                    "00add8edbf19bf2abe53e8a239e05df1b0"
                    + "edf9a49af8febdddbb7543db053b95e7"
                    + "c874611127c26796f00ede5ba1fb9183"
                    + "9019896f0a314160518ddaf3d33da54c"
                    + "4b006ab54aae81d69e6a770712ad68ed"
                    + "ad4d365adaf3ecf0e4dcade5ea5d86ee"
                    + "1cbab4c06610234f06adb8e0e8438d6d"
                    + "878c130c9c954ea3c5ff36e45165d543")!

            case .N1536:
                return BigNum(hex:
                    "009bbcaa8b5b3acf2dbd9a6164330743d4"
                    + "f8323eed05ec6311b28c41c052a7d590"
                    + "d4be1344163404bdf39122dce223124d"
                    + "689087cb201f1302d49c721f7abe104a"
                    + "5aa719e67ea61e4663de9fe095043a59"
                    + "495317be97ffe82355a22a960841ad67"
                    + "f3e986c377b6b190db0b36a7fd6ec3e3"
                    + "983929b1a76461bf54d80359e4a37650"
                    + "ce505693eeade246ea7bb4fa3dce0918"
                    + "90849b5894fe63dcc976a4fb4ada0991"
                    + "0ebdcb4a96da42d377124ddabb76d537"
                    + "f38b6a7065365428133e1d4ed49ea743")!

            case .N2048:
                return BigNum(hex:
                    "00cbcdeef727a5c66f77f4945bea38ef25"
                    + "32e05043e7a4cbecf293bccdc2bccbd8"
                    + "e9db0187f624c0b04c6423e7a3f862f9"
                    + "93efcfd2759ba512ad5d87f01e7711a6"
                    + "8733fbefec8443c2d6066634736bfb8e"
                    + "4928a9d754167ebd8669184b0990f312"
                    + "7fb563b212a4f5a27d70f51059cc4170"
                    + "80c6a945774d610cac9943a39fbefe22"
                    + "53d6c675eab2e8e0ea5f56be96cc5488"
                    + "d82aaaebd339c9f0577efaacb70214fd"
                    + "5238f070146d7c8a365a7e47cef70db2"
                    + "cc923d47d493910d2e2da5fde62b0fb2"
                    + "94346473c9ade7be27440d1a83bb320a"
                    + "2d3785967a7af99bee8ef9f4c971c256"
                    + "55f2649a834d0c43b03b27e211c4f7ff"
                    + "d96bd505bd166ff7c9673cb4f382d473")!

            case .N3072:
                return BigNum(hex:
                    "0093da890c203c42e8fba0502de61cecd5"
                    + "9fc5c3b2d0f7c8345df7671dcc362127"
                    + "4b19ab094ea1dddadbfc5acd9d9b5c7d"
                    + "199afd0e75fd2eb675d96362f48e1644"
                    + "593fbda810c3ad53c7c451ab5b9a5893"
                    + "fd130c83d985e2ced51809ca24001549"
                    + "5cac2a89fe4e79ea6d7870dede0a8f36"
                    + "7c1786090576d3d25c7088ffb871d07a"
                    + "335f5e1626e8cb702b9d2c30cbb951d5"
                    + "0e943f833496bc798d14ff3f2d0bb652"
                    + "09e4620671bb50e5016be49b3ba4d294"
                    + "c47e4a4630b9b97e3fe66917bdac6445"
                    + "cdf0efcd4f1365fee30312dbd795c53a"
                    + "52eb79818fdf2ccb7b81c6ac7c9220c4"
                    + "7ad3cc03bfbadbf63ac84b390bffb808"
                    + "9c5cccf505f683d4a35f5cd6008eece2"
                    + "234cf7bc44a7afaa3e18bf205764c522"
                    + "03828b912c4c9483fb08cfd7dacd351c"
                    + "6b9575a104e4210656de4cb55e6290b6"
                    + "701eac1e1fac708d75e02242d0240ea7"
                    + "3e309c83dd1645654a11ae88eb17ef61"
                    + "aff5c4679972e487250096f44b53877f"
                    + "0eb1fbee921bc8bdd181068f27769ccd"
                    + "073fa7e9dcecccb65c0c602c01ebdcdb")!
                
            case .N4096:
                return BigNum(hex:
                    "00d9d860a549dc4c86f91a42d345e531f5"
                    + "4dde6deb888624a6f54ec0ee73d350a6"
                    + "beba38fc1eccb174e66ae52fb901d040"
                    + "13eaefab87314b25fb40822d41cd1b37"
                    + "8c80c4018811c8caf5268184903d68fa"
                    + "0ae27f04ad5f51309eb23ba0fc023000"
                    + "f05903f4e5591baf47eb8db71619bcf6"
                    + "be47282f3db13926bddcf408c9327cbe"
                    + "75f33de6a5714f2b864509692c17195d"
                    + "017a6cbdf00726d1713d8262d9caba89"
                    + "9874f97a2ca3c48ea13fed456a861e85"
                    + "20d309c56d33469d0541a55c05d8e50f"
                    + "7295ad71b65f6699a941a322f49f2e97"
                    + "bcedad0376d9a5cc46f9012f069cbf38"
                    + "5de73b4e701e9641417a6015ada9e382"
                    + "516ee569528c3411da85c1f7a6e87981"
                    + "5fa609b73885df9668932190fe06b281"
                    + "8796d18e5ff2c01888cf08d8288a32a0"
                    + "6816d05e83b65aa53d8b5550df2aeee4"
                    + "dec9df397ce25f0a0dcfd6160c0bdc48"
                    + "619ac43aab68ce73e84cdb8ed2799713"
                    + "9454e8c6ed0d62ae1dcac6842dba6cf9"
                    + "78307092e83ae85f53cea0ed280d383c"
                    + "381a32daff546aa9ba8beb0e5456b891"
                    + "51bf5b5ba6eaa2f25840a1ae75a47409"
                    + "9a20ef5197e08adbb2c85b2c4de16db7"
                    + "d205167d85951f7f3b6dd4e1535dcddd"
                    + "c54961299172b34bdfc858872399738d"
                    + "4517cb18b4a9ec27a20e67bf766f0609"
                    + "b89b4fd1c3797505ed368e706a2aea04"
                    + "3756331c772044403074b4ebd81e1c22"
                    + "881baac1b14e3ab972ed5f9879b7e8bb")!
            }
        }
    }
}
