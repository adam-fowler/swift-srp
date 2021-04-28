//
//  File.swift
//  
//
//  Created by Joseph Ross on 4/26/21.
//

import Foundation
import CommonCrypto

public protocol HashFunction {
    static func hash<D>(data: D) -> Data where D : DataProtocol
}

public enum Insecure {
}

extension Insecure {

    /// The SHA-1 Hash Function.
    /// ⚠️ Security Recommendation: The SHA-1 hash function is no longer considered secure. We strongly recommend using the SHA-256 hash function instead.
    public struct SHA1 {
        @inlinable public static func hash<D>(data: D) -> Data where D : DataProtocol {
            var digest = Data(count:20)
            let data = Data(data)
        
            let _ = data.withUnsafeBytes() { dataPtr in
                digest.withUnsafeMutableBytes() { digestPtr in
                    CC_SHA1(dataPtr, UInt32(data.count), digestPtr)
                }
            }
            return digest
        }
    }
}

public struct SHA256 {
    @inlinable public static func hash<D>(data: D) -> Data where D : DataProtocol {
        var digest = Data(count:32)
        let data = Data(data)
    
        let _ = data.withUnsafeBytes() { dataPtr in
            digest.withUnsafeMutableBytes() { digestPtr in
                CC_SHA256(dataPtr, UInt32(data.count), digestPtr)
            }
        }
        return digest
    }
}

extension Insecure.SHA1 : HashFunction {
}

extension SHA256: HashFunction {
}

public struct SymmetricKey {
    let data: Data
    init(size: Int) {
        var data = Data(count:size)
        data.withUnsafeMutableBytes { dataPtr in
            CCRandomGenerateBytes(dataPtr, size)
        }
        self.data = data
    }
}

extension SymmetricKey: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try data.withUnsafeBytes { buffer in
            try body(buffer)
        }
    }
}
