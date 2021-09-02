//
//  ECKey.swift
//  LibWally
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation

public protocol ECKey {
    static var keyLen: Int { get }

    var data: Data { get }
    
    init?(_ data: Data)
    
    var hex: String { get }
    
    var `public`: ECCompressedPublicKey { get }
}

extension ECKey {
    public var hex: String {
        data.hex
    }
}

public protocol ECPublicKey: ECKey {
    var compressed: ECCompressedPublicKey { get }
    var uncompressed: ECUncompressedPublicKey { get }
}

public struct ECPrivateKey: ECKey {
    public static let keyLen = Int(EC_PRIVATE_KEY_LEN)
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var `public`: ECCompressedPublicKey {
        return ECCompressedPublicKey(Wally.ecPublicKeyFromPrivateKey(data: data))!
    }
}

extension ECPrivateKey: CustomStringConvertible {
    public var description: String {
        "ECPrivateKey(\(data.hex))"
    }
}

public struct ECXOnlyPublicKey: Hashable {
    public static var keyLen = 32
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }
}

public struct ECCompressedPublicKey: ECPublicKey, Hashable {
    public static var keyLen: Int = Int(EC_PUBLIC_KEY_LEN)
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var compressed: ECCompressedPublicKey {
        self
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        return ECUncompressedPublicKey(Wally.ecPublicKeyDecompress(data: data))!
    }
    
    public func address(version: UInt8) -> String {
        var hash = data.hash160
        hash.insert(version, at: 0)
        return hash.base58(isCheck: true)
    }
    
    public func address(useInfo: UseInfo, isSH: Bool) -> String {
        address(version: isSH ? useInfo.versionSH : useInfo.versionPKH)
    }

    public var `public`: ECCompressedPublicKey {
        self
    }
}

extension ECCompressedPublicKey: CustomStringConvertible {
    public var description: String {
        "ECCompressedPublicKey(\(data.hex))"
    }
}

public struct ECUncompressedPublicKey: ECPublicKey {
    public static var keyLen: Int = Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
    public let data: Data

    public init?(_ data: Data) {
        guard data.count == Self.keyLen else {
            return nil
        }
        self.data = data
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var compressed: ECCompressedPublicKey {
        return ECCompressedPublicKey(Wally.ecPublicKeyCompress(data: data))!
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        self
    }

    public var `public`: ECCompressedPublicKey {
        self.compressed
    }
}

extension ECUncompressedPublicKey: CustomStringConvertible {
    public var description: String {
        "ECUncompressedPublicKey(\(data.hex))"
    }
}
