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
    
    init(_ data: Data) throws
    
    var hex: String { get }
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

    public init(_ data: Data) throws {
        guard data.count == Self.keyLen else {
            throw LibWallyError("Incorrect private key length.")
        }
        self.data = data
    }
    
    public init(wif: String, network: Network, isCompressed: Bool) throws {
        var bytes_out = [UInt8](repeating: 0, count: Int(EC_PRIVATE_KEY_LEN))
        // TODO: autodetect network by trying both
        // TODO: autodetect compression with wally_wif_is_uncompressed
        guard wally_wif_to_bytes(wif, network.wifPrefix, UInt32(isCompressed ? WALLY_WIF_FLAG_COMPRESSED : WALLY_WIF_FLAG_UNCOMPRESSED), &bytes_out, bytes_out.count) == WALLY_OK else {
            throw LibWallyError("Invalid key.")
        }
        self.data = Data(bytes_out)
    }

    public func wif(network: Network, isCompressed: Bool) -> String {
        precondition(data.count == Int(EC_PRIVATE_KEY_LEN))
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        data.withUnsafeByteBuffer { buf in
            precondition(wally_wif_from_bytes(buf.baseAddress, buf.count, network.wifPrefix, UInt32(isCompressed ? WALLY_WIF_FLAG_COMPRESSED : WALLY_WIF_FLAG_UNCOMPRESSED), &output) == WALLY_OK)
        }
        assert(output != nil)
        return String(cString: output!)
    }

    public var `public`: ECCompressedPublicKey {
        return try! ECCompressedPublicKey(Wally.ecPublicKeyFromPrivateKey(data: data))
    }
}

public struct ECCompressedPublicKey: ECPublicKey, Hashable {
    public static var keyLen: Int = Int(EC_PUBLIC_KEY_LEN)
    public let data: Data

    public init(_ data: Data) throws {
        guard data.count == Self.keyLen else {
            throw LibWallyError("Incorrect public key length.")
        }
        self.data = data
    }
    
    public var compressed: ECCompressedPublicKey {
        self
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        return try! ECUncompressedPublicKey(Wally.ecPublicKeyDecompress(data: data))
    }
    
    public func address(version: UInt8) -> String {
        var hash = data.hash160
        hash.insert(version, at: 0)
        return hash.base58(isCheck: true)
    }
    
    public func address(useInfo: UseInfo, isSH: Bool) -> String {
        address(version: isSH ? useInfo.versionSH : useInfo.versionPKH)
    }
}

public struct ECUncompressedPublicKey: ECPublicKey {
    public static var keyLen: Int = Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
    public let data: Data

    public init(_ data: Data) throws {
        self.data = data
    }

    public var compressed: ECCompressedPublicKey {
        return try! ECCompressedPublicKey(Wally.ecPublicKeyCompress(data: data))
    }
    
    public var uncompressed: ECUncompressedPublicKey {
        self
    }
}
