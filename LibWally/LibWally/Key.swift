//
//  Key.swift
//  LibWally
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation
import CLibWally

public struct Key {
    public let isCompressed: Bool
    public let data: Data
    public let network: Network

    static func prefix (_ network: Network) -> UInt32 {
        switch network {
         case .mainnet:
             return UInt32(WALLY_ADDRESS_VERSION_WIF_MAINNET)
         case .testnet:
             return UInt32(WALLY_ADDRESS_VERSION_WIF_TESTNET)
         }
    }

    public init(_ wif: String, _ network: Network, isCompressed: Bool = true) throws {
        var bytes_out = [UInt8](repeating: 0, count: Int(EC_PRIVATE_KEY_LEN))
        // TODO: autodetect network by trying both
        // TODO: autodetect compression with wally_wif_is_uncompressed
        let flags = UInt32(isCompressed ? WALLY_WIF_FLAG_COMPRESSED : WALLY_WIF_FLAG_UNCOMPRESSED)
        guard wally_wif_to_bytes(wif, Key.prefix(network), flags, &bytes_out, bytes_out.count) == WALLY_OK else {
            throw LibWallyError("Invalid key.")
        }
        self.isCompressed = isCompressed
        self.data = Data(bytes_out)
        self.network = network
    }

    public init(_ data: Data, _ network: Network, isCompressed: Bool = true) throws {
        guard data.count == Int(EC_PRIVATE_KEY_LEN) else {
            throw LibWallyError("Invalid key.")
        }
        self.data = data
        self.network = network
        self.isCompressed = isCompressed
    }

    public var wif: String {
        precondition(data.count == Int(EC_PRIVATE_KEY_LEN))
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        data.withUnsafeByteBuffer { buf in
            let flags = UInt32(isCompressed ? WALLY_WIF_FLAG_COMPRESSED : WALLY_WIF_FLAG_UNCOMPRESSED)
            precondition(wally_wif_from_bytes(buf.baseAddress, buf.count, Key.prefix(network), flags, &output) == WALLY_OK)
        }
        assert(output != nil)
        return String(cString: output!)
    }

    public var pubKey: PubKey {
        precondition(data.count == Int(EC_PRIVATE_KEY_LEN))

        var bytes_out = [UInt8](repeating: 0, count: Int(EC_PUBLIC_KEY_LEN))

        data.withUnsafeByteBuffer { buf in
            precondition(wally_ec_public_key_from_private_key(buf.baseAddress, buf.count, &bytes_out, Int(EC_PUBLIC_KEY_LEN)) == WALLY_OK)
        }
        if !isCompressed {
            var bytes_out_uncompressed = [UInt8](repeating: 0, count: Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN))
            precondition(wally_ec_public_key_decompress(bytes_out, Int(EC_PUBLIC_KEY_LEN), &bytes_out_uncompressed, Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN)) == WALLY_OK)
            return try! PubKey(Data(bytes_out_uncompressed), network, isCompressed: false)
        } else {
            return try! PubKey(Data(bytes_out), network, isCompressed: true)
        }
    }
}
