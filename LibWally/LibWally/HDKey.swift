//
//  HDKey.swift
//  LibWally
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation

public struct HDKey {
    public var wally_ext_key: ext_key
    public var masterKeyFingerprint: Data? // TODO: https://github.com/ElementsProject/libwally-core/issues/164

    init(key: ext_key, masterKeyFingerprint: Data? = nil) {
        self.wally_ext_key = key
        self.masterKeyFingerprint = masterKeyFingerprint
    }

    public init(base58: String, masterKeyFingerprint: Data? = nil) throws {
        var output = ext_key()
        let result = bip32_key_from_base58(base58, &output)
        if result == WALLY_OK {
            self.init(key: output, masterKeyFingerprint: masterKeyFingerprint)
        } else {
            throw LibWallyError("Invalid HD key.")
        }
        if wally_ext_key.depth == 0 {
            if masterKeyFingerprint == nil {
                self.masterKeyFingerprint = fingerprint
            } else {
                guard masterKeyFingerprint == fingerprint else {
                    throw LibWallyError("Invalid HD key.")
                }
            }
        }

    }

    public init(seed: BIP39Mnemonic.Seed, network: Network = .mainnet) throws {
        let flags: UInt32
        switch network {
        case .mainnet:
            flags = UInt32(BIP32_VER_MAIN_PRIVATE)
        case .testnet:
            flags = UInt32(BIP32_VER_TEST_PRIVATE)
        }
        var output = ext_key()
        let result = seed.data.withUnsafeByteBuffer { buf in
            bip32_key_from_seed(buf.baseAddress, buf.count, flags, 0, &output)
        }
        if result == WALLY_OK {
            self.init(key: output)
        } else {
            // From libwally-core docs:
            // The entropy passed in may produce an invalid key. If this happens, WALLY_ERROR will be returned
            // and the caller should retry with new entropy.
            throw LibWallyError("Invalid HD key.")
        }
        masterKeyFingerprint = fingerprint
    }

    public var network: Network {
        switch wally_ext_key.version {
        case UInt32(BIP32_VER_MAIN_PRIVATE), UInt32(BIP32_VER_MAIN_PUBLIC):
            return .mainnet
        case UInt32(BIP32_VER_TEST_PRIVATE), UInt32(BIP32_VER_TEST_PUBLIC):
            return .testnet
        default:
            precondition(false)
            return .mainnet
        }
    }

    public var description: String {
        isNeutered ? xpub : xpriv!
    }

    public var isNeutered: Bool {
        wally_ext_key.version == BIP32_VER_MAIN_PUBLIC || wally_ext_key.version == BIP32_VER_TEST_PUBLIC
    }

    public var xpub: String {
        var hdkey = wally_ext_key
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }

        precondition(bip32_key_to_base58(&hdkey, UInt32(BIP32_FLAG_KEY_PUBLIC), &output) == WALLY_OK)
        precondition(output != nil)
        return String(cString: output!)
    }

    public var pubKey: PubKey {
        try! PubKey(Data(of: wally_ext_key.pub_key), isCompressed: true)
    }

    public var privKey: Key? {
        if isNeutered {
            return nil
        }
        var data = Data(of: wally_ext_key.priv_key)
        // skip prefix byte 0
        precondition(data.popFirst() != nil)
        return try! Key(data, isCompressed: true)
    }

    public var xpriv: String? {
        if isNeutered {
            return nil
        }
        var hdkey = wally_ext_key
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }

        precondition(bip32_key_to_base58(&hdkey, UInt32(BIP32_FLAG_KEY_PRIVATE), &output) == WALLY_OK)
        precondition(output != nil)
        return String(cString: output!)
    }

    public var fingerprint: Data {
        var hdkey = wally_ext_key
        var fingerprint_bytes = [UInt8](repeating: 0, count: Int(BIP32_KEY_FINGERPRINT_LEN))
        precondition(bip32_key_get_fingerprint(&hdkey, &fingerprint_bytes, fingerprint_bytes.count) == WALLY_OK)
        return Data(fingerprint_bytes)
    }

    public func derive(using path: BIP32Path) throws -> HDKey {
        let depth = wally_ext_key.depth
        var tmpPath = path
        if !path.isRelative {
            tmpPath = try path.chop(depth: Int(depth))
        }

        if isNeutered && tmpPath.components.first(where: { $0.isHardened }) != nil {
            throw LibWallyError("Hardened derivation without private key.")
        }

        var hdkey = wally_ext_key
        var output = ext_key()
        precondition(bip32_key_from_parent_path(&hdkey, tmpPath.rawPath, tmpPath.rawPath.count, UInt32(isNeutered ? BIP32_FLAG_KEY_PUBLIC : BIP32_FLAG_KEY_PRIVATE), &output) == WALLY_OK)
        return HDKey(key: output, masterKeyFingerprint: masterKeyFingerprint)
    }

    public func address(type: AddressType) -> Address {
        try! Address(hdKey: self, type: type)
    }
}
