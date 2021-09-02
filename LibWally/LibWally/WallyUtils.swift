//
//  WallyUtils.swift
//  LibWally
//
//  Created by Wolf McNally on 8/25/21.
//

import Foundation
@_implementationOnly import WolfBase

public enum Wally {
}

extension Wally {
    public static func base58(from key: ext_key, isPrivate: Bool) -> String? {
        guard
            !Data(of: key.chain_code).isAllZero,
            key.version != 0
        else {
            return nil
        }

        let flags = UInt32(isPrivate ? BIP32_FLAG_KEY_PRIVATE : BIP32_FLAG_KEY_PUBLIC)
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        return withUnsafePointer(to: key) {
            precondition(bip32_key_to_base58($0, flags, &output) == WALLY_OK)
            return String(cString: output!)
        }
    }
    
    public static func key(from parentKey: ext_key, childNum: UInt32, isPrivate: Bool) -> ext_key? {
        withUnsafePointer(to: parentKey) { parentPointer in
            let flags = UInt32(isPrivate ? BIP32_FLAG_KEY_PRIVATE : BIP32_FLAG_KEY_PUBLIC)
            var derivedKey = ext_key()
            guard bip32_key_from_parent(parentPointer, childNum, flags, &derivedKey) == WALLY_OK else {
                return nil
            }
            return derivedKey
        }
    }
    
    public static func fingerprintData(for key: ext_key) -> Data {
        // This doesn't work with a non-derivable key, because LibWally thinks it's invalid.
        //var bytes = [UInt8](repeating: 0, count: Int(BIP32_KEY_FINGERPRINT_LEN))
        //precondition(bip32_key_get_fingerprint(&hdkey, &bytes, bytes.count) == WALLY_OK)
        //return Data(bytes)

        hash160(key.pub_key).prefix(Int(BIP32_KEY_FINGERPRINT_LEN))
    }
    
    public static func fingerprint(for key: ext_key) -> UInt32 {
        deserialize(UInt32.self, fingerprintData(for: key))!
    }
    
    public static func updateHash160(in key: inout ext_key) {
        let hash160Size = MemoryLayout.size(ofValue: key.hash160)
        withUnsafeByteBuffer(of: key.pub_key) { pub_key in
            withUnsafeMutableByteBuffer(of: &key.hash160) { hash160 in
                precondition(wally_hash160(
                    pub_key.baseAddress!, Int(EC_PUBLIC_KEY_LEN),
                    hash160.baseAddress!, hash160Size
                ) == WALLY_OK)
            }
        }
    }
    
    public static func updatePublicKey(in key: inout ext_key) {
        withUnsafeByteBuffer(of: key.priv_key) { priv_key in
            withUnsafeMutableByteBuffer(of: &key.pub_key) { pub_key in
                precondition(wally_ec_public_key_from_private_key(
                    priv_key.baseAddress! + 1, Int(EC_PRIVATE_KEY_LEN),
                    pub_key.baseAddress!, Int(EC_PUBLIC_KEY_LEN)
                ) == WALLY_OK)
            }
        }
    }
}

extension Wally {
    public static func encodeWIF(key: ECKey, network: Network, isPublicKeyCompressed: Bool) -> String {
        var output: UnsafeMutablePointer<Int8>!
        defer {
            wally_free_string(output)
        }
        key.data.withUnsafeByteBuffer { buf in
            precondition(wally_wif_from_bytes(buf.baseAddress, buf.count, network.wifPrefix, UInt32(isPublicKeyCompressed ? WALLY_WIF_FLAG_COMPRESSED : WALLY_WIF_FLAG_UNCOMPRESSED), &output) == WALLY_OK)
        }
        return String(cString: output)
    }
}

extension Wally {
    public static func psbt(from data: Data) -> UnsafeMutablePointer<wally_psbt>? {
        data.withUnsafeByteBuffer { bytes in
            var p: UnsafeMutablePointer<wally_psbt>? = nil
            guard wally_psbt_from_bytes(bytes.baseAddress!, data.count, &p) == WALLY_OK else {
                return nil
            }
            return p!
        }
    }
    
    public static func free(psbt: UnsafeMutablePointer<wally_psbt>) {
        wally_psbt_free(psbt)
    }
    
    public static func isFinalized(psbt: UnsafePointer<wally_psbt>) -> Bool {
        var result = 0
        precondition(wally_psbt_is_finalized(psbt, &result) == WALLY_OK)
        return result != 0
    }
    
    public static func serialized(psbt: UnsafePointer<wally_psbt>) -> Data {
        var len = 0
        precondition(wally_psbt_get_length(psbt, 0, &len) == WALLY_OK)
        var result = Data(count: len)
        result.withUnsafeMutableBytes {
            var written = 0
            precondition(wally_psbt_to_bytes(psbt, 0, $0.bindMemory(to: UInt8.self).baseAddress!, len, &written) == WALLY_OK)
            precondition(written == len)
        }
        return result
    }
    
    private static func copy(psbt: UnsafePointer<wally_psbt>) -> UnsafeMutablePointer<wally_psbt> {
        let data = serialized(psbt: psbt)
        return Self.psbt(from: data)!
    }
    
    public static func finalized(psbt: UnsafePointer<wally_psbt>) -> UnsafeMutablePointer<wally_psbt>? {
        let final = copy(psbt: psbt)
        guard wally_psbt_finalize(final) == WALLY_OK else {
            return nil
        }
        return final
    }
    
    public static func signed(psbt: UnsafePointer<wally_psbt>, ecPrivateKey: Data) -> UnsafeMutablePointer<wally_psbt>? {
        ecPrivateKey.withUnsafeByteBuffer { keyBytes in
            let signedPSBT = copy(psbt: psbt)
            let ret = wally_psbt_sign(signedPSBT, keyBytes.baseAddress, keyBytes.count, 0)
            guard ret == WALLY_OK else {
                return nil
            }
            return signedPSBT
        }
    }
}

extension Wally {
    public static func ecPublicKeyFromPrivateKey(data: Data) -> Data {
        data.withUnsafeByteBuffer { inputBytes in
            var result = Data(count: Int(EC_PUBLIC_KEY_LEN))
            result.withUnsafeMutableByteBuffer { outputBytes in
                precondition(
                    wally_ec_public_key_from_private_key(
                        inputBytes.baseAddress,
                        inputBytes.count,
                        outputBytes.baseAddress,
                        outputBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func ecPublicKeyDecompress(data: Data) -> Data {
        data.withUnsafeByteBuffer { inputBytes in
            var result = Data(count: Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN))
            result.withUnsafeMutableByteBuffer { outputBytes in
                precondition(
                    wally_ec_public_key_decompress(
                        inputBytes.baseAddress,
                        inputBytes.count,
                        outputBytes.baseAddress,
                        outputBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func ecPublicKeyCompress(data: Data) -> Data {
        data.withUnsafeByteBuffer { inputBytes in
            var result = Data(count: Int(EC_PUBLIC_KEY_LEN))
            result.withUnsafeMutableByteBuffer { outputBytes in
                precondition(
                    wally_ec_public_key_negate(
                        inputBytes.baseAddress,
                        inputBytes.count,
                        outputBytes.baseAddress,
                        outputBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func hash160(_ data: Data) -> Data {
        data.withUnsafeByteBuffer { inBytes in
            var result = Data(count: Int(HASH160_LEN))
            result.withUnsafeMutableByteBuffer { outBytes in
                precondition(
                    wally_hash160(
                        inBytes.baseAddress,
                        inBytes.count,
                        outBytes.baseAddress,
                        outBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func hash160<T>(_ input: T) -> Data {
        withUnsafeByteBuffer(of: input) { inBytes in
            var result = Data(repeating: 0, count: Int(HASH160_LEN))
            result.withUnsafeMutableByteBuffer { outBytes in
                precondition(
                    wally_hash160(
                        inBytes.baseAddress,
                        inBytes.count,
                        outBytes.baseAddress,
                        outBytes.count
                    ) == WALLY_OK)
            }
            return result
        }
    }

    public static func base58(data: Data, isCheck: Bool) -> String {
        data.withUnsafeByteBuffer { p in
            var result: UnsafeMutablePointer<CChar>?
            precondition(
                wally_base58_from_bytes(
                    p.baseAddress,
                    p.count,
                    isCheck ? UInt32(BASE58_FLAG_CHECKSUM) : 0,
                    &result
                ) == WALLY_OK
            )
            let s = String(cString: result!)
            wally_free_string(result)
            return s
        }
    }
    
    public static func decodeBase58(_ s: String, isCheck: Bool) -> Data? {
        var output = [UInt8](repeating: 0, count: s.count)
        var written = 0
        guard wally_base58_to_bytes(s, isCheck ? UInt32(BASE58_FLAG_CHECKSUM) : 0, &output, output.count, &written) == WALLY_OK else {
            return nil
        }
        return Data(bytes: output, count: written)
    }
}

extension Wally {
    public static func getType(from scriptPubKey: ScriptPubKey) -> ScriptPubKey.ScriptType? {
        var output = 0
        scriptPubKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_scriptpubkey_get_type(buf.baseAddress, buf.count, &output) == WALLY_OK)
        }

        switch Int32(output) {
        case WALLY_SCRIPT_TYPE_OP_RETURN:
            return .opReturn
        case WALLY_SCRIPT_TYPE_P2PKH:
            return .payToPubKeyHash
        case WALLY_SCRIPT_TYPE_P2SH:
            return .payToScriptHash
        case WALLY_SCRIPT_TYPE_P2WPKH:
            return .payToWitnessPubKeyHash
        case WALLY_SCRIPT_TYPE_P2WSH:
            return .payToWitnessScriptHash
        case WALLY_SCRIPT_TYPE_MULTISIG:
            return .multiSig
        default:
            precondition(output == WALLY_SCRIPT_TYPE_UNKNOWN)
            return nil
        }
    }
    
    public static func multisigScriptPubKey(pubKeys:[ECCompressedPublicKey], threshold: UInt, isBIP67: Bool = true) -> ScriptPubKey {
        var pubkeys_bytes = Data()
        for pubKey in pubKeys {
            pubkeys_bytes.append(pubKey.data)
        }
        let scriptLen = 3 + pubKeys.count * (Int(EC_PUBLIC_KEY_LEN) + 1)
        var script_bytes = [UInt8](repeating: 0, count: scriptLen)
        let flags = UInt32(isBIP67 ? WALLY_SCRIPT_MULTISIG_SORTED : 0)
        var written = 0
        pubkeys_bytes.withUnsafeByteBuffer { buf in
            precondition(wally_scriptpubkey_multisig_from_bytes(buf.baseAddress, buf.count, UInt32(threshold), flags, &script_bytes, scriptLen, &written) == WALLY_OK)
        }
        return ScriptPubKey(Data(bytes: script_bytes, count: written))
    }
    
    public static func address(from scriptPubKey: ScriptPubKey, network: Network) -> String {
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        scriptPubKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_scriptpubkey_to_address(buf.baseAddress, buf.count, network.wallyNetwork, &output) == WALLY_OK)
        }
        precondition(output != nil)
        return String(cString: output!)
    }
    
    public static func segwitAddress(data: Data, network: Network) -> String {
        var output: UnsafeMutablePointer<Int8>!
        defer {
            wally_free_string(output)
        }
        data.withUnsafeByteBuffer { buf in
            precondition(wally_addr_segwit_from_bytes(buf.baseAddress, buf.count, network.segwitFamily, 0, &output) == WALLY_OK)
        }
        return String(cString: output)
    }
    
    public static func segwitAddress(scriptPubKey: ScriptPubKey, network: Network) -> String {
        segwitAddress(data: scriptPubKey.data, network: network)
    }
    
    public static func witnessProgram(scriptPubKey: ScriptPubKey) -> Data {
        var script_bytes = [UInt8](repeating: 0, count: 34) // 00 20 HASH256
        var written = 0
        scriptPubKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_witness_program_from_bytes(buf.baseAddress, buf.count, UInt32(WALLY_SCRIPT_SHA256), &script_bytes, script_bytes.count, &written) == WALLY_OK)
            precondition(written == script_bytes.count)
        }
        return Data(script_bytes)
    }

    public static func addressToScriptPubKey(address: String, network: Network) -> ScriptPubKey? {
        // base58 and bech32 use more bytes in string form, so description.count should be safe:
        var bytes_out = [UInt8](repeating: 0, count: address.count)
        var written = 0
        guard wally_address_to_scriptpubkey(address, network.wallyNetwork, &bytes_out, address.count, &written) == WALLY_OK else {
            return nil
        }
        return ScriptPubKey(Data(bytes: bytes_out, count: written))
    }

    public static func segwitAddressToScriptPubKey(address: String, network: Network) -> ScriptPubKey? {
        // base58 and bech32 use more bytes in string form, so description.count should be safe:
        var bytes_out = [UInt8](repeating: 0, count: address.count)
        var written = 0
        guard wally_addr_segwit_to_bytes(address, network.segwitFamily, 0, &bytes_out, address.count, &written) == WALLY_OK else {
            return nil
        }
        return ScriptPubKey(Data(bytes: bytes_out, count: written))
    }
    
    public static func hdKeyToAddress(hdKey: HDKey, type: Address.AddressType) -> String {
        var key = hdKey.wally_ext_key
        var output: UnsafeMutablePointer<Int8>!
        defer {
            wally_free_string(output)
        }
        
        switch type {
        case .payToPubKeyHash, .payToScriptHashPayToWitnessPubKeyHash:
            var version: UInt32
            switch hdKey.network {
            case .mainnet:
                version = type == .payToPubKeyHash ? 0x00 : 0x05
            case .testnet:
                version = type == .payToPubKeyHash ? 0x6F : 0xC4
            }
            precondition(wally_bip32_key_to_address(&key, type.wallyType, version, &output) == WALLY_OK)
        case .payToWitnessPubKeyHash:
            precondition(wally_bip32_key_to_addr_segwit(&key, hdKey.network.segwitFamily, 0, &output) == WALLY_OK)
        }
        
        return String(cString: output)
    }
}

extension Data {
    public var hash160: Data {
        Wally.hash160(self)
    }
}

extension Data {
    public func base58(isCheck: Bool) -> String {
        Wally.base58(data: self, isCheck: isCheck)
    }
}

extension ext_key: CustomStringConvertible {
    public var description: String {
        let chain_code = Data(of: self.chain_code).hex
        let parent160 = Data(of: self.parent160).hex
        let depth = self.depth
        let priv_key = Data(of: self.priv_key).hex
        let child_num = self.child_num
        let hash160 = Data(of: self.hash160).hex
        let version = self.version
        let pub_key = Data(of: self.pub_key).hex
        
        return "ext_key(chain_code: \(chain_code), parent160: \(parent160), depth: \(depth), priv_key: \(priv_key), child_num: \(child_num), hash160: \(hash160), version: \(version), pub_key: \(pub_key))"
    }
    
    public var isPrivate: Bool {
        return priv_key.0 == BIP32_FLAG_KEY_PRIVATE
    }
    
    public var isMaster: Bool {
        return depth == 0
    }
    
    public static func version_is_valid(ver: UInt32, flags: UInt32) -> Bool
    {
        if ver == BIP32_VER_MAIN_PRIVATE || ver == BIP32_VER_TEST_PRIVATE {
            return true
        }

        return flags == BIP32_FLAG_KEY_PUBLIC &&
               (ver == BIP32_VER_MAIN_PUBLIC || ver == BIP32_VER_TEST_PUBLIC)
    }

    public func checkValid() {
        let ver_flags = isPrivate ? UInt32(BIP32_FLAG_KEY_PRIVATE) : UInt32(BIP32_FLAG_KEY_PUBLIC)
        precondition(Self.version_is_valid(ver: version, flags: ver_flags))
        //precondition(!Data(of: chain_code).isAllZero)
        precondition(pub_key.0 == 0x2 || pub_key.0 == 0x3)
        precondition(!Data(of: pub_key).dropFirst().isAllZero)
        precondition(priv_key.0 == BIP32_FLAG_KEY_PUBLIC || priv_key.0 == BIP32_FLAG_KEY_PRIVATE)
        precondition(!isPrivate || !Data(of: priv_key).dropFirst().isAllZero)
        precondition(!isMaster || Data(of: parent160).isAllZero)
    }
}
