//
//  BitcoinWallyExtensions.swift
//  LibWally
//
//  Created by Wolf McNally on 9/17/21.
//

import Foundation
@_implementationOnly import WolfBase

public typealias WallyTx = UnsafeMutablePointer<wally_tx>
public typealias WallyTxInput = UnsafeMutablePointer<wally_tx_input>
public typealias WallyTxOutput = UnsafeMutablePointer<wally_tx_output>
public typealias WallyExtKey = ext_key
public typealias WallyPSBT = UnsafeMutablePointer<wally_psbt>
public typealias WallyPSBTInput = wally_psbt_input
public typealias WallyPSBTOutput = wally_psbt_output

extension Wally {
    public static func base58(from key: WallyExtKey, isPrivate: Bool) -> String? {
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
    public static func hdKeyToAddress(hdKey: HDKey, type: Bitcoin.Address.AddressType) -> String {
        var key = hdKey.wallyExtKey
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

extension Wally {
    public static func encodeWIF(key: ECPrivateKey, network: Network, isPublicKeyCompressed: Bool) -> String {
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
    public static func psbt(from data: Data) -> WallyPSBT? {
        data.withUnsafeByteBuffer { bytes in
            var p: WallyPSBT? = nil
            guard wally_psbt_from_bytes(bytes.baseAddress!, data.count, &p) == WALLY_OK else {
                return nil
            }
            return p!
        }
    }
    
    public static func free(psbt: WallyPSBT) {
        wally_psbt_free(psbt)
    }
    
    public static func clone(psbt: WallyPSBT) -> WallyPSBT {
        var new_psbt: WallyPSBT!
        precondition(wally_psbt_clone_alloc(psbt, 0, &new_psbt) == WALLY_OK)
        return new_psbt
    }
    
    public static func isFinalized(psbt: WallyPSBT) -> Bool {
        var result = 0
        precondition(wally_psbt_is_finalized(psbt, &result) == WALLY_OK)
        return result != 0
    }
    
    public static func finalized(psbt: WallyPSBT) -> WallyPSBT? {
        let final = copy(psbt: psbt)
        guard wally_psbt_finalize(final) == WALLY_OK else {
            return nil
        }
        return final
    }

    public static func finalizedTransaction(psbt: WallyPSBT) -> Transaction? {
        var output: WallyTx!
        defer {
            wally_tx_free(output)
        }

        guard wally_psbt_extract(psbt, &output) == WALLY_OK else {
            return nil
        }
        return Transaction(tx: output)
    }
    
    public static func getLength(psbt: WallyPSBT) -> Int {
        var len = 0
        precondition(wally_psbt_get_length(psbt, 0, &len) == WALLY_OK)
        return len
    }
    
    public static func serialized(psbt: WallyPSBT) -> Data {
        let len = getLength(psbt: psbt)
        var result = Data(count: len)
        result.withUnsafeMutableBytes {
            var written = 0
            precondition(wally_psbt_to_bytes(psbt, 0, $0.bindMemory(to: UInt8.self).baseAddress!, len, &written) == WALLY_OK)
            precondition(written == len)
        }
        return result
    }
    
    private static func copy(psbt: WallyPSBT) -> WallyPSBT {
        let data = serialized(psbt: psbt)
        return Self.psbt(from: data)!
    }
    
    public static func signed(psbt: WallyPSBT, ecPrivateKey: Data) -> WallyPSBT? {
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
    public static func getType(from scriptPubKey: ScriptPubKey) -> ScriptPubKey.ScriptType? {
        var output = 0
        scriptPubKey.script.data.withUnsafeByteBuffer { buf in
            precondition(wally_scriptpubkey_get_type(buf.baseAddress, buf.count, &output) == WALLY_OK)
        }

        switch Int32(output) {
        case WALLY_SCRIPT_TYPE_OP_RETURN:
            return .return
        case WALLY_SCRIPT_TYPE_P2PKH:
            return .pkh
        case WALLY_SCRIPT_TYPE_P2SH:
            return .sh
        case WALLY_SCRIPT_TYPE_P2WPKH:
            return .wpkh
        case WALLY_SCRIPT_TYPE_P2WSH:
            return .wsh
        case WALLY_SCRIPT_TYPE_MULTISIG:
            return .multi
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
        return ScriptPubKey(Script(Data(bytes: script_bytes, count: written)))
    }
    
    public static func address(from scriptPubKey: ScriptPubKey, network: Network) -> String {
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        scriptPubKey.script.data.withUnsafeByteBuffer { buf in
            precondition(wally_scriptpubkey_to_address(buf.baseAddress, buf.count, network.wallyNetwork, &output) == WALLY_OK)
        }
        precondition(output != nil)
        return String(cString: output!)
    }
    
    public static func segwitAddress(script: Script, network: Network) -> String {
        var output: UnsafeMutablePointer<Int8>!
        defer {
            wally_free_string(output)
        }
        script.data.withUnsafeByteBuffer { buf in
            precondition(wally_addr_segwit_from_bytes(buf.baseAddress, buf.count, network.segwitFamily, 0, &output) == WALLY_OK)
        }
        return String(cString: output)
    }
    
    public static func segwitAddress(scriptPubKey: ScriptPubKey, network: Network) -> String {
        segwitAddress(script: scriptPubKey.script, network: network)
    }
    
    public static func witnessProgram(scriptPubKey: ScriptPubKey) -> Script {
        var script_bytes = [UInt8](repeating: 0, count: 34) // 00 20 HASH256
        var written = 0
        scriptPubKey.script.data.withUnsafeByteBuffer { buf in
            precondition(wally_witness_program_from_bytes(buf.baseAddress, buf.count, UInt32(WALLY_SCRIPT_SHA256), &script_bytes, script_bytes.count, &written) == WALLY_OK)
            precondition(written == script_bytes.count)
        }
        return Script(Data(script_bytes))
    }

    public static func addressToScriptPubKey(address: String, network: Network) -> ScriptPubKey? {
        // base58 and bech32 use more bytes in string form, so description.count should be safe:
        var bytes_out = [UInt8](repeating: 0, count: address.count)
        var written = 0
        guard wally_address_to_scriptpubkey(address, network.wallyNetwork, &bytes_out, address.count, &written) == WALLY_OK else {
            return nil
        }
        return ScriptPubKey(Script(Data(bytes: bytes_out, count: written)))
    }

    public static func segwitAddressToScriptPubKey(address: String, network: Network) -> ScriptPubKey? {
        // base58 and bech32 use more bytes in string form, so description.count should be safe:
        var bytes_out = [UInt8](repeating: 0, count: address.count)
        var written = 0
        guard wally_addr_segwit_to_bytes(address, network.segwitFamily, 0, &bytes_out, address.count, &written) == WALLY_OK else {
            return nil
        }
        return ScriptPubKey(Script(Data(bytes: bytes_out, count: written)))
    }
    
    public static func hdKey(fromBase58 base58: String) -> WallyExtKey? {
        var result = WallyExtKey()
        guard bip32_key_from_base58(base58, &result) == WALLY_OK else {
            return nil
        }
        return result
    }
}

extension Wally {
    public static func txFromBytes(_ data: Data) -> WallyTx? {
        var newTx: WallyTx!
        let result = data.withUnsafeByteBuffer { buf in
            wally_tx_from_bytes(buf.baseAddress, buf.count, UInt32(WALLY_TX_FLAG_USE_WITNESS), &newTx)
        }
        guard result == WALLY_OK else {
            return nil
        }
        return newTx
    }
    
    public static func txSetInputScript(tx: WallyTx, index: Int, script: Data) {
        script.withUnsafeByteBuffer {
            precondition(wally_tx_set_input_script(tx, index, $0.baseAddress, $0.count) == WALLY_OK)
        }
    }
    
    public static func txAddInput(tx: WallyTx, input: WallyTxInput) {
        precondition(wally_tx_add_input(tx, input) == WALLY_OK)
    }
    
    public static func txAddOutput(tx: WallyTx, output: WallyTxOutput) {
        precondition(wally_tx_add_output(tx, output) == WALLY_OK)
    }
    
    public static func txToHex(tx: WallyTx) -> String {
        var output: UnsafeMutablePointer<Int8>!
        defer {
            wally_free_string(output)
        }
        
        precondition(wally_tx_to_hex(tx, UInt32(WALLY_TX_FLAG_USE_WITNESS), &output) == WALLY_OK)
        return String(cString: output!)
    }
    
    public static func txGetTotalOutputSatoshi(tx: WallyTx) -> Satoshi {
        var value_out: UInt64 = 0
        precondition(wally_tx_get_total_output_satoshi(tx, &value_out) == WALLY_OK)
        return value_out
    }
    
    public static func txGetVsize(tx: WallyTx) -> Int {
        var value_out = 0
        precondition(wally_tx_get_vsize(tx, &value_out) == WALLY_OK)
        return value_out
    }
    
    public static func txGetBTCSignatureHash(tx: WallyTx, index: Int, script: Data, amount: Satoshi, isWitness: Bool) -> Data {
        script.withUnsafeByteBuffer { buf in
            var message_bytes = [UInt8](repeating: 0, count: Int(SHA256_LEN))
            precondition(wally_tx_get_btc_signature_hash(tx, index, buf.baseAddress, buf.count, amount, UInt32(WALLY_SIGHASH_ALL), isWitness ? UInt32(WALLY_TX_FLAG_USE_WITNESS) : 0, &message_bytes, Int(SHA256_LEN)) == WALLY_OK)
            return Data(message_bytes)
        }
    }
}

extension Data {
    public func base58(isCheck: Bool) -> String {
        Wally.base58(data: self, isCheck: isCheck)
    }
}
