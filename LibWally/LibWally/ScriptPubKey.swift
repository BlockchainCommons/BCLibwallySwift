//
//  ScriptPubKey.swift
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation

public struct ScriptPubKey : Equatable {
    public let data: Data

    public enum ScriptType {
        case opReturn // OP_RETURN
        case payToPubKeyHash // P2PKH (legacy)
        case payToScriptHash // P2SH (could be wrapped SegWit)
        case payToWitnessPubKeyHash // P2WPKH (native SegWit)
        case payToWitnessScriptHash // P2WS (native SegWit script)
        case multiSig
    }

    public var type: ScriptType? {
        var output = 0
        data.withUnsafeByteBuffer { buf in
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

    public init(hex: String) throws {
        guard let data = Data(hex: hex) else {
            throw LibWallyError("Invalid ScriptPubKey.")
        }
        self.data = data
    }
    
    public init(multisig pubKeys:[ECCompressedPublicKey], threshold: UInt, isBIP67: Bool = true) {
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
        self.data = Data(bytes: script_bytes, count: written)
    }

    public var description: String {
        data.hex
    }

    public init(_ data: Data) {
        self.data = data
    }

    public var witnessProgram: Data {
        var script_bytes = [UInt8](repeating: 0, count: 34) // 00 20 HASH256
        var written = 0
        data.withUnsafeByteBuffer { buf in
            precondition(wally_witness_program_from_bytes(buf.baseAddress, buf.count, UInt32(WALLY_SCRIPT_SHA256), &script_bytes, script_bytes.count, &written) == WALLY_OK)
            precondition(written == script_bytes.count)
        }
        return Data(script_bytes)
    }
}
