//
//  ScriptPubKey.swift
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import CLibWally

public struct ScriptPubKey : Equatable {
    var bytes: Data

    public enum ScriptType {
        case opReturn // OP_RETURN
        case payToPubKeyHash // P2PKH (legacy)
        case payToScriptHash // P2SH (could be wrapped SegWit)
        case payToWitnessPubKeyHash // P2WPKH (native SegWit)
        case payToWitnessScriptHash // P2WS (native SegWit script)
        case multiSig
    }

    public var type: ScriptType? {
        let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: self.bytes.count)
        let bytes_len = self.bytes.count
        let output = UnsafeMutablePointer<Int>.allocate(capacity: 1)

        self.bytes.copyBytes(to: bytes, count: bytes_len)

        precondition(wally_scriptpubkey_get_type(bytes, bytes_len, output) == WALLY_OK)

        switch Int32(output.pointee) {
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
            precondition(output.pointee == WALLY_SCRIPT_TYPE_UNKNOWN)
            return nil
        }
    }

    public init(hex: String) throws {
        self.bytes = try Data(hex: hex)
    }
    
    public init(multisig pubKeys:[PubKey], threshold: UInt, isBIP67: Bool = true) {
        let pubkeys_bytes_len = Int(EC_PUBLIC_KEY_LEN) * pubKeys.count
        let pubkeys_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: pubkeys_bytes_len)
        var offset = 0
        for pubKey in pubKeys {
            pubKey.data.copyBytes(to: pubkeys_bytes + offset, count: pubKey.data.count)
            offset += Int(EC_PUBLIC_KEY_LEN)
        }
        let scriptLen = 3 + pubKeys.count * (Int(EC_PUBLIC_KEY_LEN) + 1)
        let script_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: scriptLen)
        defer {
            script_bytes.deallocate()
        }
        let flags = UInt32(isBIP67 ? WALLY_SCRIPT_MULTISIG_SORTED : 0)
        var written = 0
        precondition(wally_scriptpubkey_multisig_from_bytes(pubkeys_bytes, pubkeys_bytes_len, UInt32(threshold), flags, script_bytes, scriptLen, &written) == WALLY_OK)

        self.bytes = Data(bytes: script_bytes, count: written)
    }

    public var description: String {
        return self.bytes.hex
    }


    init(_ bytes: Data) {
        self.bytes = bytes
    }

    public var witnessProgram: Data {
        let bytes_len = self.bytes.count
        let bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: bytes_len)
        self.bytes.copyBytes(to: bytes, count: bytes_len)
        let script_bytes_len = 34 // 00 20 HASH256
        let script_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: script_bytes_len)
        defer {
            script_bytes.deallocate()
        }
        var written = 0
        precondition(wally_witness_program_from_bytes(bytes, bytes_len, UInt32(WALLY_SCRIPT_SHA256), script_bytes, script_bytes_len, &written) == WALLY_OK)
        precondition(written == script_bytes_len)
        return Data(bytes: script_bytes, count: written)
    }

}
