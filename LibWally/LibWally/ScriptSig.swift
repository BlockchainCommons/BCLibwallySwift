//
//  ScriptSig.swift
//  LibWally
//
//  Created by Wolf McNally on 11/22/20.
//

import Foundation
import CLibWally

public struct ScriptSig {
    public typealias Signature = Data

    public let type: ScriptSigType

    // When used in a finalized transaction, scriptSig usually includes a signature:
    public var signature: Signature?

    public enum ScriptSigType : Equatable {
        case payToPubKeyHash(PubKey) // P2PKH (legacy)
        case payToScriptHashPayToWitnessPubKeyHash(PubKey) // P2SH-P2WPKH (wrapped SegWit)
    }

    public init(type: ScriptSigType) {
        self.type = type
        self.signature = nil
    }

    public enum ScriptSigPurpose {
        case signed
        case feeWorstCase
    }

    public func render(purpose: ScriptSigPurpose) -> Data? {
        switch type {
        case .payToPubKeyHash(let pubKey):
            switch purpose {
            case .feeWorstCase:
                // DER encoded signature
                let dummySignature = Data([UInt8].init(repeating: 0, count: Int(EC_SIGNATURE_DER_MAX_LOW_R_LEN)))
                let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
                let lengthPushSignature = Data([UInt8(dummySignature.count + 1)]) // DER encoded signature + sighash byte
                let lengthPushPubKey = Data([UInt8(pubKey.data.count)])
                return lengthPushSignature + dummySignature + sigHashByte + lengthPushPubKey + pubKey.data
            case .signed:
                if let signature = signature {
                    let lengthPushSignature = Data([UInt8(signature.count + 1)]) // DER encoded signature + sighash byte
                    let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
                    let lengthPushPubKey = Data([UInt8(pubKey.data.count)])
                    return lengthPushSignature + signature + sigHashByte + lengthPushPubKey + pubKey.data
                } else {
                    return nil
                }
            }
        case .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
            var pubkey_hash_bytes = [UInt8](repeating: 0, count: Int(HASH160_LEN))
            pubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_hash160(buf.baseAddress, buf.count, &pubkey_hash_bytes, Int(HASH160_LEN)) == WALLY_OK)
            }
            let redeemScript = try! Data(hex: "0014") + Data(pubkey_hash_bytes)
            return Data([UInt8(redeemScript.count)]) + redeemScript
        }
    }
}
