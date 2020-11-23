//
//  Witness.swift
//  LibWally
//
//  Created by Wolf McNally on 11/22/20.
//

import Foundation
import CLibWally

public struct Witness {
    public let type: WitnessType
    public let signature: Data
    public let isDummy: Bool

    public enum WitnessType {
        case payToWitnessPubKeyHash(PubKey) // P2WPKH (native SegWit)
        case payToScriptHashPayToWitnessPubKeyHash(PubKey) // P2SH-P2WPKH (wrapped SegWit)
    }

    public init(type: WitnessType, signature: Data, isDummy: Bool = false) {
        self.type = type
        self.signature = signature
        self.isDummy = isDummy
    }

    public func createWallyStack() -> UnsafeMutablePointer<wally_tx_witness_stack> {
        var newStack: UnsafeMutablePointer<wally_tx_witness_stack>!
        switch type {
        case .payToWitnessPubKeyHash(let pubKey):
            precondition(wally_tx_witness_stack_init_alloc(2, &newStack) == WALLY_OK)

            let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
            (signature + sigHashByte).withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 0, buf.baseAddress, buf.count) == WALLY_OK)
            }
            pubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 1, buf.baseAddress, buf.count) == WALLY_OK)
            }
        case .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
            precondition(wally_tx_witness_stack_init_alloc(2, &newStack) == WALLY_OK)

            let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
            (signature + sigHashByte).withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 0, buf.baseAddress, buf.count) == WALLY_OK)
            }
            pubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_tx_witness_stack_set(newStack!, 1, buf.baseAddress, buf.count) == WALLY_OK)
            }
        }
        return newStack
    }

    // Initialize without signature argument to get a dummy signature for fee calculation
    public init(type: WitnessType) {
        let dummySignature = Data([UInt8].init(repeating: 0, count: Int(EC_SIGNATURE_DER_MAX_LOW_R_LEN)))
        self.init(type: type, signature: dummySignature, isDummy: true)
    }

    public func signed(signature: Data) -> Witness {
        Witness(type: type, signature: signature)
    }

    public var scriptCode: Data {
        switch type {
        case .payToWitnessPubKeyHash(let pubKey), .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
            var pubkey_hash_bytes = [UInt8](repeating: 0, count: Int(HASH160_LEN))
            pubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_hash160(buf.baseAddress, buf.count, &pubkey_hash_bytes, pubkey_hash_bytes.count) == WALLY_OK)
            }
            return try! Data(hex: "76a914") + Data(pubkey_hash_bytes) + Data(hex: "88ac")
        }
    }
}
