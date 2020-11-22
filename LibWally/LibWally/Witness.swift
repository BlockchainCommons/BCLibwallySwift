//
//  Witness.swift
//  LibWally
//
//  Created by Wolf McNally on 11/22/20.
//

import Foundation
import CLibWally

public struct Witness {
    var stack: UnsafeMutablePointer<wally_tx_witness_stack>?
    var isDummy: Bool = false

    let type: WitnessType

    public enum WitnessType {
        case payToWitnessPubKeyHash(PubKey) // P2WPKH (native SegWit)
        case payToScriptHashPayToWitnessPubKeyHash(PubKey) // P2SH-P2WPKH (wrapped SegWit)
    }

    public init (_ type: WitnessType, _ signature: Data) {
        self.type = type
        switch type {
        case .payToWitnessPubKeyHash(let pubKey):
            precondition(wally_tx_witness_stack_init_alloc(2, &self.stack) == WALLY_OK)
            let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
            let signature_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: signature.count + 1)
            (signature + sigHashByte).copyBytes(to: signature_bytes, count: signature.count + 1)
            let pubkey_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: pubKey.data.count)
            pubKey.data.copyBytes(to: pubkey_bytes, count: pubKey.data.count)

            precondition(wally_tx_witness_stack_set(self.stack!, 0, signature_bytes, signature.count + 1) == WALLY_OK)
            precondition(wally_tx_witness_stack_set(self.stack!, 1, pubkey_bytes, pubKey.data.count) == WALLY_OK)
        case .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
            precondition(wally_tx_witness_stack_init_alloc(2, &self.stack) == WALLY_OK)
            let sigHashByte = Data([UInt8(WALLY_SIGHASH_ALL)])
            let signature_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: signature.count + 1)
            (signature + sigHashByte).copyBytes(to: signature_bytes, count: signature.count + 1)
            let pubkey_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: pubKey.data.count)
            pubKey.data.copyBytes(to: pubkey_bytes, count: pubKey.data.count)

            precondition(wally_tx_witness_stack_set(self.stack!, 0, signature_bytes, signature.count + 1) == WALLY_OK)
            precondition(wally_tx_witness_stack_set(self.stack!, 1, pubkey_bytes, pubKey.data.count) == WALLY_OK)
        }
    }

    // Initialize without signature argument to get a dummy signature for fee calculation
    public init (_ type: WitnessType) {
        let dummySignature = Data([UInt8].init(repeating: 0, count: Int(EC_SIGNATURE_DER_MAX_LOW_R_LEN)))
        self.init(type, dummySignature)
        self.isDummy = true
    }

    func signed (_ signature: Data) -> Witness {
        return Witness(self.type, signature)
    }

    var scriptCode: Data {
        switch self.type {
        case .payToWitnessPubKeyHash(let pubKey), .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
            let pubkey_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: pubKey.data.count)
            pubKey.data.copyBytes(to: pubkey_bytes, count: pubKey.data.count)
            let pubkey_hash_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(HASH160_LEN))
            defer {
                pubkey_hash_bytes.deallocate()
            }
            precondition(wally_hash160(pubkey_bytes, pubKey.data.count, pubkey_hash_bytes, Int(HASH160_LEN)) == WALLY_OK)
            return try! Data(hex: "76a914") + Data(bytes: pubkey_hash_bytes, count: Int(HASH160_LEN)) + Data(hex: "88ac")
        }
    }
}
