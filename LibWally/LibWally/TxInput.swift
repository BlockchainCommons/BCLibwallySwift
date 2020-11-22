//
//  TxInput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
import CLibWally

public final class TxInput {
    let wally_tx_input: UnsafeMutablePointer<wally_tx_input>

    let transaction: Transaction
    public var vout: UInt32 {
        return self.wally_tx_input.pointee.index
    }
    public var sequence: UInt32 {
        return self.wally_tx_input.pointee.sequence
    }
    public let scriptPubKey: ScriptPubKey
    public var scriptSig: ScriptSig?
    public var witness: Witness?
    public let amount: Satoshi

    deinit {
        wally_tx_input_free(wally_tx_input)
    }

    // For P2SH wrapped SegWit, we set scriptSig automatically
    public init(_ tx: Transaction, _ vout: UInt32, _ amount: Satoshi, _ scriptSig: ScriptSig?, _ witness: Witness?, _ scriptPubKey: ScriptPubKey) throws {
        if tx.hash == nil {
            throw LibWallyError("Invalid transaction.")
        }

        self.witness = witness

        if witness == nil {
            self.scriptSig = scriptSig
        } else {
            switch witness!.type {
            case .payToWitnessPubKeyHash(_):
                self.scriptSig = nil
            case .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
                self.scriptSig = ScriptSig(.payToScriptHashPayToWitnessPubKeyHash(pubKey))
            }
        }

        self.scriptPubKey = scriptPubKey
        self.amount = amount
        let sequence: UInt32 = 0xFFFFFFFF
        self.transaction = tx

        let tx_hash_bytes = UnsafeMutablePointer<UInt8>.allocate(capacity: tx.hash!.count)
        let tx_hash_bytes_len = tx.hash!.count

        tx.hash!.copyBytes(to: tx_hash_bytes, count: tx_hash_bytes_len)

        var wti: UnsafeMutablePointer<wally_tx_input>?

        let result = wally_tx_input_init_alloc(tx_hash_bytes, tx_hash_bytes_len, vout, sequence, nil, 0, self.witness == nil ? nil : self.witness!.stack!, &wti)
        precondition(result == WALLY_OK)

        self.wally_tx_input = wti!
    }

    public var isSigned: Bool {
        return (self.scriptSig != nil && self.scriptSig!.signature != nil) || (self.witness != nil && !self.witness!.isDummy)
    }
}
