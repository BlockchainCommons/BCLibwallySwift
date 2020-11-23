//
//  TxInput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
import CLibWally

public struct TxInput {
    public let txHash: Data
    public let vout: UInt32
    public let sequence: UInt32
    public let amount: Satoshi
    public var scriptSig: ScriptSig?
    public var witness: Witness?
    public let scriptPubKey: ScriptPubKey

    // For P2SH wrapped SegWit, we set scriptSig automatically
    public init(txHash: Data, vout: UInt32, sequence: UInt32 = 0xffffffff, amount: Satoshi, scriptSig: ScriptSig?, witness: Witness?, scriptPubKey: ScriptPubKey) throws {
        self.txHash = txHash
        self.vout = vout
        self.sequence = sequence
        self.amount = amount

        if witness == nil {
            self.scriptSig = scriptSig
        } else {
            switch witness!.type {
            case .payToWitnessPubKeyHash(_):
                self.scriptSig = nil
            case .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
                self.scriptSig = ScriptSig(type: .payToScriptHashPayToWitnessPubKeyHash(pubKey))
            }
        }

        self.witness = witness
        self.scriptPubKey = scriptPubKey
    }

    public func createWallyInput() -> UnsafeMutablePointer<wally_tx_input> {
        var wti: UnsafeMutablePointer<wally_tx_input>?
        txHash.withUnsafeByteBuffer { hashBuf in
            precondition(wally_tx_input_init_alloc(hashBuf.baseAddress, hashBuf.count, vout, sequence, nil, 0, self.witness == nil ? nil : self.witness!.createWallyStack(), &wti) == WALLY_OK)
        }
        return wti!
    }

    public var isSigned: Bool {
        (self.scriptSig != nil && self.scriptSig!.signature != nil) || (self.witness != nil && !self.witness!.isDummy)
    }
}
