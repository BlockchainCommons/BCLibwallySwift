//
//  TxOutput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
import CLibWally

public final class TxOutput {
    let wally_tx_output: UnsafeMutablePointer<wally_tx_output>

    deinit {
        wally_tx_output_free(wally_tx_output)
    }

    private static func clone(txo: UnsafeMutablePointer<wally_tx_output>) -> UnsafeMutablePointer<wally_tx_output> {
        var output: UnsafeMutablePointer<wally_tx_output>?
        wally_tx_output_clone_alloc(txo, &output)
        return output!
    }

    public let network: Network
    public var amount: Satoshi {
        return self.wally_tx_output.pointee.satoshi
    }
    public let scriptPubKey: ScriptPubKey
    public var address: String? {
        try? Address(self.scriptPubKey, self.network).description
    }

    public init (_ scriptPubKey: ScriptPubKey, _ amount: Satoshi, _ network: Network) {
        self.network = network
        self.scriptPubKey = scriptPubKey

        var output: UnsafeMutablePointer<wally_tx_output>?
        scriptPubKey.bytes.withUnsafeByteBuffer { buf in
            precondition(wally_tx_output_init_alloc(amount, buf.baseAddress, buf.count, &output) == WALLY_OK)
        }
        self.wally_tx_output = output!
    }

    public init (tx_output: UnsafeMutablePointer<wally_tx_output>, scriptPubKey: ScriptPubKey, network: Network) {
        self.network = network
        self.wally_tx_output = Self.clone(txo: tx_output)
        self.scriptPubKey = scriptPubKey
    }
}
