//
//  TxOutput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation

public struct TxOutput {
    public let scriptPubKey: ScriptPubKey
    public var amount: Satoshi
    public let network: Network

    public var address: String? {
        try? Address(scriptPubKey: self.scriptPubKey, network: self.network).description
    }

    public init (scriptPubKey: ScriptPubKey, amount: Satoshi, network: Network) {
        self.scriptPubKey = scriptPubKey
        self.amount = amount
        self.network = network
    }

    public func createWallyOutput() -> UnsafeMutablePointer<wally_tx_output> {
        var output: UnsafeMutablePointer<wally_tx_output>!
        scriptPubKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_tx_output_init_alloc(amount, buf.baseAddress, buf.count, &output) == WALLY_OK)
        }
        return output
    }
}
