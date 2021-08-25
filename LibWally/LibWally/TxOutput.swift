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

    public func address(network: Network) -> String? {
        try? Address(scriptPubKey: self.scriptPubKey, network: network).description
    }

    public init (scriptPubKey: ScriptPubKey, amount: Satoshi) {
        self.scriptPubKey = scriptPubKey
        self.amount = amount
    }

    public func createWallyOutput() -> UnsafeMutablePointer<wally_tx_output> {
        var output: UnsafeMutablePointer<wally_tx_output>!
        scriptPubKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_tx_output_init_alloc(amount, buf.baseAddress, buf.count, &output) == WALLY_OK)
        }
        return output
    }
}
