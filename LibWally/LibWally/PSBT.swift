//
//  PSBT.swift
//  PSBT
//
//  Created by Sjors Provoost on 16/12/2019.
//  Copyright © 2019 Sjors Provoost. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import CLibWally

public final class PSBT : Equatable {
    public let network: Network
    public let inputs: [PSBTInput]
    public let outputs: [PSBTOutput]
    public let wally_psbt: UnsafeMutablePointer<wally_psbt>

    deinit {
        wally_psbt_free(wally_psbt)
    }

    private static func clone(psbt: UnsafeMutablePointer<wally_psbt>) -> UnsafeMutablePointer<wally_psbt> {
        var new_psbt: UnsafeMutablePointer<wally_psbt>!
        precondition(wally_psbt_clone_alloc(psbt, 0, &new_psbt) == WALLY_OK)
        return new_psbt
    }

    public static func == (lhs: PSBT, rhs: PSBT) -> Bool {
        lhs.network == rhs.network && lhs.data == rhs.data
    }

    public init(psbt: UnsafeMutablePointer<wally_psbt>, network: Network) throws {
        self.network = network
        self.wally_psbt = Self.clone(psbt: psbt)
        var inputs: [PSBTInput] = []
        for i in 0 ..< wally_psbt.pointee.inputs_allocation_len {
            try inputs.append(PSBTInput(wally_psbt.pointee.inputs![i], network: network))
        }
        self.inputs = inputs
        var outputs: [PSBTOutput] = []
        for i in 0..<wally_psbt.pointee.outputs_allocation_len {
            try outputs.append(PSBTOutput(wally_psbt.pointee.outputs, tx: wally_psbt.pointee.tx!.pointee, index: i, network: network))
        }
        self.outputs = outputs
    }

    public convenience init (psbt: Data, network: Network) throws {
        var output: UnsafeMutablePointer<wally_psbt>?
        defer {
            wally_psbt_free(output)
        }
        try psbt.withUnsafeByteBuffer { buf in
            guard wally_psbt_from_bytes(buf.baseAddress, buf.count, &output) == WALLY_OK else {
                // libwally-core returns WALLY_EINVAL regardless of why parsing fails
                throw LibWallyError("Invalid PSBT.")
            }
        }
        precondition(output != nil)
        precondition(output!.pointee.tx != nil)
        try self.init(psbt: output!, network: network)
    }

    public convenience init (psbt: String, network: Network) throws {
        guard psbt.count != 0 else {
            throw LibWallyError("Invalid PSBT.")
        }

        guard let psbtData = Data(base64Encoded: psbt) else {
            throw LibWallyError("Invalid PSBT.")
        }

        try self.init(psbt: psbtData, network: network)
    }

    public var data: Data {
        var len = 0
        precondition(wally_psbt_get_length(wally_psbt, 0, &len) == WALLY_OK)
        var result = Data(repeating: 0, count: len)
        result.withUnsafeMutableBytes { resultBuffer in
            var written = 0
            precondition(wally_psbt_to_bytes(wally_psbt, 0, resultBuffer.bindMemory(to: UInt8.self).baseAddress, resultBuffer.count, &written) == WALLY_OK)
        }
        return result
    }

    public var description: String {
        return data.base64EncodedString()
    }

    public var isComplete: Bool {
        // TODO: add function to libwally-core to check this directly
        return self.transactionFinal != nil
    }

    public var transaction: Transaction {
        precondition(self.wally_psbt.pointee.tx != nil)
        return Transaction(tx: self.wally_psbt.pointee.tx!)
    }

    public var fee: Satoshi? {
        if let valueOut = self.transaction.totalOut {
            var tally: Satoshi = 0
            for input in self.inputs {
                guard input.isSegWit else {
                    return nil
                }
                guard let amount = input.amount else {
                    return nil
                }
                tally += amount
            }
            precondition(tally >= valueOut)
            return tally - valueOut
        }
        return nil
    }

    public var transactionFinal: Transaction? {
        var output: UnsafeMutablePointer<wally_tx>?
        defer {
            if let output = output {
                wally_tx_free(output)
            }
        }

        guard wally_psbt_extract(wally_psbt, &output) == WALLY_OK else {
            return nil
        }
        return Transaction(tx: output!)
    }

    public func signed(_ privKey: Key) throws -> PSBT {
        // TODO: sanity key for network
        let psbt = Self.clone(psbt: wally_psbt)
        defer {
            wally_psbt_free(psbt)
        }
        privKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_psbt_sign(psbt, buf.baseAddress, buf.count, 0) == WALLY_OK)
        }
        return try PSBT(psbt: psbt, network: network)
    }

    public func signed(_ hdKey: HDKey) throws -> PSBT {
        var psbt = self
        for input in self.inputs {
            if let origins: [PubKey : KeyOrigin] = input.canSign(hdKey) {
                for origin in origins {
                    if let childKey = try? hdKey.derive(origin.value.path) {
                        if let privKey = childKey.privKey {
                            precondition(privKey.pubKey == origin.key)
                            psbt = try psbt.signed(privKey)
                        }
                    }
                }
            }
        }
        return psbt
    }

    public func finalized() throws -> PSBT {
        let psbt = Self.clone(psbt: wally_psbt)
        defer {
            wally_psbt_free(psbt)
        }
        guard wally_psbt_finalize(psbt) == WALLY_OK else {
            throw LibWallyError("Unable to finalize.")
        }
        return try PSBT(psbt: psbt, network: network)
    }

}
