//
//  PSBT.swift
//  PSBT
//
//  Created by Sjors Provoost on 16/12/2019.
//  Copyright © 2019 Sjors Provoost. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation

public struct PSBT : Equatable {
    public let network: Network
    public let inputs: [PSBTInput]
    public let outputs: [PSBTOutput]

    private var storage: Storage

    private final class Storage {
        var psbt: UnsafeMutablePointer<wally_psbt>

        init(psbt: UnsafeMutablePointer<wally_psbt>) {
            self.psbt = psbt
        }

        deinit {
            wally_psbt_free(psbt)
        }
    }

    var psbt: UnsafeMutablePointer<wally_psbt> {
        storage.psbt
    }

    private static func clone(psbt: UnsafeMutablePointer<wally_psbt>) -> UnsafeMutablePointer<wally_psbt> {
        var new_psbt: UnsafeMutablePointer<wally_psbt>!
        precondition(wally_psbt_clone_alloc(psbt, 0, &new_psbt) == WALLY_OK)
        return new_psbt
    }

    private mutating func prepareForWrite() {
        if !isKnownUniquelyReferenced(&storage) {
            storage.psbt = Self.clone(psbt: storage.psbt)
        }
    }

    public static func == (lhs: PSBT, rhs: PSBT) -> Bool {
        lhs.network == rhs.network && lhs.data == rhs.data
    }

    private init(ownedPSBT: UnsafeMutablePointer<wally_psbt>, network: Network) throws {
        self.network = network
        self.storage = Storage(psbt: ownedPSBT)

        var inputs: [PSBTInput] = []
        for i in 0 ..< ownedPSBT.pointee.inputs_allocation_len {
            try inputs.append(PSBTInput(wallyInput: ownedPSBT.pointee.inputs![i], network: network))
        }
        self.inputs = inputs

        var outputs: [PSBTOutput] = []
        for i in 0 ..< ownedPSBT.pointee.outputs_allocation_len {
            try outputs.append(PSBTOutput(wallyPSBTOutput: ownedPSBT.pointee.outputs[i], wallyTxOutput: ownedPSBT.pointee.tx!.pointee.outputs[i], network: network))
        }
        self.outputs = outputs
    }

    public init(psbt data: Data, network: Network) throws {
        var output: UnsafeMutablePointer<wally_psbt>!
        try data.withUnsafeByteBuffer { buf in
            guard wally_psbt_from_bytes(buf.baseAddress, buf.count, &output) == WALLY_OK else {
                // libwally-core returns WALLY_EINVAL regardless of why parsing fails
                throw LibWallyError("Invalid PSBT.")
            }
        }
        precondition(output.pointee.tx != nil)
        try self.init(ownedPSBT: output, network: network)
    }

    public init(psbt string: String, network: Network) throws {
        guard string.count != 0 else {
            throw LibWallyError("Invalid PSBT.")
        }

        guard let psbtData = Data(base64Encoded: string) else {
            throw LibWallyError("Invalid PSBT.")
        }

        try self.init(psbt: psbtData, network: network)
    }

    public var data: Data {
        var len = 0
        precondition(wally_psbt_get_length(psbt, 0, &len) == WALLY_OK)
        var result = Data(repeating: 0, count: len)
        result.withUnsafeMutableBytes { resultBuffer in
            var written = 0
            precondition(wally_psbt_to_bytes(psbt, 0, resultBuffer.bindMemory(to: UInt8.self).baseAddress, resultBuffer.count, &written) == WALLY_OK)
        }
        return result
    }

    public var description: String {
        data.base64EncodedString()
    }

    public var isComplete: Bool {
        // TODO: add function to libwally-core to check this directly
        self.transactionFinal != nil
    }

    public var transaction: Transaction {
        precondition(psbt.pointee.tx != nil)
        return Transaction(tx: psbt.pointee.tx!)
    }

    public var fee: Satoshi? {
        guard let valueOut = self.transaction.totalOut else { return nil }
        var tally: Satoshi = 0
        for input in self.inputs {
            guard input.isSegwit, let amount = input.amount else {
                return nil
            }
            tally += amount
        }
        precondition(tally >= valueOut)
        return tally - valueOut
    }

    public var transactionFinal: Transaction? {
        var output: UnsafeMutablePointer<wally_tx>!
        defer {
            wally_tx_free(output)
        }

        guard wally_psbt_extract(psbt, &output) == WALLY_OK else {
            return nil
        }
        return Transaction(tx: output)
    }

    public func signed(with privKey: Key) throws -> PSBT {
        // TODO: sanity key for network
        let clonedPSBT = Self.clone(psbt: self.psbt)
        privKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_psbt_sign(clonedPSBT, buf.baseAddress, buf.count, 0) == WALLY_OK)
        }
        return try PSBT(ownedPSBT: clonedPSBT, network: network)
    }

    public func signed(with hdKey: HDKey) throws -> PSBT {
        var psbt = self
        for input in self.inputs {
            if let origins: [PubKey : KeyOrigin] = input.canSignOrigins(with: hdKey) {
                for origin in origins {
                    if let childKey = try? hdKey.derive(using: origin.value.path) {
                        if let privKey = childKey.privKey {
                            precondition(privKey.pubKey == origin.key)
                            psbt = try psbt.signed(with: privKey)
                        }
                    }
                }
            }
        }
        return psbt
    }

    public func finalized() throws -> PSBT {
        let clonedPSBT = Self.clone(psbt: psbt)
        guard wally_psbt_finalize(clonedPSBT) == WALLY_OK else {
            throw LibWallyError("Unable to finalize.")
        }
        return try PSBT(ownedPSBT: clonedPSBT, network: network)
    }
}
