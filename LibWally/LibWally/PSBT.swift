//
//  PSBT.swift
//  PSBT
//
//  Created by Sjors Provoost on 16/12/2019.
//  Copyright © 2019 Sjors Provoost. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation

public struct PSBT : Equatable {
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

    private var _psbt: UnsafeMutablePointer<wally_psbt> {
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
        lhs.data == rhs.data
    }

    private init(ownedPSBT: UnsafeMutablePointer<wally_psbt>) {
        self.storage = Storage(psbt: ownedPSBT)

        var inputs: [PSBTInput] = []
        for i in 0 ..< ownedPSBT.pointee.inputs_allocation_len {
            inputs.append(PSBTInput(wallyInput: ownedPSBT.pointee.inputs![i]))
        }
        self.inputs = inputs

        var outputs: [PSBTOutput] = []
        for i in 0 ..< ownedPSBT.pointee.outputs_allocation_len {
            outputs.append(PSBTOutput(wallyPSBTOutput: ownedPSBT.pointee.outputs[i], wallyTxOutput: ownedPSBT.pointee.tx!.pointee.outputs[i]))
        }
        self.outputs = outputs
    }

    public init?(_ data: Data) {
        var output: UnsafeMutablePointer<wally_psbt>!
        let result = data.withUnsafeByteBuffer { buf in
            // libwally-core returns WALLY_EINVAL regardless of why parsing fails
            wally_psbt_from_bytes(buf.baseAddress, buf.count, &output)
        }
        guard result == WALLY_OK else {
            return nil
        }
        precondition(output.pointee.tx != nil)
        self.init(ownedPSBT: output)
    }

    public init?(base64 string: String) {
        guard string.count != 0 else {
            return nil
        }

        guard let psbtData = Data(base64Encoded: string) else {
            return nil
        }

        self.init(psbtData)
    }

    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.init(data)
    }

    public var data: Data {
        var len = 0
        precondition(wally_psbt_get_length(_psbt, 0, &len) == WALLY_OK)
        var result = Data(repeating: 0, count: len)
        result.withUnsafeMutableBytes { resultBuffer in
            var written = 0
            precondition(wally_psbt_to_bytes(_psbt, 0, resultBuffer.bindMemory(to: UInt8.self).baseAddress, resultBuffer.count, &written) == WALLY_OK)
        }
        return result
    }
    
    public var base64: String {
        data.base64EncodedString()
    }
    
    public var hex: String {
        data.hex
    }

    public var isFinalized: Bool {
        var result = 0
        precondition(wally_psbt_is_finalized(_psbt, &result) == WALLY_OK)
        return result != 0
    }

    public var transaction: Transaction {
        precondition(_psbt.pointee.tx != nil)
        return Transaction(tx: _psbt.pointee.tx!)
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

    public func finalizedTransaction() -> Transaction? {
        var output: UnsafeMutablePointer<wally_tx>!
        defer {
            wally_tx_free(output)
        }

        guard wally_psbt_extract(_psbt, &output) == WALLY_OK else {
            return nil
        }
        return Transaction(tx: output)
    }

    public func signed(with privKey: ECPrivateKey) -> PSBT? {
        // TODO: sanity key for network
        let clonedPSBT = Self.clone(psbt: self._psbt)
        privKey.data.withUnsafeByteBuffer { buf in
            precondition(wally_psbt_sign(clonedPSBT, buf.baseAddress, buf.count, 0) == WALLY_OK)
        }
        return PSBT(ownedPSBT: clonedPSBT)
    }

    public func signed(with hdKey: HDKey) -> PSBT? {
        var psbt: PSBT? = self
        for input in self.inputs {
            if let origins: [ECCompressedPublicKey : DerivationPath] = input.canSignOrigins(with: hdKey) {
                for origin in origins {
                    if let childKey = hdKey.derive(path: origin.value) {
                        if let privKey = childKey.privKey {
                            precondition(privKey.public == origin.key)
                            psbt = psbt?.signed(with: privKey)
                        }
                    }
                }
            }
        }
        return psbt
    }

    public func finalized() -> PSBT? {
        let clonedPSBT = Self.clone(psbt: _psbt)
        guard wally_psbt_finalize(clonedPSBT) == WALLY_OK else {
            return nil
        }
        return PSBT(ownedPSBT: clonedPSBT)
    }
}

extension PSBT: CustomStringConvertible {
    public var description: String {
        base64
    }
}
