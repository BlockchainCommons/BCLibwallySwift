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
        var psbt: WallyPSBT

        init(psbt: WallyPSBT) {
            self.psbt = psbt
        }

        deinit {
            Wally.free(psbt: psbt)
        }
    }

    private var _psbt: WallyPSBT {
        storage.psbt
    }

    private static func clone(psbt: WallyPSBT) -> WallyPSBT {
        Wally.clone(psbt: psbt)
    }

    private mutating func prepareForWrite() {
        if !isKnownUniquelyReferenced(&storage) {
            storage.psbt = Self.clone(psbt: storage.psbt)
        }
    }

    public static func == (lhs: PSBT, rhs: PSBT) -> Bool {
        lhs.data == rhs.data
    }

    private init(ownedPSBT: WallyPSBT) {
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
        guard let psbt = Wally.psbt(from: data) else {
            return nil
        }
        precondition(psbt.pointee.tx != nil)
        self.init(ownedPSBT: psbt)
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
        return Wally.serialized(psbt: _psbt)
    }
    
    public var base64: String {
        data.base64EncodedString()
    }
    
    public var hex: String {
        data.hex
    }

    public var isFinalized: Bool {
        Wally.isFinalized(psbt: _psbt)
    }

    public var transaction: Transaction {
        precondition(_psbt.pointee.tx != nil)
        return Transaction(tx: _psbt.pointee.tx!)
    }

    public var fee: Satoshi? {
        guard let valueOut = self.transaction.totalOut else {
            return nil
        }
        let tally = inputs.reduce(into: Satoshi(0)) { (total, input) in
            guard input.isSegwit, let amount = input.amount else {
                return
            }
            total += amount
        }
        precondition(tally >= valueOut)
        return tally - valueOut
    }

    public func finalizedTransaction() -> Transaction? {
        Wally.finalizedTransaction(psbt: _psbt)
    }

    public func signed(with privKey: ECPrivateKey) -> PSBT? {
        guard let signedPSBT = Wally.signed(psbt: _psbt, ecPrivateKey: privKey.data) else {
            return nil
        }
        return PSBT(ownedPSBT: signedPSBT)
    }

    public func signed(with hdKey: HDKey) -> PSBT? {
        var psbt = self
        for input in self.inputs {
            for origin in input.signableOrigins(with: hdKey) {
                if
                    let childKey = hdKey.derive(path: origin.value),
                    let privKey = childKey.ecPrivateKey,
                    privKey.public == origin.key,
                    let signedPSBT = psbt.signed(with: privKey)
                {
                    psbt = signedPSBT
                }
            }
        }
        guard self != psbt else {
            return nil
        }
        return psbt
    }

    public func finalized() -> PSBT? {
        guard let psbt = Wally.finalized(psbt: _psbt) else {
            return nil
        }
        return PSBT(ownedPSBT: psbt)
    }
}

extension PSBT: CustomStringConvertible {
    public var description: String {
        base64
    }
}
