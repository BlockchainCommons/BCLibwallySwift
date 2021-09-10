//
//  Transaction.swift
//  Transaction
//
//  Created by Sjors Provoost on 18/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
@_implementationOnly import WolfBase

public struct Transaction {
    public let hash: Data?
    public let inputs: [TxInput]?
    public let outputs: [TxOutput]?

    private var storage: Storage

    private final class Storage {
        var tx: UnsafeMutablePointer<wally_tx>?

        init(tx: UnsafeMutablePointer<wally_tx>) {
            self.tx = tx
        }

        init() {
            self.tx = nil
        }

        deinit {
            wally_tx_free(tx)
        }
    }

    var tx: UnsafeMutablePointer<wally_tx>? {
        storage.tx
    }

    private static func clone(tx: UnsafeMutablePointer<wally_tx>) -> UnsafeMutablePointer<wally_tx> {
        var newTx: UnsafeMutablePointer<wally_tx>!
        precondition(wally_tx_clone_alloc(tx, 0, &newTx) == WALLY_OK)
        return newTx
    }

    private mutating func prepareForWrite() {
        if !isKnownUniquelyReferenced(&storage),
           let tx = storage.tx {
            storage.tx = Self.clone(tx: tx)
        }
    }

    init(tx: UnsafeMutablePointer<wally_tx>) {
        hash = nil
        inputs = nil
        outputs = nil
        storage = Storage(tx: Self.clone(tx: tx))
    }

    public init?(hex: String) {
        inputs = nil
        outputs = nil
        guard let data = Data(hex: hex) else {
            return nil
        }
        if data.count != SHA256_LEN { // Not a transaction hash
            var newTx: UnsafeMutablePointer<wally_tx>!
            let result = data.withUnsafeByteBuffer { buf in
                wally_tx_from_bytes(buf.baseAddress, buf.count, UInt32(WALLY_TX_FLAG_USE_WITNESS), &newTx)
            }
            guard result == WALLY_OK else {
                return nil
            }
            storage = Storage(tx: newTx)
            hash = nil
        } else { // 32 bytes, but not a valid transaction, so treat as a hash
            hash = Data(data.reversed())
            storage = Storage()
        }
    }

    public init(inputs: [TxInput], outputs: [TxOutput]) {
        self.hash = nil

        self.inputs = inputs
        self.outputs = outputs
        
        let version: UInt32 = 1
        let lockTime: UInt32 = 0

        var wtx: UnsafeMutablePointer<wally_tx>!
        precondition(wally_tx_init_alloc(version, lockTime, inputs.count, outputs.count, &wtx) == WALLY_OK)

        for input in inputs {
            precondition(wally_tx_add_input(wtx, input.createWallyInput()) == WALLY_OK)
        }

        for output in outputs {
            precondition(wally_tx_add_output(wtx, output.createWallyOutput()) == WALLY_OK)
        }

        storage = Storage(tx: wtx)
    }

    private init(inputs: [TxInput]?, outputs: [TxOutput]?, tx: UnsafeMutablePointer<wally_tx>) {
        self.hash = nil
        self.inputs = inputs
        self.outputs = outputs
        self.storage = Storage(tx: tx)
    }

    public var description: String? {
        guard let tx = tx else { return nil }

        // If we have TxInput objects, make sure they're all signed. Otherwise we've been initialized
        // from a hex string, so we'll just try to reserialize what we have.
        if let inputs = inputs {
            for input in inputs {
                if !input.isSigned {
                    return nil
                }
            }
        }
        
        var output: UnsafeMutablePointer<Int8>!
        defer {
            wally_free_string(output)
        }
        
        precondition(wally_tx_to_hex(tx, UInt32(WALLY_TX_FLAG_USE_WITNESS), &output) == WALLY_OK)
        return String(cString: output!)
    }

    var totalIn: Satoshi? {
        guard let inputs = inputs else { return nil }
        return inputs.reduce(0) {
            $0 + $1.amount
        }
    }
    
    var totalOut: Satoshi? {
        guard let tx = tx else { return nil }

        var value_out: UInt64 = 0
        precondition(wally_tx_get_total_output_satoshi(tx, &value_out) == WALLY_OK)
        
        return value_out;
    }
    
    var isFunded: Bool? {
        guard let totalOut = totalOut, let totalIn = totalIn else { return nil }
        return totalOut <= totalIn
    }
    
    public var vbytes: Int? {
        guard
            let tx = tx,
            let inputs = inputs
        else {
            return nil
        }

        let cloned_tx = Self.clone(tx: tx)
        defer {
            wally_tx_free(cloned_tx)
        }

        // Set scriptSig for all unsigned inputs to .feeWorstCase
        for (index, input) in inputs.enumerated() {
            if !input.isSigned {
                let scriptSig: ScriptSig?
                switch input.sig {
                case .scriptSig(let ss):
                    scriptSig = ss
                case .witness(let witness):
                    if witness.type == .payToScriptHashPayToWitnessPubKeyHash {
                        scriptSig = ScriptSig(type: .payToScriptHashPayToWitnessPubKeyHash(witness.pubKey))
                    } else {
                        scriptSig = nil
                    }
                }
                
                if let scriptSig = scriptSig {
                    let scriptSigWorstCase = scriptSig.render(purpose: .feeWorstCase)!
                    scriptSigWorstCase.data.withUnsafeByteBuffer { buf in
                        precondition(wally_tx_set_input_script(cloned_tx, index, buf.baseAddress, buf.count) == WALLY_OK)
                    }
                }
            }
        }
        
        var value_out = 0
        precondition(wally_tx_get_vsize(cloned_tx, &value_out) == WALLY_OK)
        return value_out;
    }
    
    public var fee: Satoshi? {
        guard let totalOut = totalOut, let totalIn = totalIn, totalIn >= totalOut else { return nil }
        return totalIn - totalOut
    }
    
    public var feeRate: Float64? {
        guard let fee = fee, let vbytes = vbytes else { return nil }
        precondition(vbytes > 0)
        return Float64(fee) / Float64(vbytes)
    }
    
    public func signed(with privKeys: [HDKey]) -> Transaction? {
        guard let tx = tx else {
            // No transaction to sign.
            return nil
        }
        guard let inputs = inputs else {
            // No inputs to sign.
            return nil
        }
        if privKeys.count != inputs.count {
            // Wrong number of keys to sign.
            return nil
        }

        let cloned_tx = Self.clone(tx: tx)

        var updatedInputs = inputs

        // Loop through inputs to sign:
        for i in 0 ..< inputs.count {
            var message_bytes = [UInt8](repeating: 0, count: Int(SHA256_LEN))

            switch inputs[i].sig {
            case .witness(let witness):
                switch witness.type {
                case .payToScriptHashPayToWitnessPubKeyHash:
                    let scriptSig = ScriptSig(type: .payToScriptHashPayToWitnessPubKeyHash(witness.pubKey)).render(purpose: .signed)!
                    scriptSig.data.withUnsafeByteBuffer { buf in
                        precondition(wally_tx_set_input_script(cloned_tx, i, buf.baseAddress, buf.count) == WALLY_OK)
                    }
                    
                    fallthrough
                case .payToWitnessPubKeyHash:
                    // Check that we're using the right public key:
                    let pubKeyData = Data(of: privKeys[i].wally_ext_key.pub_key)
                    precondition(witness.pubKey.data == pubKeyData)
                    
                    let script = witness.script
                    script.data.withUnsafeByteBuffer { buf in
                        precondition(wally_tx_get_btc_signature_hash(cloned_tx, i, buf.baseAddress, buf.count, inputs[i].amount, UInt32(WALLY_SIGHASH_ALL), UInt32(WALLY_TX_FLAG_USE_WITNESS), &message_bytes, Int(SHA256_LEN)) == WALLY_OK)
                    }
                }
            case .scriptSig:
                // Prep input for signing:
                let scriptPubKey = inputs[i].scriptPubKey.script.data
                scriptPubKey.withUnsafeByteBuffer { buf in
                    // Create hash for signing
                    precondition(wally_tx_get_btc_signature_hash(cloned_tx, i, buf.baseAddress, buf.count, 0, UInt32(WALLY_SIGHASH_ALL), 0, &message_bytes, Int(SHA256_LEN)) == WALLY_OK)
                }
            }

            var compact_sig_bytes = [UInt8](repeating: 0, count: Int(EC_SIGNATURE_LEN))

            // Sign hash using private key (without 0 prefix)
            precondition(EC_MESSAGE_HASH_LEN == SHA256_LEN)
            
            var data = Data(of: privKeys[i].wally_ext_key.priv_key)
            // skip prefix byte 0
            precondition(data.popFirst() != nil)
            let privKey = [UInt8](data)

            // Ensure private key is valid
            precondition(wally_ec_private_key_verify(privKey, Int(EC_PRIVATE_KEY_LEN)) == WALLY_OK)
        
            precondition(wally_ec_sig_from_bytes(privKey, Int(EC_PRIVATE_KEY_LEN), &message_bytes, Int(EC_MESSAGE_HASH_LEN), UInt32(EC_FLAG_ECDSA | EC_FLAG_GRIND_R), &compact_sig_bytes, Int(EC_SIGNATURE_LEN)) == WALLY_OK)
        
            // Check that signature is valid and for the correct public key:
            withUnsafeByteBuffer(of: privKeys[i].wally_ext_key.pub_key) { buf in
                precondition(wally_ec_sig_verify(buf.baseAddress, buf.count, &message_bytes, Int(EC_MESSAGE_HASH_LEN), UInt32(EC_FLAG_ECDSA), &compact_sig_bytes, Int(EC_SIGNATURE_LEN)) == WALLY_OK)
            }

            // Convert to low s form:
            var sig_norm_bytes = [UInt8](repeating: 0, count: Int(EC_SIGNATURE_LEN))
            precondition(wally_ec_sig_normalize(&compact_sig_bytes, Int(EC_SIGNATURE_LEN), &sig_norm_bytes, Int(EC_SIGNATURE_LEN)) == WALLY_OK)
            
            // Convert normalized signature to DER
            var sig_bytes = [UInt8](repeating: 0, count: Int(EC_SIGNATURE_DER_MAX_LEN))
            var sig_bytes_written = 0;
            precondition(wally_ec_sig_to_der(sig_norm_bytes, Int(EC_SIGNATURE_LEN), &sig_bytes, Int(EC_SIGNATURE_DER_MAX_LEN), &sig_bytes_written) == WALLY_OK)
            
            // Store signature in TxInput
            let signature =  Data(bytes: sig_bytes, count: sig_bytes_written)
            switch inputs[i].sig {
            case .witness(let witness):
                let witness = witness.signed(signature: signature)
                updatedInputs[i].sig = .witness(witness)
                precondition(wally_tx_set_input_witness(cloned_tx, i, witness.createWallyStack()) == WALLY_OK)
            case .scriptSig(var scriptSig):
                scriptSig.signature = signature
                updatedInputs[i].sig = .scriptSig(scriptSig)
                
                // Update scriptSig:
                let signedScriptSig = scriptSig.render(purpose: .signed)!
                signedScriptSig.data.withUnsafeByteBuffer { buf in
                    precondition(wally_tx_set_input_script(cloned_tx, i, buf.baseAddress, buf.count) == WALLY_OK)
                }
            }
        }

        return Transaction(inputs: updatedInputs, outputs: outputs, tx: cloned_tx)
    }

}
