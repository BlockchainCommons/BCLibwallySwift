//
//  Transaction.swift
//  Transaction
//
//  Created by Sjors Provoost on 18/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import CLibWally

public final class Transaction {
    let hash: Data?
    let wally_tx: UnsafeMutablePointer<wally_tx>?
    let inputs: [TxInput]?
    let outputs: [TxOutput]?

    deinit {
        if let wally_tx = wally_tx {
            wally_tx_free(wally_tx)
        }
    }

    private static func clone(tx: UnsafeMutablePointer<wally_tx>) -> UnsafeMutablePointer<wally_tx> {
        var new_tx: UnsafeMutablePointer<wally_tx>!
        precondition(wally_tx_clone_alloc(tx, 0, &new_tx) == WALLY_OK)
        return new_tx
    }

    init(tx: UnsafeMutablePointer<wally_tx>) {
        hash = nil
        inputs = nil
        outputs = nil
        wally_tx = Self.clone(tx: tx)
    }

    public init(hex: String) throws {
        inputs = nil
        outputs = nil
        let data = try Data(hex: hex)
        if data.count != SHA256_LEN { // Not a transaction hash
            hash = nil
            wally_tx = try data.withUnsafeByteBuffer { buf in
                var tx: UnsafeMutablePointer<wally_tx>?
                guard wally_tx_from_bytes(buf.baseAddress, buf.count, UInt32(WALLY_TX_FLAG_USE_WITNESS), &tx) == WALLY_OK else {
                    throw LibWallyError("Invalid transaction.")
                }
                return tx!
            }
        } else { // 32 bytes, but not a valid transaction, so treat as a hash
            hash = Data(data.reversed())
            wally_tx = nil
        }
    }
    
    public init(inputs: [TxInput], outputs: [TxOutput]) {
        self.hash = nil

        self.inputs = inputs
        self.outputs = outputs
        
        let version: UInt32 = 1
        let lockTime: UInt32 = 0
        
        var wtx: UnsafeMutablePointer<wally_tx>?
        precondition(wally_tx_init_alloc(version, lockTime, inputs.count, outputs.count, &wtx) == WALLY_OK)
        precondition(wtx != nil)
        
        for input in inputs {
            precondition(wally_tx_add_input(wtx, input.wally_tx_input) == WALLY_OK)
        }
        
        for output in outputs {
            precondition(wally_tx_add_output(wtx, output.wally_tx_output) == WALLY_OK)
        }

        self.wally_tx = wtx
    }

    private init(inputs: [TxInput]?, outputs: [TxOutput]?, tx: UnsafeMutablePointer<wally_tx>) {
        self.hash = nil
        self.inputs = inputs
        self.outputs = outputs
        self.wally_tx = tx
    }
    
    public var description: String? {
        if wally_tx == nil {
            return nil
        }
        // If we have TxInput objects, make sure they're all signed. Otherwise we've been initialized
        // from a hex string, so we'll just try to reserialize what we have.
        if inputs != nil {
            for input in inputs! {
                if !input.isSigned {
                    return nil
                }
            }
        }
        
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        
        precondition(wally_tx_to_hex(wally_tx, UInt32(WALLY_TX_FLAG_USE_WITNESS), &output) == WALLY_OK)
        precondition(output != nil)
        return String(cString: output!)
    }

    var totalIn: Satoshi? {
        var tally: Satoshi = 0
        if let inputs = inputs {
            for input in inputs {
                tally += input.amount
            }
        } else {
            return nil
        }
        
        return tally
    }
    
    var totalOut: Satoshi? {
        if wally_tx == nil {
            return nil
        }

        var value_out: UInt64 = 0
        precondition(wally_tx_get_total_output_satoshi(wally_tx, &value_out) == WALLY_OK)
        
        return value_out;
    }
    
    var isFunded: Bool? {
        if let totalOut = totalOut {
            if let totalIn = totalIn {
                return totalOut <= totalIn
            }
        }
        return nil
    }
    
    public var vbytes: Int? {
        if wally_tx == nil {
            return nil
        }
        
        precondition(inputs != nil)

        let cloned_tx = Self.clone(tx: wally_tx!)
        defer {
            wally_tx_free(cloned_tx)
        }

        // Set scriptSig for all unsigned inputs to .feeWorstCase
        for (index, input) in inputs!.enumerated() {
            if !input.isSigned {
                if let scriptSig = input.scriptSig {
                    let scriptSigWorstCase = scriptSig.render(.feeWorstCase)!
                    scriptSigWorstCase.withUnsafeByteBuffer { buf in
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
        if let totalOut = totalOut {
            if let totalIn = totalIn {
                if totalIn >= totalOut {
                    return totalIn - totalOut
                }
            }
        }
        return nil
    }
    
    public var feeRate: Float64? {
        if let fee = fee {
            if let vbytes = vbytes {
                precondition(vbytes > 0)
                return Float64(fee) / Float64(vbytes)
            }
        }
        return nil
    }
    
    public func signed(_ privKeys: [HDKey]) throws -> Transaction {
        if wally_tx == nil {
            throw LibWallyError("No transaction to sign.")
        }
        precondition(inputs != nil)
        if privKeys.count != inputs!.count {
            throw LibWallyError("Wrong number of keys to sign.")
        }

        let cloned_tx = Self.clone(tx: wally_tx!)

        let updatedInputs = inputs!

        // Loop through inputs to sign:
        for i in 0 ..< inputs!.count {
            let hasWitness = inputs![i].witness != nil

            var message_bytes = [UInt8](repeating: 0, count: Int(SHA256_LEN))

            if hasWitness {
                switch inputs![i].witness!.type {
                case .payToScriptHashPayToWitnessPubKeyHash(let pubKey):
                    let scriptSig = inputs![i].scriptSig!.render(.signed)!
                    scriptSig.withUnsafeByteBuffer { buf in
                        precondition(wally_tx_set_input_script(cloned_tx, i, buf.baseAddress, buf.count) == WALLY_OK)
                    }

                    fallthrough
                case .payToWitnessPubKeyHash(let pubKey):
                    // Check that we're using the right public key:
                    let pubKeyData = Data(of: privKeys[i].wally_ext_key.pub_key)
                    precondition(pubKey.data == pubKeyData)
                    
                    let scriptCode = inputs![i].witness!.scriptCode
                    scriptCode.withUnsafeByteBuffer { buf in
                        precondition(wally_tx_get_btc_signature_hash(cloned_tx, i, buf.baseAddress, buf.count, inputs![i].amount, UInt32(WALLY_SIGHASH_ALL), UInt32(WALLY_TX_FLAG_USE_WITNESS), &message_bytes, Int(SHA256_LEN)) == WALLY_OK)
                    }
                }
            } else {
                // Prep input for signing:
                let scriptPubKey = inputs![i].scriptPubKey.bytes
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
            if hasWitness {
                let witness = inputs![i].witness!.signed(signature)
                updatedInputs[i].witness = witness
                precondition(wally_tx_set_input_witness(cloned_tx, i, witness.stack!) == WALLY_OK)
            } else {
                updatedInputs[i].scriptSig!.signature = signature
                
                // Update scriptSig:
                let signedScriptSig = updatedInputs[i].scriptSig!.render(.signed)!
                signedScriptSig.withUnsafeByteBuffer { buf in
                    precondition(wally_tx_set_input_script(cloned_tx, i, buf.baseAddress, buf.count) == WALLY_OK)
                }
            }
        }

        return Transaction(inputs: updatedInputs, outputs: outputs, tx: cloned_tx)
    }

}
