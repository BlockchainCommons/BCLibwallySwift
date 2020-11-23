//
//  PSBTOutput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
import CLibWally

public struct PSBTOutput : Identifiable {
    public let txOutput: TxOutput
    public let origins: [PubKey: KeyOrigin]?

    public var id: String {
        self.txOutput.address! + String(self.txOutput.amount)
    }

    init(wallyPSBTOutput: wally_psbt_output, wallyTxOutput: wally_tx_output, network: Network) throws {
        if wallyPSBTOutput.keypaths.num_items > 0 {
            self.origins = try KeyOrigin.getOrigins(keypaths: wallyPSBTOutput.keypaths, network: network)
        } else {
            self.origins = nil
        }
        let scriptPubKey: ScriptPubKey
        if let scriptPubKeyBytes = wallyPSBTOutput.witness_script {
            scriptPubKey = ScriptPubKey(Data(bytes: scriptPubKeyBytes, count: wallyPSBTOutput.witness_script_len))
        } else {
            scriptPubKey = ScriptPubKey(Data(bytes: wallyTxOutput.script, count: wallyTxOutput.script_len))
        }

        self.txOutput = TxOutput(scriptPubKey: scriptPubKey, amount: wallyTxOutput.satoshi, network: network)
    }

    static func commonOriginChecks(origin: KeyOrigin, rootPathLength: Int, pubKey: PubKey, signer: HDKey, cosigners: [HDKey]) ->  Bool {
        // Check that origin ends with 0/* or 1/*
        let components = origin.path.components
        if components.count < 2 ||
                !(components.reversed()[1] == .normal(0) || components.reversed()[1] == .normal(1)) ||
            components.reversed()[0].isHardened
        {
            return false
        }

        // Find matching HDKey
        var hdKey: HDKey? = nil
        guard let signerMasterKeyFingerprint = signer.masterKeyFingerprint else {
            return false
        }
        if signerMasterKeyFingerprint == origin.fingerprint {
            hdKey = signer
        } else {
            for cosigner in cosigners {
                guard let cosignerMasterKeyFingerprint = cosigner.masterKeyFingerprint else {
                    return false
                }
                if cosignerMasterKeyFingerprint == origin.fingerprint {
                    hdKey = cosigner
                }
            }
        }

        guard hdKey != nil else {
            return false
        }

        // Check that origin pubkey is correct
        guard let childKey = try? hdKey!.derive(using: origin.path) else {
            return false
        }

        if childKey.pubKey != pubKey {
            return false
        }

        return true
    }

    public func isChange(signer: HDKey, inputs:[PSBTInput], cosigners: [HDKey], threshold: UInt) -> Bool {
        // Transaction must have at least one input
        if inputs.count < 1 {
            return false
        }

        // All inputs must have origin info
        for input in inputs {
            if input.origins == nil {
                return false
            }
        }

        // Skip key deriviation root
        let keyPath = inputs[0].origins!.first!.value.path
        if keyPath.components.count < 2 {
            return false
        }
        let keyPathRootLength = keyPath.components.count - 2

        for input in inputs {
            // Check that we can sign all inputs (TODO: relax assumption for e.g. coinjoin)
            if !input.canSign(with: signer) {
                return false
            }
            guard let origins = input.origins else {
                return false
            }

            for origin in origins {
                if !(PSBTOutput.commonOriginChecks(origin: origin.value, rootPathLength:keyPathRootLength, pubKey: origin.key, signer: signer, cosigners: cosigners)) {
                    return false
                }
            }
        }

        // Check outputs
        guard let origins = self.origins else {
            return false
        }

        var changeIndex: UInt32? = nil
        for origin in origins {
            if !(PSBTOutput.commonOriginChecks(origin: origin.value, rootPathLength:keyPathRootLength, pubKey: origin.key, signer: signer, cosigners: cosigners)) {
                return false
            }
            // Check that the output index is reasonable
            // When combined with the above constraints, change "hijacked" to an extreme index can
            // be covered by importing keys using Bitcoin Core's maximum range [0,999999].
            // This needs less than 1 GB of RAM, but is fairly slow.
            if case let .normal(i) = origin.value.path.components.reversed()[0] {
                if i > 999999 {
                    return false
                }
                // Change index must be the same for all origins
                if changeIndex != nil && i != changeIndex {
                    return false
                } else {
                    changeIndex = i
                }
            }
        }

        // Check scriptPubKey
        switch self.txOutput.scriptPubKey.type {
        case .multiSig:
            let expectedScriptPubKey = ScriptPubKey(multisig: Array(origins.keys), threshold: threshold)
            if self.txOutput.scriptPubKey != expectedScriptPubKey {
                return false
            }
        default:
            return false
        }
        return true
    }
}
