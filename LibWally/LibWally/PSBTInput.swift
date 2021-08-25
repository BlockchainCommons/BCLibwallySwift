//
//  PSBTInput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation

public struct PSBTInput {
    public let origins: [PubKey: KeyOrigin]?
    public let signatures: [PubKey: Data]?
    public let witnessScript: Data?
    public let isSegwit: Bool
    public let amount: Satoshi?

    private static func getSignatures(signatures: wally_map) throws -> [PubKey: Data] {
        var result: [PubKey: Data] = [:]
        for i in 0 ..< signatures.num_items {
            let item = signatures.items[i]
            let pubKey = try PubKey(Data(bytes: item.key, count: Int(EC_PUBLIC_KEY_LEN)))
            let sig = Data(bytes: item.value, count: Int(item.value_len))
            result[pubKey] = sig
        }
        return result
    }

    init(wallyInput: wally_psbt_input) throws {
        if wallyInput.keypaths.num_items > 0 {
            self.origins = try KeyOrigin.getOrigins(keypaths: wallyInput.keypaths)
        } else {
            self.origins = nil
        }

        if(wallyInput.signatures.num_items > 0) {
            self.signatures = try Self.getSignatures(signatures: wallyInput.signatures)
        } else {
            self.signatures = nil
        }

        if let witnessScript = wallyInput.witness_script {
            self.witnessScript = Data(bytes: witnessScript, count: wallyInput.witness_script_len)
        } else {
            self.witnessScript = nil
        }

        if let witness_utxo = wallyInput.witness_utxo {
            isSegwit = true
            amount = witness_utxo.pointee.satoshi
        } else {
            isSegwit = false
            amount = nil
        }
    }

    // Can we provide at least one signature, assuming we have the private key?
    public func canSignOrigins(with hdKey: HDKey) -> [PubKey: KeyOrigin]? {
        var result: [PubKey: KeyOrigin] = [:]
        if let origins = self.origins {
            for origin in origins {
                guard let masterKeyFingerprint = hdKey.masterKeyFingerprint else {
                    break
                }
                if masterKeyFingerprint == origin.value.fingerprint {
                    if let childKey = try? hdKey.derive(using: origin.value.path) {
                        if childKey.pubKey == origin.key {
                            result[origin.key] = origin.value
                        }
                    }
                }
            }
        }
        if result.count == 0 { return nil }
        return result
    }

    public func canSign(with hdKey: HDKey) -> Bool {
        canSignOrigins(with: hdKey) != nil
    }
}
