//
//  PSBTInput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
import CLibWally

public struct PSBTInput {
    let wally_psbt_input: wally_psbt_input
    public let origins: [PubKey: KeyOrigin]?
    public let signatures: [PubKey: Data]?
    public let witnessScript: Data?

    private static func getSignatures(signatures: wally_map, network: Network) throws -> [PubKey: Data] {
        var result: [PubKey: Data] = [:]
        for i in 0 ..< signatures.num_items {
            let item = signatures.items[i]
            let pubKey = try PubKey(Data(bytes: item.key, count: Int(EC_PUBLIC_KEY_LEN)), network)
            let sig = Data(bytes: item.value, count: Int(item.value_len))
            result[pubKey] = sig
        }
        return result
    }

    init(_ wally_psbt_input: wally_psbt_input, network: Network) throws {
        self.wally_psbt_input = wally_psbt_input
        if wally_psbt_input.keypaths.num_items > 0 {
            self.origins = try KeyOrigin.getOrigins(keypaths: wally_psbt_input.keypaths, network: network)
        } else {
            self.origins = nil
        }

        if(wally_psbt_input.signatures.num_items > 0) {
            self.signatures = try Self.getSignatures(signatures: wally_psbt_input.signatures, network: network)
        } else {
            self.signatures = nil
        }

        if let witnessScript = wally_psbt_input.witness_script {
            self.witnessScript = Data(bytes: witnessScript, count: wally_psbt_input.witness_script_len)
        } else {
            self.witnessScript = nil
        }
    }

    // Can we provide at least one signature, assuming we have the private key?
    public func canSign(_ hdKey: HDKey) -> [PubKey: KeyOrigin]? {
        var result: [PubKey: KeyOrigin] = [:]
        if let origins = self.origins {
            for origin in origins {
                guard let masterKeyFingerprint = hdKey.masterKeyFingerprint else {
                    break
                }
                if masterKeyFingerprint == origin.value.fingerprint {
                    if let childKey = try? hdKey.derive(origin.value.path) {
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

    public func canSign(_ hdKey: HDKey) -> Bool {
        return canSign(hdKey) != nil
    }

    public var isSegWit: Bool {
        return self.wally_psbt_input.witness_utxo != nil
    }

    public var amount: Satoshi? {
        if let witness_utxo = self.wally_psbt_input.witness_utxo {
            return witness_utxo.pointee.satoshi
        }
        return nil
    }
}
