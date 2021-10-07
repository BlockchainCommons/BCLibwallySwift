//
//  PSBTInput.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation
@_implementationOnly import WolfBase

public struct PSBTInput {
    public let origins: [ECCompressedPublicKey: DerivationPath]
    public let signatures: [ECCompressedPublicKey: Data]
    public let witnessScript: Data?
    public let isSegwit: Bool
    public let amount: Satoshi?

    private static func getSignatures(signatures: wally_map) -> [ECCompressedPublicKey: Data] {
        var result: [ECCompressedPublicKey: Data] = [:]
        for i in 0 ..< signatures.num_items {
            let item = signatures.items[i]
            let pubKey = ECCompressedPublicKey(Data(bytes: item.key, count: Int(EC_PUBLIC_KEY_LEN)))!
            let sig = Data(bytes: item.value, count: Int(item.value_len))
            result[pubKey] = sig
        }
        return result
    }

    init(wallyInput: WallyPSBTInput) {
        if wallyInput.keypaths.num_items > 0 {
            self.origins = DerivationPath.getOrigins(keypaths: wallyInput.keypaths)
        } else {
            self.origins = [:]
        }

        if(wallyInput.signatures.num_items > 0) {
            self.signatures = Self.getSignatures(signatures: wallyInput.signatures)
        } else {
            self.signatures = [:]
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
    public func signableOrigins(with hdKey: HDKey) -> [ECCompressedPublicKey: DerivationPath] {
        var result: [ECCompressedPublicKey: DerivationPath] = [:]
        for origin in origins {
            guard let masterKeyFingerprint = hdKey.originFingerprint else {
                break
            }
            let path = origin.value
            guard
                let pathOrigin = path.origin,
                case .fingerprint(let originFingerprint) = pathOrigin
            else {
                continue
            }
            if masterKeyFingerprint == originFingerprint {
                if let childKey = try? HDKey(parent: hdKey, childDerivationPath: path) {
                    if childKey.ecPublicKey == origin.key {
                        result[origin.key] = origin.value
                    }
                }
            }
        }
        return result
    }

    public func canSign(with hdKey: HDKey) -> Bool {
        !signableOrigins(with: hdKey).isEmpty
    }
}

extension PSBTInput: CustomStringConvertible {
    public var description: String {
        "PSBTInput(origins: \(origins), signatures: \(signatures), witnessScript: \((witnessScript?.hex)†), isSegwit: \(isSegwit), amount: \(amount†))"
    }
}
