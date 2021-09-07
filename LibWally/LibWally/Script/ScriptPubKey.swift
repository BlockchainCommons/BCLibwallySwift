//
//  ScriptPubKey.swift
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation

public struct ScriptPubKey : Equatable {
    public let script: Script

    public enum ScriptType {
        case opReturn // OP_RETURN
        case payToPubKeyHash // P2PKH (legacy)
        case payToScriptHash // P2SH (could be wrapped SegWit)
        case payToWitnessPubKeyHash // P2WPKH (native SegWit)
        case payToWitnessScriptHash // P2WS (native SegWit script)
        case multiSig
    }

    public var type: ScriptType? {
        Wally.getType(from: self)
    }

    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self.script = Script(data)
    }
    
    public init(multisig pubKeys: [ECCompressedPublicKey], threshold: UInt, isBIP67: Bool = true) {
        self = Wally.multisigScriptPubKey(pubKeys: pubKeys, threshold: threshold, isBIP67: isBIP67)
    }

    public init(_ script: Script) {
        self.script = script
    }

    public var witnessProgram: Script {
        Wally.witnessProgram(scriptPubKey: self)
    }
}

extension ScriptPubKey: CustomStringConvertible {
    public var description: String {
        let t: String
        if let type = type {
            t = String(describing: type)
        } else {
            t = "unknown"
        }
        return "\(t):\(script.description)"
    }
}
