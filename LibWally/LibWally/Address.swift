//
//  Address.swift
//  Address 
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation

public struct Address {
    public let network: Network
    public let scriptPubKey: ScriptPubKey
    let address: String
    
    public init?(string: String) {
        self.address = string

        // Try if this is a bech32 Bitcoin mainnet address:
        if let scriptPubKey = Wally.segwitAddressToScriptPubKey(address: string, network: .mainnet) {
            self.network = .mainnet
            self.scriptPubKey = scriptPubKey
            return
        }
        
        // Try if this is a bech32 Bitcoin testnet address:
        if let scriptPubKey = Wally.segwitAddressToScriptPubKey(address: string, network: .testnet) {
            self.network = .testnet
            self.scriptPubKey = scriptPubKey
            return
        }

        // Try if this is a base58 addresses (P2PKH or P2SH)
        if let scriptPubKey = Wally.addressToScriptPubKey(address: string, network: .mainnet) {
            self.network = .mainnet
            self.scriptPubKey = scriptPubKey
            return
        }

        // Try if this is a testnet base58 addresses (P2PKH or P2SH)
        if let scriptPubKey = Wally.addressToScriptPubKey(address: string, network: .testnet) {
            self.network = .testnet
            self.scriptPubKey = scriptPubKey
            return
        }
        
        return nil
    }
    
    init?(hdKey: HDKey, type: AddressType) {
        let address = Wally.hdKeyToAddress(hdKey: hdKey, type: type)
        // TODO: get scriptPubKey directly from libwally (requires a new function) instead parsing the string
        self.init(string: address) // libwally generated this string, so it's safe to force unwrap
    }
    
    public init?(scriptPubKey: ScriptPubKey, network: Network) {
        self.network = network
        self.scriptPubKey = scriptPubKey
        switch scriptPubKey.type {
        case .payToPubKeyHash, .payToScriptHash:
            self.address = Wally.address(from: scriptPubKey, network: network)
        case .payToWitnessPubKeyHash, .payToWitnessScriptHash:
            self.address = Wally.segwitAddress(scriptPubKey: scriptPubKey, network: network)
        case .multiSig:
            self.address = Wally.segwitAddress(script: scriptPubKey.witnessProgram, network: network)
        default:
            return nil
        }
    }
    
    public var description: String {
        address
    }

    public enum AddressType {
        case payToPubKeyHash // P2PKH (legacy)
        case payToScriptHashPayToWitnessPubKeyHash // P2SH-P2WPKH (wrapped SegWit)
        case payToWitnessPubKeyHash // P2WPKH (native SegWit)
        
        var wallyType: UInt32 {
            switch self {
            case .payToPubKeyHash:
                return UInt32(WALLY_ADDRESS_TYPE_P2PKH)
            case .payToScriptHashPayToWitnessPubKeyHash:
                return UInt32(WALLY_ADDRESS_TYPE_P2SH_P2WPKH)
            case .payToWitnessPubKeyHash:
                return UInt32(WALLY_ADDRESS_TYPE_P2WPKH)
            }
        }
    }
}
