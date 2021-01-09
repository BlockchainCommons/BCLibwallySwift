//
//  Address.swift
//  Address 
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation

public enum AddressType {
    case payToPubKeyHash // P2PKH (legacy)
    case payToScriptHashPayToWitnessPubKeyHash // P2SH-P2WPKH (wrapped SegWit)
    case payToWitnessPubKeyHash // P2WPKH (native SegWit)
}

public protocol AddressProtocol {
    var scriptPubKey: ScriptPubKey { get }
}

public struct Address : AddressProtocol {
    public let network: Network
    public let scriptPubKey: ScriptPubKey
    let address: String
    
    public init(string: String) throws {
        self.address = string

        // base58 and bech32 use more bytes in string form, so description.count should be safe:
        var bytes_out = [UInt8](repeating: 0, count: string.count)
        var written = 0

        // Try if this is a bech32 Bitcoin mainnet address:
        var family: String = "bc"
        var result = wally_addr_segwit_to_bytes(string, family, 0, &bytes_out, string.count, &written)
        var network: Network = .mainnet

        if result != WALLY_OK {
            // Try if this is a bech32 Bitcoin testnet address:
            family = "tb"
            result = wally_addr_segwit_to_bytes(string, family, 0, &bytes_out, string.count, &written)
            network = .testnet
        }
        
        if result != WALLY_OK {
            // Try if this is a base58 addresses (P2PKH or P2SH)
            result = wally_address_to_scriptpubkey(string, UInt32(WALLY_NETWORK_BITCOIN_MAINNET), &bytes_out, string.count, &written)
            network = .mainnet
        }
        
        if result != WALLY_OK {
            // Try if this is a testnet base58 addresses (P2PKH or P2SH)
            result = wally_address_to_scriptpubkey(string, UInt32(WALLY_NETWORK_BITCOIN_TESTNET), &bytes_out, string.count, &written)
            network = .testnet
        }

        self.network = network
        
        if result != WALLY_OK {
            throw LibWallyError("Invalid address.")
        }
        
        self.scriptPubKey = ScriptPubKey(Data(bytes: bytes_out, count: written))
    }
    
    init(hdKey: HDKey, type: AddressType) throws {
        let wally_type: Int32 = {
            switch type {
            case .payToPubKeyHash:
                return WALLY_ADDRESS_TYPE_P2PKH
            case .payToScriptHashPayToWitnessPubKeyHash:
                return WALLY_ADDRESS_TYPE_P2SH_P2WPKH
            case .payToWitnessPubKeyHash:
                return WALLY_ADDRESS_TYPE_P2WPKH
            }
        }()

        var key = hdKey.wally_ext_key
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        
        if wally_type == WALLY_ADDRESS_TYPE_P2PKH || wally_type == WALLY_ADDRESS_TYPE_P2SH_P2WPKH {
            var version: UInt32
            switch hdKey.network {
            case .mainnet:
                version = wally_type == WALLY_ADDRESS_TYPE_P2PKH ? 0x00 : 0x05
            case .testnet:
                version = wally_type == WALLY_ADDRESS_TYPE_P2PKH ? 0x6F : 0xC4
            }
            precondition(wally_bip32_key_to_address(&key, UInt32(wally_type), version, &output) == WALLY_OK)
            precondition(output != nil)
        } else {
            precondition(wally_type == WALLY_ADDRESS_TYPE_P2WPKH)
            var family: String
            switch hdKey.network {
            case .mainnet:
                family = "bc"
            case .testnet:
                family = "tb"
            }
            precondition(wally_bip32_key_to_addr_segwit(&key, family, 0, &output) == WALLY_OK)
            precondition(output != nil)
        }
        
        let address = String(cString: output!)
        
        // TODO: get scriptPubKey directly from libwally (requires a new function) instead parsing the string
        try self.init(string: address) // libwally generated this string, so it's safe to force unwrap
    }
    
    public init(scriptPubKey: ScriptPubKey, network: Network) throws {
        self.network = network
        self.scriptPubKey = scriptPubKey
        switch scriptPubKey.type {
        case .payToPubKeyHash, .payToScriptHash:
            var output: UnsafeMutablePointer<Int8>?
            defer {
                wally_free_string(output)
            }
            scriptPubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_scriptpubkey_to_address(buf.baseAddress, buf.count, UInt32(network == .mainnet ? WALLY_NETWORK_BITCOIN_MAINNET : WALLY_NETWORK_BITCOIN_TESTNET), &output) == WALLY_OK)
            }
            precondition(output != nil)
            self.address = String(cString: output!)
        case .payToWitnessPubKeyHash, .payToWitnessScriptHash:
            var family: String
            switch network {
            case .mainnet:
              family = "bc"
            case .testnet:
              family = "tb"
            }
            var output: UnsafeMutablePointer<Int8>?
            defer {
                wally_free_string(output)
            }
            scriptPubKey.data.withUnsafeByteBuffer { buf in
                precondition(wally_addr_segwit_from_bytes(buf.baseAddress, buf.count, family, 0, &output) == WALLY_OK)
            }
            precondition(output != nil)
            self.address = String(cString: output!)
        case .multiSig:
            var family: String
            switch network {
            case .mainnet:
                family = "bc"
            case .testnet:
                family = "tb"
            }
            var output: UnsafeMutablePointer<Int8>?
            defer {
                wally_free_string(output)
            }

            scriptPubKey.witnessProgram.withUnsafeByteBuffer { buf in
                precondition(wally_addr_segwit_from_bytes(buf.baseAddress, buf.count, family, 0, &output) == WALLY_OK)
            }

            if let words_c_string = output {
                self.address = String(cString: words_c_string)
            } else {
                throw LibWallyError("Invalid address.")
            }
        default:
            throw LibWallyError("Invalid address.")
        }
    }
    
    public var description: String {
        address
    }
}
