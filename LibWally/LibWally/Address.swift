//
//  Address.swift
//  Address 
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import CLibWally

public enum AddressType {
    case payToPubKeyHash // P2PKH (legacy)
    case payToScriptHashPayToWitnessPubKeyHash // P2SH-P2WPKH (wrapped SegWit)
    case payToWitnessPubKeyHash // P2WPKH (native SegWit)
}

public protocol AddressProtocol {
    var scriptPubKey: ScriptPubKey { get }
}

public struct Address : AddressProtocol {
    public var network: Network
    public var scriptPubKey: ScriptPubKey
    var address: String
    
    public init(_ description: String) throws {
        self.address = description

        // base58 and bech32 use more bytes in string form, so description.count should be safe:
        var bytes_out = [UInt8](repeating: 0, count: description.count)
        var written = 0

        // Try if this is a bech32 Bitcoin mainnet address:
        var family: String = "bc"
        var result = wally_addr_segwit_to_bytes(description, family, 0, &bytes_out, description.count, &written)
        self.network = .mainnet

        if result != WALLY_OK {
            // Try if this is a bech32 Bitcoin testnet address:
            family = "tb"
            result = wally_addr_segwit_to_bytes(description, family, 0, &bytes_out, description.count, &written)
            self.network = .testnet
        }
        
        if result != WALLY_OK {
            // Try if this is a base58 addresses (P2PKH or P2SH)
            result = wally_address_to_scriptpubkey(description, UInt32(WALLY_NETWORK_BITCOIN_MAINNET), &bytes_out, description.count, &written)
            self.network = .mainnet
        }
        
        if result != WALLY_OK {
            // Try if this is a testnet base58 addresses (P2PKH or P2SH)
            result = wally_address_to_scriptpubkey(description, UInt32(WALLY_NETWORK_BITCOIN_TESTNET), &bytes_out, description.count, &written)
            self.network = .testnet
        }
        
        if result != WALLY_OK {
            throw LibWallyError("Invalid address.")
        }
        
        self.scriptPubKey = ScriptPubKey(Data(bytes: bytes_out, count: written))
    }
    
    init(_ hdKey: HDKey, _ type: AddressType) throws {
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
        try self.init(address) // libwally generated this string, so it's safe to force unwrap
    }
    
    public init(_ scriptPubKey: ScriptPubKey, _ network: Network) throws {
        self.network = network
        self.scriptPubKey = scriptPubKey
        switch scriptPubKey.type {
        case .payToPubKeyHash, .payToScriptHash:
            var output: UnsafeMutablePointer<Int8>?
            defer {
                wally_free_string(output)
            }
            scriptPubKey.bytes.withUnsafeByteBuffer { buf in
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
            scriptPubKey.bytes.withUnsafeByteBuffer { buf in
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
        return address
    }
}
