//
//  BIP39.swift
//  LibWally
//
//  Created by Sjors on 27/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md.
//

import Foundation
import CLibWally

let MAX_BYTES = 32 // Arbitrary, used only to determine array size in bip39_mnemonic_to_bytes

public var BIP39Words: [String] = {
    // Implementation based on Blockstream Green Development Kit
    var words: [String] = []
    var WL: OpaquePointer?
    precondition(bip39_get_wordlist(nil, &WL) == WALLY_OK)
    for i in 0..<BIP39_WORDLIST_LEN {
        var word: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(word)
        }
        precondition(bip39_get_word(WL, Int(i), &word) == WALLY_OK)
        words.append(String(cString: word!))
    }
    return words
}()

public struct BIP39Entropy : Equatable {
    public var data: Data
    
    public init(hex: String) throws {
        self.data = try Data(hex: hex)
    }
    
    public init(_ data: Data) {
        self.data = data
    }
    
    public var description: String { return data.hex }
}

public struct BIP39Seed : Equatable {
    var data: Data
    
    public init(hex: String) throws {
        self.data = try Data(hex: hex)
    }
    
    init(_ data: Data) {
        self.data = data
    }
    
    public var description: String { return data.hex }
}

public struct BIP39Mnemonic : Equatable {
    public let words: [String]
    public var description: String { return words.joined(separator: " ") }

    public init(words: [String]) throws {
        if !BIP39Mnemonic.isValid(words) {
            throw LibWallyError("Invalid mnemonic.")
        }
        self.words = words
    }
    
    public init(words: String) throws {
        try self.init(words: words.components(separatedBy: " "))
    }
    
    public init(entropy: BIP39Entropy) throws {
        precondition(entropy.data.count <= MAX_BYTES)

        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }

        let result = entropy.data.withUnsafeByteBuffer { buf in
            bip39_mnemonic_from_bytes(nil, buf.baseAddress, buf.count, &output)
        }

        if result == WALLY_OK {
            let words = String(cString: output!)
            try self.init(words: words)
        } else {
            throw LibWallyError("Invalid mnemonic.")
        }
    }
    
    public var entropy: BIP39Entropy {
        let mnemonic = words.joined(separator: " ")
        var bytes_out = [UInt8](repeating: 0, count: Int(BIP39_SEED_LEN_512))
        var written = 0
        precondition(bip39_mnemonic_to_bytes(nil, mnemonic, &bytes_out, MAX_BYTES, &written) == WALLY_OK)
        precondition(written > 0)
        return BIP39Entropy(Data(bytes: bytes_out, count: written))
    }
    
    public func seedHex(_ passphrase: String? = nil) -> BIP39Seed {
        let mnemonic = words.joined(separator: " ")
        var bytes_out = [UInt8](repeating: 0, count: Int(BIP39_SEED_LEN_512))
        var written = 0
        precondition(bip39_mnemonic_to_seed(mnemonic, passphrase, &bytes_out, Int(BIP39_SEED_LEN_512), &written) == WALLY_OK)
        return BIP39Seed(Data(bytes: bytes_out, count: written))
    }

    static func isValid(_ words: [String]) -> Bool {
        // Enforce maximum length
        if words.count > MAX_BYTES { return false }

        // Check that each word appears in the BIP39 dictionary:
        if !Set(words).subtracting(Set(BIP39Words)).isEmpty {
            return false
        }
        let mnemonic = words.joined(separator: " ")
        return bip39_mnemonic_validate(nil, mnemonic) == WALLY_OK
    }
    
    static func isValid(_ words: String) -> Bool {
        return self.isValid(words.components(separatedBy: " "))
    }

}
