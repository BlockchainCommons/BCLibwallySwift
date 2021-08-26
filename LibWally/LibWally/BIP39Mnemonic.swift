//
//  BIP39.swift
//  LibWally
//
//  Created by Sjors on 27/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md.
//

import Foundation
@_implementationOnly import WolfBase

public struct BIP39Mnemonic : Equatable, CustomStringConvertible {
    public let words: [String]
    public var description: String {
        words.joined(separator: " ")
    }

    private static let MAX_BYTES = 32 // Arbitrary, used only to determine array size in bip39_mnemonic_to_bytes

    public struct Entropy : Equatable, CustomStringConvertible {
        public let data: Data

        public init(hex: String) throws {
            guard let data = Data(hex: hex) else {
                throw LibWallyError("Invalid BIP39 mnemonic.")
            }
            self.data = data
        }

        public init(_ data: Data) {
            self.data = data
        }

        public var description: String {
            data.hex
        }
    }

    public struct Seed : Equatable, CustomStringConvertible {
        let data: Data

        public init(hex: String) throws {
            guard let data = Data(hex: hex) else {
                throw LibWallyError("Invalid BIP39 mnemonic.")
            }
            self.data = data
        }

        init(_ data: Data) {
            self.data = data
        }

        public var description: String { data.hex }
    }

    static let allWords: [String] = {
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

    public init(words: [String]) throws {
        if !BIP39Mnemonic.isValid(words: words) {
            throw LibWallyError("Invalid mnemonic.")
        }
        self.words = words
    }
    
    public init(words: String) throws {
        try self.init(words: words.components(separatedBy: " "))
    }
    
    public init(entropy: Entropy) throws {
        precondition(entropy.data.count <= Self.MAX_BYTES)

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
    
    public var entropy: Entropy {
        let mnemonic = words.joined(separator: " ")
        var bytes_out = [UInt8](repeating: 0, count: Int(BIP39_SEED_LEN_512))
        var written = 0
        precondition(bip39_mnemonic_to_bytes(nil, mnemonic, &bytes_out, Self.MAX_BYTES, &written) == WALLY_OK)
        precondition(written > 0)
        return Entropy(Data(bytes: bytes_out, count: written))
    }
    
    public func seedHex(passphrase: String? = nil) -> Seed {
        let mnemonic = words.joined(separator: " ")
        var bytes_out = [UInt8](repeating: 0, count: Int(BIP39_SEED_LEN_512))
        var written = 0
        precondition(bip39_mnemonic_to_seed(mnemonic, passphrase, &bytes_out, Int(BIP39_SEED_LEN_512), &written) == WALLY_OK)
        return Seed(Data(bytes: bytes_out, count: written))
    }

    static func isValid(words: [String]) -> Bool {
        // Enforce maximum length
        if words.count > Self.MAX_BYTES { return false }

        // Check that each word appears in the BIP39 dictionary:
        if !Set(words).subtracting(Set(BIP39Mnemonic.allWords)).isEmpty {
            return false
        }
        let mnemonic = words.joined(separator: " ")
        return bip39_mnemonic_validate(nil, mnemonic) == WALLY_OK
    }
    
    static func isValid(words: String) -> Bool {
        isValid(words: words.components(separatedBy: " "))
    }
}
