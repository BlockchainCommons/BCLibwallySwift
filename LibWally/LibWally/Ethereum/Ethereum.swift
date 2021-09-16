//
//  Ethereum.swift
//  LibWally
//
//  Created by Wolf McNally on 9/15/21.
//

import Foundation
@_implementationOnly import class CryptoSwift.SHA3
@_implementationOnly import WolfBase

// https://kobl.one/blog/create-full-ethereum-keypair-and-address/

public enum Ethereum {
}

extension Ethereum {
    public static func keccak256(_ data: Data) -> Data {
        let s = SHA3(variant: .keccak256)
        let r = s.calculate(for: data.bytes)
        return Data(r)
    }
}

extension Ethereum {
    open class Account {
        public let bip39: BIP39?
        public let accountPath: DerivationPath
        public let account: UInt32
        public static let defaultAccountPath = DerivationPath(string: "44'/60'/*'/0/0")!
        public static let defaultAccount: UInt32 = 0
        
        public private(set) lazy var bip39Seed: BIP39.Seed? = {
            guard let bip39 = bip39 else {
                return nil
            }
            return BIP39.Seed(bip39: bip39)
        }()
        
        public private(set) lazy var masterKey: HDKey? = {
            guard let bip39Seed = bip39Seed else {
                return nil
            }
            return HDKey(bip39Seed: bip39Seed)
        }()
        
        public private(set) lazy var accountKey: HDKey? = {
            guard let masterKey = masterKey else {
                return nil
            }
            return masterKey.derive(path: accountPath, wildcardChildNum: account)
        }()
        
        public private(set) lazy var accountPrivateKey: ECPrivateKey? = {
            guard let accountKey = accountKey else {
                return nil
            }
            return accountKey.privKey
        }()
        
        public private(set) lazy var accountPublicKey: ECUncompressedPublicKey? = {
            guard let accountPrivateKey = accountPrivateKey else {
                return nil
            }
            return accountPrivateKey.public.uncompressed
        }()
        
        public private(set) lazy var address: String? = {
            guard let accountPublicKey = accountPublicKey else {
                return nil
            }
            let data = accountPublicKey.data.dropFirst()
            let hash = Ethereum.keccak256(data)
            return "0x" + hash.suffix(20).hex
        }()
        
        public private(set) lazy var shortAddress: String? = {
            guard let address = address else {
                return nil
            }
            return address.dropFirst(2).prefix(4) + "..." + address.suffix(4)
        }()
        
        public init(bip39: BIP39, accountPath: DerivationPath = defaultAccountPath, account: UInt32 = defaultAccount) {
            self.bip39 = bip39
            self.accountPath = accountPath
            self.account = account
        }
        
        public convenience init?(mnemonic: String) {
            guard let bip39 = BIP39(mnemonic: mnemonic) else {
                return nil
            }
            self.init(bip39: bip39)
        }
        
        public init(bip39Seed: BIP39.Seed, accountPath: DerivationPath = defaultAccountPath, account: UInt32 = defaultAccount) {
            self.bip39 = nil
            self.accountPath = accountPath
            self.account = account
            self.bip39Seed = bip39Seed
        }
        
        public init(masterKey: HDKey, account: UInt32 = defaultAccount) {
            self.bip39 = nil
            self.accountPath = masterKey.children
            self.account = account
            self.bip39Seed = nil
            self.masterKey = masterKey
        }
        
        public init(accountKey: HDKey) {
            self.bip39 = nil
            self.accountPath = .init()
            self.account = 0
            self.bip39Seed = nil
            self.masterKey = nil
            self.accountKey = accountKey
        }
        
        public init(accountPrivateKey: ECPrivateKey) {
            self.bip39 = nil
            self.accountPath = .init()
            self.account = 0
            self.bip39Seed = nil
            self.masterKey = nil
            self.accountKey = nil
            self.accountPrivateKey = accountPrivateKey
        }
        
        public init(accountPublicKey: ECUncompressedPublicKey) {
            self.bip39 = nil
            self.accountPath = .init()
            self.account = 0
            self.bip39Seed = nil
            self.masterKey = nil
            self.accountKey = nil
            self.accountPrivateKey = nil
            self.accountPublicKey = accountPublicKey
        }
        
        public init?(address: String) {
            self.bip39 = nil
            self.accountPath = .init()
            self.account = 0
            self.bip39Seed = nil
            self.masterKey = nil
            self.accountKey = nil
            self.accountPrivateKey = nil
            self.accountPublicKey = nil
            guard
                address.count == 42,
                address.hasPrefix("0x"),
                Data(hex: address.dropFirst(2)) != nil
            else {
                return nil
            }
            self.address = address.lowercased()
        }
    }
}
