//
//  HDKey.swift
//  LibWally
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation

public struct HDKey : CustomStringConvertible {
    public private(set) var wallyExtKey: WallyExtKey
    public let parent: DerivationPath
    public let children: DerivationPath

    public init(key: WallyExtKey, parent: DerivationPath, children: DerivationPath) {
        self.wallyExtKey = key
        self.parent = parent
        self.children = children
    }
    
    public init(key: WallyExtKey, masterKeyFingerprint: UInt32? = nil) {
        let origin: DerivationPath.Origin?
        if let fingerprint = masterKeyFingerprint {
            origin = .fingerprint(fingerprint)
        } else {
            origin = nil
        }
        self.init(key: key, parent: DerivationPath(origin: origin), children: .init())
    }

    public init?(base58: String, masterKeyFingerprint: UInt32? = nil) {
        guard let key = Wally.hdKey(fromBase58: base58) else {
            return nil
        }
        let fingerprint = Wally.fingerprint(for: key)
        var masterKeyFingerprint = masterKeyFingerprint
        
        if key.depth == 0 {
            if masterKeyFingerprint == nil {
                masterKeyFingerprint = fingerprint
            } else {
                guard masterKeyFingerprint == fingerprint else {
                    return nil
                }
            }
        }
        self.init(key: key, masterKeyFingerprint: masterKeyFingerprint)
    }

    public init?(bip39Seed: BIP39.Seed, network: Network = .mainnet) {
        guard let key = Wally.hdKey(bip39Seed: bip39Seed, network: network) else {
            // From libwally-core docs:
            // The entropy passed in may produce an invalid key. If this happens, WALLY_ERROR will be returned
            // and the caller should retry with new entropy.
            return nil
        }
        self.init(key: key, masterKeyFingerprint: Wally.fingerprint(for: key))
    }
    
    public init?(seed: Seed, network: Network = .mainnet) {
        let bip39Seed = BIP39.Seed(bip39: seed.bip39)
        self.init(bip39Seed: bip39Seed, network: network)
    }
    
    public var masterKeyFingerprint: UInt32? {
        guard case let .fingerprint(fingerprint) = parent.origin else {
            return nil
        }
        return fingerprint
    }

    public var network: Network {
        wallyExtKey.network!
    }

    public var description: String {
        base58
    }
    
    public func description(withParent: Bool = false, withChildren: Bool = false) -> String {
        var comps: [String] = []
        if withParent && !parent.isEmpty {
            comps.append("[\(parent)]")
        }
        comps.append(base58)
        if withChildren && !children.isEmpty {
            comps.append("/\(children)")
        }
        return comps.joined()
    }
    
    public var fullDescription: String {
        description(withParent: true, withChildren: true)
    }

    public var isPrivate: Bool {
        wallyExtKey.version == BIP32_VER_MAIN_PRIVATE || wallyExtKey.version == BIP32_VER_TEST_PRIVATE
    }
    
    public var requiresWildcardChildNum: Bool {
        children.hasWildcard
    }

    public var xpub: String {
        var hdkey = wallyExtKey
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }

        precondition(bip32_key_to_base58(&hdkey, UInt32(BIP32_FLAG_KEY_PUBLIC), &output) == WALLY_OK)
        precondition(output != nil)
        return String(cString: output!)
    }

    public var pubKey: ECCompressedPublicKey {
        ECCompressedPublicKey(Data(of: wallyExtKey.pub_key))!
    }

    public var privKey: ECPrivateKey? {
        if !isPrivate {
            return nil
        }
        var data = Data(of: wallyExtKey.priv_key)
        // skip prefix byte 0
        precondition(data.popFirst() != nil)
        return ECPrivateKey(data)!
    }

    public var xpriv: String? {
        if !isPrivate {
            return nil
        }
        var hdkey = wallyExtKey
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }

        precondition(bip32_key_to_base58(&hdkey, UInt32(BIP32_FLAG_KEY_PRIVATE), &output) == WALLY_OK)
        precondition(output != nil)
        return String(cString: output!)
    }
    
    public var base58: String {
        xpriv ?? xpub
    }
    
    public var `public`: HDKey {
        var hdkey = wallyExtKey
        precondition(bip32_key_strip_private_key(&hdkey) == WALLY_OK)
        switch network {
        case .mainnet:
            hdkey.version = UInt32(BIP32_VER_MAIN_PUBLIC)
        case .testnet:
            hdkey.version = UInt32(BIP32_VER_TEST_PUBLIC)
        }
        return HDKey(key: hdkey, parent: parent, children: children)
    }

    public var fingerprintData: Data {
        Wally.fingerprintData(for: wallyExtKey)
    }
    
    public var fingerprint: UInt32 {
        Wally.fingerprint(for: wallyExtKey)
    }

    public func derive(
        path: DerivationPath,
        wildcardChildNum: UInt32? = nil,
        children: DerivationPath? = nil,
        privateKeyProvider: PrivateKeyProvider? = nil
    ) -> HDKey? {
        guard !path.isEmpty else {
            return self
        }
        
        let depth = wallyExtKey.depth
        var tmpPath = path
        if path.origin != nil {
            guard let p = path.chop(depth: Int(depth)) else {
                // Invalid depth.
                return nil
            }
            tmpPath = p
        }

        var workingKey = self
        if !isPrivate && tmpPath.isHardened {
            // Attempt to do hardened derivation without private key.
            guard
                let privateKeyProvider = privateKeyProvider,
                let privateKey = privateKeyProvider(workingKey),
                privateKey.isPrivate
            else {
                return nil
            }
            workingKey = privateKey
        }

        var hdkey = workingKey.wallyExtKey
        var output = ext_key()
        let rawPath = tmpPath.rawPath(wildcardChildNum: wildcardChildNum).compactMap({ $0 })
        guard rawPath.count == tmpPath.steps.count else {
            return nil
        }
        precondition(bip32_key_from_parent_path(&hdkey, rawPath, rawPath.count, UInt32(isPrivate ? BIP32_FLAG_KEY_PRIVATE : BIP32_FLAG_KEY_PUBLIC), &output) == WALLY_OK)
        let newParent: DerivationPath
        if parent.isEmpty {
            newParent = DerivationPath(steps: path.steps, origin: .fingerprint(workingKey.fingerprint))
        } else {
            newParent = DerivationPath(steps: parent.steps + path.steps, origin: parent.origin)
        }
        return HDKey(key: output, parent: newParent, children: children ?? .init())
    }

    public func address(type: Address.AddressType) -> Address {
        Address(hdKey: self, type: type)!
    }
}
