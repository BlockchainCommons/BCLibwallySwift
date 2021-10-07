//
//  ProtoHDKey.swift
//  LibWally
//
//  Created by Wolf McNally on 10/4/21.
//

import Foundation
@_implementationOnly import WolfBase

open class ProtoHDKey {
    public let isMaster: Bool
    public let keyType: KeyType
    public let keyData: Data
    public let chainCode: Data?
    public let useInfo: UseInfo
    public let parent: DerivationPath?
    public let children: DerivationPath?
    public let parentFingerprint: UInt32?
    
    public enum Error: Swift.Error {
        case invalidSeed
        case invalidBase58
        case cannotDerivePrivateFromPublic
        case cannotDeriveHardenedFromPublic
        case cannotDeriveFromNonDerivable
        case cannotDeriveInspecificStep
        case invalidDepth
        case unknownDerivationError
    }

    public init(isMaster: Bool, keyType: KeyType, keyData: Data, chainCode: Data?, useInfo: UseInfo, origin: DerivationPath?, children: DerivationPath?, parentFingerprint: UInt32?) {
        self.isMaster = isMaster
        self.keyType = keyType
        self.keyData = keyData
        self.chainCode = chainCode
        self.useInfo = useInfo
        self.parent = origin
        self.children = children
        self.parentFingerprint = parentFingerprint
    }
    
    public init(parent: ProtoHDKey, derivedKeyType: KeyType, isDerivable: Bool = true) throws {
        guard parent.keyType == .private || derivedKeyType == .public else {
            // public -> private
            throw Error.cannotDerivePrivateFromPublic
        }

        let chainCode = isDerivable ? parent.chainCode : nil
        self.isMaster = parent.isMaster
        self.keyType = derivedKeyType
        self.chainCode = chainCode
        self.useInfo = parent.useInfo
        self.parent = parent.parent
        self.children = parent.children
        self.parentFingerprint = parent.parentFingerprint
        if parent.keyType == derivedKeyType {
            // private -> private
            // public -> public
            self.keyData = parent.keyData
        } else {
            // private -> public
            self.keyData = Data(of: parent.wallyExtKey.pub_key)
        }
    }
    
    public init(base58: String, useInfo: UseInfo = .init(), parent: DerivationPath? = nil, children: DerivationPath? = nil) throws {
        guard let key = Wally.hdKey(fromBase58: base58) else {
            throw Error.invalidBase58
        }
        self.isMaster = key.isMaster
        self.keyType = key.keyType
        if key.isPrivate {
            self.keyData = Data(of: key.priv_key)
        } else {
            self.keyData = Data(of: key.pub_key)
        }
        self.chainCode = Data(of: key.chain_code)
        self.useInfo = UseInfo(asset: useInfo.asset, network: key.network!)

        let steps: [DerivationStep]
        if key.child_num == 0 {
            steps = []
        } else {
            steps = [DerivationStep(rawValue: key.child_num)]
        }
        if let parent = parent {
            self.parent = parent
        } else {
            let o = DerivationPath.Origin.fingerprint(Wally.fingerprint(for: key))
            self.parent = DerivationPath(steps: steps, origin: o, depth: Int(key.depth))
        }
        self.children = children
        self.parentFingerprint = deserialize(UInt32.self, Data(of: key.parent160))!
    }
    
    public init(bip39Seed: BIP39.Seed, useInfo: UseInfo = .init(), children: DerivationPath? = nil) throws {
        guard let key = Wally.hdKey(bip39Seed: bip39Seed, network: useInfo.network) else {
            // From libwally-core docs:
            // The entropy passed in may produce an invalid key. If this happens, WALLY_ERROR will be returned
            // and the caller should retry with new entropy.
            throw Error.invalidSeed
        }
        self.isMaster = true
        self.keyType = .private
        self.keyData = Data(of: key.priv_key)
        self.chainCode = Data(of: key.chain_code)
        self.useInfo = UseInfo(asset: useInfo.asset, network: useInfo.network)
        self.parent = DerivationPath(origin: .fingerprint(Wally.fingerprint(for: key)))
        self.children = children
        self.parentFingerprint = nil
    }
    
    public init(seed: Seed, useInfo: UseInfo = .init(), origin: DerivationPath? = nil, children: DerivationPath? = nil) throws {
        let bip39Seed = BIP39.Seed(bip39: seed.bip39)
        guard let key = LibWally.HDKey(bip39Seed: bip39Seed, network: useInfo.network) else {
            // From libwally-core docs:
            // The entropy passed in may produce an invalid key. If this happens, WALLY_ERROR will be returned
            // and the caller should retry with new entropy.
            throw Error.invalidSeed
        }
        
        self.isMaster = true
        self.keyType = .private
        self.keyData = Data(of: key.wallyExtKey.priv_key)
        self.chainCode = Data(of: key.wallyExtKey.chain_code)
        self.useInfo = UseInfo(asset: useInfo.asset, network: useInfo.network)
        self.parent = origin
        self.children = children
        self.parentFingerprint = origin?.originFingerprint
    }

    public init(parent: ProtoHDKey, derivedKeyType: KeyType, childDerivation: DerivationStep) throws {
        guard parent.keyType == .private || derivedKeyType == .public else {
            throw Error.cannotDerivePrivateFromPublic
        }
        guard parent.isDerivable else {
            throw Error.cannotDeriveFromNonDerivable
        }
        
        self.isMaster = false

        guard let childNum = childDerivation.rawValue() else {
            throw Error.cannotDeriveInspecificStep
        }
        guard let derivedKey = Wally.key(from: parent.wallyExtKey, childNum: childNum, isPrivate: derivedKeyType.isPrivate) else {
            throw Error.unknownDerivationError
        }

        self.keyType = derivedKeyType
        self.keyData = derivedKeyType == .private ? Data(of: derivedKey.priv_key) : Data(of: derivedKey.pub_key)
        self.chainCode = Data(of: derivedKey.chain_code)
        self.useInfo = parent.useInfo

        self.parentFingerprint = parent.keyFingerprint
        let origin: DerivationPath
        if let parentOrigin = parent.parent {
            var steps = parentOrigin.steps
            steps.append(childDerivation)
            let sourceFingerprint = parentOrigin.originFingerprint ?? parentFingerprint
            let o: DerivationPath.Origin? = sourceFingerprint != nil ? .fingerprint(sourceFingerprint!) : nil
            let depth: Int
            if let parentDepth = parentOrigin.depth {
                depth = parentDepth + 1
            } else {
                depth = 1
            }
            origin = DerivationPath(steps: steps, origin: o, depth: depth)
        } else {
            let o: DerivationPath.Origin? = parentFingerprint != nil ? .fingerprint(parentFingerprint!) : nil
            origin = DerivationPath(steps: [childDerivation], origin: o, depth: 1)
        }
        self.parent = origin
        self.children = nil
    }
    
    public init(parent: ProtoHDKey, derivedKeyType: KeyType, childDerivationPath: DerivationPath, isDerivable: Bool = true) throws {
        var effectiveDerivationPath = childDerivationPath
        if effectiveDerivationPath.origin != nil {
            let parentDepth = parent.parent?.effectiveDepth ?? 0
            guard let p = childDerivationPath.dropFirst(parentDepth) else {
                throw Error.invalidDepth
            }
            effectiveDerivationPath = p
        }

        if parent.keyType == .public {
            if derivedKeyType == .private {
                throw Error.cannotDerivePrivateFromPublic
            } else if effectiveDerivationPath.isHardened {
                throw Error.cannotDeriveHardenedFromPublic
            }
        }
        guard parent.isDerivable else {
            throw Error.cannotDeriveFromNonDerivable
        }

        var derivedKey = parent
        for step in effectiveDerivationPath.steps {
            derivedKey = try ProtoHDKey(parent: derivedKey, derivedKeyType: parent.keyType, childDerivation: step)
        }
        self.isMaster = false
        self.keyType = derivedKeyType
        self.keyData = derivedKey.keyData
        self.chainCode = isDerivable ? derivedKey.chainCode : nil
        self.useInfo = parent.useInfo
        self.parentFingerprint = derivedKey.parentFingerprint
        self.parent = derivedKey.parent
        self.children = derivedKey.children
    }
    
    public var isPrivate: Bool {
        keyType.isPrivate
    }
    
    public var isDerivable: Bool {
        chainCode != nil
    }
    
    public var originFingerprint: UInt32? {
        parent?.originFingerprint
    }
    
    public var keyFingerprintData: Data {
        Wally.fingerprintData(for: wallyExtKey)
    }

    public var keyFingerprint: UInt32 {
        Wally.fingerprint(for: wallyExtKey)
    }

    public var wallyHDKey: LibWally.HDKey {
        LibWally.HDKey(key: wallyExtKey, parent: parent ?? .init(), children: children ?? .init())
    }
    
    public var base58: String? {
        base58PrivateKey ?? base58PublicKey
    }
    
    public var base58PublicKey: String {
        Wally.base58(from: wallyExtKey, isPrivate: false)!
    }
    
    public var base58PrivateKey: String? {
        Wally.base58(from: wallyExtKey, isPrivate: true)
    }
    
    public var ecPublicKey: ECCompressedPublicKey {
        ECCompressedPublicKey(Data(of: wallyExtKey.pub_key))!
    }

    public var ecPrivateKey: ECPrivateKey? {
        if !isPrivate {
            return nil
        }
        var data = Data(of: wallyExtKey.priv_key)
        // skip prefix byte 0
        precondition(data.popFirst() != nil)
        return ECPrivateKey(data)!
    }

    public var wallyExtKey: ext_key {
        var k = ext_key()
        
        if let parent = parent {
            k.depth = UInt8(parent.effectiveDepth)

            if let lastStep = parent.steps.last,
               case let ChildIndexSpec.index(childIndex) = lastStep.childIndexSpec {
                let value = childIndex.value
                let isHardened = lastStep.isHardened
                let childNum = value | (isHardened ? 0x80000000 : 0)
                k.child_num = childNum
            }
        }
        
        switch keyType {
        case .private:
            keyData.store(into: &k.priv_key)
            Wally.updatePublicKey(in: &k)
            switch useInfo.network {
            case .mainnet:
                k.version = UInt32(BIP32_VER_MAIN_PRIVATE)
            case .testnet:
                k.version = UInt32(BIP32_VER_TEST_PRIVATE)
            }
        case .public:
            k.priv_key.0 = 0x01;
            keyData.store(into: &k.pub_key)
            switch useInfo.network {
            case .mainnet:
                k.version = UInt32(BIP32_VER_MAIN_PUBLIC)
            case .testnet:
                k.version = UInt32(BIP32_VER_TEST_PUBLIC)
            }
        }
        
        Wally.updateHash160(in: &k)
        
        if let chainCode = chainCode {
            chainCode.store(into: &k.chain_code)
        }
        
        if let parentFingerprint = parentFingerprint {
            parentFingerprint.serialized.store(into: &k.parent160)
        }
        
        k.checkValid()
        return k
    }
}
