//
//  DescriptorKeyExpression.swift
//  LibWally
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation

struct DescriptorKeyExpression {
    let origin: DerivationPath
    let key: Key

    enum Key {
        case ecCompressedPublicKey(ECCompressedPublicKey)
        case ecUncompressedPublicKey(ECUncompressedPublicKey)
        //case ecXOnlyPublicKey(ECXOnlyPublicKey)
        case wif(WIF)
        case hdKey(HDKey)
    }
}

extension DescriptorKeyExpression {
    func pubKeyData(
        wildcardChildNum: UInt32?,
        privateKeyProvider: PrivateKeyProvider?
    ) -> Data? {
        let data: Data
        switch key {
        case .ecCompressedPublicKey(let k):
            data = k.data
        case .ecUncompressedPublicKey(let k):
            data = k.data
        // case .ecXOnlyPublicKey(let k):
        //     data = k.data
        case .wif(let k):
            data = k.key.public.data
        case .hdKey(let k):
            guard let k2 = k.derive(path: k.children, wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
                return nil
            }
            data = k2.pubKey.data
        }
        return data
    }
}

extension DescriptorKeyExpression : CustomStringConvertible {
    var description: String {
        var comps: [String] = []
        if !origin.isEmpty {
            comps.append("[\(origin)]")
        }
        comps.append(key.description)
        return comps.joined()
    }
}

extension DescriptorKeyExpression.Key : CustomStringConvertible {
    var description: String {
        switch self {
        case .ecCompressedPublicKey(let key):
            return key.data.hex
        case .ecUncompressedPublicKey(let key):
            return key.data.hex
        // case .ecXOnlyPublicKey(let key):
        //    return key.data.hex
        case .wif(let key):
            return key.description
        case .hdKey(let key):
            return key.description(withChildren: true)
        }
    }
}
