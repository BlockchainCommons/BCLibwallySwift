//
//  DescriptorKeyExpression.swift
//  LibWally
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation

public struct DescriptorKeyExpression {
    public let origin: DerivationPath
    public let key: Key

    public enum Key {
        case ecCompressedPublicKey(ECCompressedPublicKey)
        case ecUncompressedPublicKey(ECUncompressedPublicKey)
        case ecXOnlyPublicKey(ECXOnlyPublicKey)
        case wif(WIF)
        case hdKey(HDKey)
    }
}

extension DescriptorKeyExpression : CustomStringConvertible {
    public var description: String {
        var comps: [String] = []
        if !origin.isEmpty {
            comps.append("[\(origin)]")
        }
        comps.append(key.description)
        return comps.joined()
    }
}

extension DescriptorKeyExpression.Key : CustomStringConvertible {
    public var description: String {
        switch self {
        case .ecCompressedPublicKey(let key):
            return key.data.hex
        case .ecUncompressedPublicKey(let key):
            return key.data.hex
        case .ecXOnlyPublicKey(let key):
            return key.data.hex
        case .wif(let key):
            return key.description
        case .hdKey(let key):
            return key.description(withChildren: true)
        }
    }
}
