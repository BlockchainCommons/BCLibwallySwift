//
//  KeyOrigin.swift
//  LibWally
//
//  Created by Wolf McNally on 11/21/20.
//

import Foundation

public struct KeyOrigin : Equatable {
    public let fingerprint: Data
    public let path: BIP32Path

    static func getOrigins(keypaths: wally_map) throws -> [ECCompressedPublicKey: KeyOrigin] {
        var origins: [ECCompressedPublicKey: KeyOrigin] = [:]
        for i in 0..<keypaths.num_items {
            // TOOD: simplify after https://github.com/ElementsProject/libwally-core/issues/241
            let item: wally_map_item = keypaths.items[i]

            let pubKey = try ECCompressedPublicKey(Data(bytes: item.key, count: Int(EC_PUBLIC_KEY_LEN)))
            let fingerprint = Data(bytes: item.value, count: Int(BIP32_KEY_FINGERPRINT_LEN))
            let keyPath = Data(bytes: item.value + Int(BIP32_KEY_FINGERPRINT_LEN), count: Int(item.value_len) - Int(BIP32_KEY_FINGERPRINT_LEN))

            var components: [UInt32] = []
            for j in 0..<keyPath.count / 4 {
                let data = keyPath.subdata(in: (j * 4)..<((j + 1) * 4)).withUnsafeBytes{ $0.load(as: UInt32.self) }
                components.append(data)
            }
            let path = try! BIP32Path(rawPath: components, isRelative: false)
            origins[pubKey] = KeyOrigin(fingerprint: fingerprint, path: path)
        }
        return origins
    }
}
