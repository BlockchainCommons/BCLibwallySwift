//
//  Asset.swift
//  LibWally
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation

public enum Asset: UInt32, CaseIterable, Equatable {
    // Values from [SLIP44] with high bit turned off
    case btc = 0
    case eth = 0x3c
//    case bch = 0x91
}

extension Asset: Identifiable {
    public var id: String {
        "asset-\(description)"
    }
}

extension Asset: CustomStringConvertible {
    public var description: String {
        switch self {
        case .btc:
            return "btc"
        case .eth:
            return "eth"
//        case .bch:
//            return "bch"
        }
    }
}
