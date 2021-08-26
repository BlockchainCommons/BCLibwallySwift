//
//  Network.swift
//  LibWally
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation

public enum Network: UInt32, CaseIterable, Equatable {
    case mainnet = 0
    case testnet = 1
}

extension Network: Identifiable {
    public var id: String {
        "network-\(description)"
    }
}

extension Network: CustomStringConvertible {
    public var description: String {
        switch self {
        case .mainnet:
            return "main"
        case .testnet:
            return "test"
        }
    }
}

extension Network {
    public var wifPrefix: UInt32 {
        switch self {
        case .mainnet:
            return UInt32(WALLY_ADDRESS_VERSION_WIF_MAINNET)
        case .testnet:
            return UInt32(WALLY_ADDRESS_VERSION_WIF_TESTNET)
        }
    }
}
