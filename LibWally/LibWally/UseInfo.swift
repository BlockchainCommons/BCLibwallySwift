//
//  UseInfo.swift
//  LibWally
//
//  Created by Wolf McNally on 8/26/21.
//

import Foundation

// https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md#cddl-for-coin-info
public struct UseInfo: Equatable {
    public let asset: Asset
    public let network: Network

    public init(asset: Asset = .btc, network: Network = .mainnet) {
        self.asset = asset
        self.network = network
    }
    
    public var coinType: UInt32 {
        switch asset {
        case .btc:
            switch network {
            case .mainnet:
                return Asset.btc.rawValue
            case .testnet:
                return 1
            }
        case .eth:
            switch network {
            case .mainnet:
                return Asset.eth.rawValue
            case .testnet:
                return 1
            }
        }
//        case .bch:
//            switch network {
//            case .mainnet:
//                return Asset.bch.rawValue
//            case .testnet:
//                return 1
//            }
//        }
    }
    
    public var versionSH: UInt8 {
        precondition(asset == .btc)
        switch network {
        case .mainnet:
            return 0x05
        case .testnet:
            return 0xc4
        }
    }
    
    public var versionPKH: UInt8 {
        precondition(asset == .btc)
        switch network {
        case .mainnet:
            return 0x00
        case .testnet:
            return 0x6f
        }
    }
}
