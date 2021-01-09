//
//  PubKey.swift
//  LibWally
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation

public struct PubKey : Equatable, Hashable {
    public let isCompressed: Bool
    public let data: Data
    public let network: Network

    public init(_ data: Data, network: Network, isCompressed: Bool = true) throws {
        guard data.count == Int(isCompressed ? EC_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_UNCOMPRESSED_LEN) else {
            throw LibWallyError("Invalid public key.")
        }
        self.data = data
        self.network = network
        self.isCompressed = isCompressed
    }
}
