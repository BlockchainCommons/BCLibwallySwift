//
//  Seed.swift
//  LibWally
//
//  Created by Wolf McNally on 9/15/21.
//

import Foundation

open class Seed: CustomStringConvertible {
    public let data: Data
    
    public init?(data: Data) {
        guard data.count <= 32 else {
            return nil
        }
        self.data = data
    }
    
    public convenience init() {
        self.init(data: SecureRandomNumberGenerator.shared.data(count: 16))!
    }

    open var description: String {
        hex
    }
}

extension Seed {
    public var hex: String {
        data.hex
    }
}

extension Seed {
    public var bip39: BIP39 {
        BIP39(data: data)!
    }
    
    public convenience init(bip39: BIP39) {
        self.init(data: bip39.data)!
    }
}
