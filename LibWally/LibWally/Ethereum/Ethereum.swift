//
//  Ethereum.swift
//  LibWally
//
//  Created by Wolf McNally on 9/15/21.
//

import Foundation
@_implementationOnly import CryptoSwift

// https://kobl.one/blog/create-full-ethereum-keypair-and-address/

public enum Ethereum {
    public static func keccak256(_ data: Data) -> Data {
        let s = SHA3(variant: .keccak256)
        let r = s.calculate(for: data.bytes)
        return Data(r)
    }
    
    public static func derive(mnemonic: String) {
        
    }
}
