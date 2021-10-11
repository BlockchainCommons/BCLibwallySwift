//
//  PSBTSigner.swift
//  LibWally
//
//  Created by Wolf McNally on 10/10/21.
//

import Foundation

public protocol PSBTSigner {
    var masterKey: HDKey { get }
}
