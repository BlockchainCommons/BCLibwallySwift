//
//  Descriptor.swift
//  LibWally
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation

public typealias PrivateKeyProvider = (HDKey) -> HDKey?

protocol DescriptorFunction {
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?, comboOutput: Descriptor.ComboOutput?) -> ScriptPubKey?
}

public struct Descriptor {
    public let source: String
    let function: DescriptorFunction
    
    public init(_ source: String) throws {
        self.source = source
        let tokens = try DescriptorLexer(source: source).lex()
        self.function = try DescriptorParser(tokens: tokens, source: source).parse()
    }
    
    public func scriptPubKey(wildcardChildNum: UInt32? = nil, privateKeyProvider: PrivateKeyProvider? = nil, comboOutput: ComboOutput? = nil) -> ScriptPubKey? {
        return function.scriptPubKey(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider, comboOutput: comboOutput)
    }
    
    public var isCombo: Bool {
        return (function as? DescriptorCombo) != nil
    }

    public enum ComboOutput {
        case pk
        case pkh
        case wpkh
        case sh_wpkh
    }
}

extension Descriptor: CustomStringConvertible {
    public var description: String {
        source
    }
}
