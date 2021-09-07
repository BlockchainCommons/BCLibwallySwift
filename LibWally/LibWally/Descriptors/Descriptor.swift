//
//  Descriptor.swift
//  LibWally
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation

protocol DescriptorFunction {
    var scriptPubKey: ScriptPubKey { get }
}

public struct Descriptor {
    public let source: String
    public let scriptPubKey: ScriptPubKey
    
    public init(_ source: String) throws {
        self.source = source
        let tokens = try DescriptorLexer(source: source).lex()
        let function = try DescriptorParser(tokens: tokens, source: source).parse()
        self.scriptPubKey = function.scriptPubKey
    }
}

extension Descriptor: CustomStringConvertible {
    public var description: String {
        source
    }
}
