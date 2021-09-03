//
//  Descriptor.swift
//  LibWally
//
//  Created by Wolf McNally on 9/2/21.
//

import Foundation

public struct Descriptor {
    let key: DescriptorKeyExpression
    
    public init(_ source: String) throws {
        let tokens = try DescriptorLexer(source: source).lex()
        self = try DescriptorParser(tokens: tokens, source: source).parseTop()
    }
    
    init(key: DescriptorKeyExpression) {
        self.key = key
    }
}
