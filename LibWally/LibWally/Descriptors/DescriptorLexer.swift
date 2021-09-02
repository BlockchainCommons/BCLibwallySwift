//
//  DescriptorLexer.swift
//  LibWally
//
//  Created by Wolf McNally on 8/31/21.
//

import Foundation
@_implementationOnly import Flexer

public struct DescriptorLexer {
    static func lex(lexer: DescriptorTokenSequence, string: String) -> [DescriptorToken] {
        return lexer.reduce(into: []) {
            $0.append($1)
        }
    }

    static func lex(string: String) -> [DescriptorToken] {
        let lexer = DescriptorTokenSequence(string: string)
        return lex(lexer: lexer, string: string)
    }
    
    public static func debugLex(string: String) -> String {
        let lexer = DescriptorTokenSequence(string: string)
        let strings = lex(lexer: lexer, string: string).map { $0.summary(lexer: lexer) }
        return strings.joined(separator: ", ")
    }
}

struct DescriptorTokenSequence: Sequence, IteratorProtocol, StringInitializable {
    public typealias Element = DescriptorToken
    
    private let string: String
    private var lexer: BasicTextCharacterLexer
    
    public func range(of token: DescriptorToken) -> Range<Int> {
        let a = string.distance(from: string.startIndex, to: token.startIndex)
        let b = string.distance(from: string.startIndex, to: token.endIndex)
        return a ..< b
    }
    
    public init(string: String) {
        self.string = string
        self.lexer = BasicTextCharacterLexer(string: string)
    }

    private static let tokenLexers = [
        Self.lexDelimiters,
        Self.lexKeywords,
        Self.lexAddress,
        Self.lexHDKey,
        Self.lexData,
        Self.lexInt,
        Self.lexHardened
    ]

    mutating func next() -> DescriptorToken? {
        for tokenLexer in Self.tokenLexers {
            if let token = tokenLexer(&lexer, string) {
                return token
            }
        }
        
        return nil
    }

    private static let delimiters: [(BasicTextCharacterKind, DescriptorToken.Kind)] = [
        (.openParen, .openParen),
        (.closeParen, .closeParen),
        (.openBracket, .openBracket),
        (.closeBracket, .closeBracket),
        (.openBrace, .openBrace),
        (.closeBrace, .closeBrace),
        (.comma, .comma),
        (.slash, .slash),
        (.star, .star)
    ]
    
    private static func lexDelimiters(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        func lexDelimiter(kind: BasicTextCharacterKind, descriptorKind: DescriptorToken.Kind) -> DescriptorToken? {
            var seq = lexer
            guard
                let token = seq.peek(),
                token.kind == kind,
                let endingToken = seq.next() else
            {
                return nil
            }
            let range = token.startIndex ..< endingToken.endIndex
            lexer = seq
            return DescriptorToken(kind: descriptorKind, range: range)
        }

        for delimiter in Self.delimiters {
            if let descriptorToken = lexDelimiter(kind: delimiter.0, descriptorKind: delimiter.1) {
                return descriptorToken
            }
        }
        return nil
    }

    private mutating func lexDelimiters() -> DescriptorToken? {
        func lexDelimiter(kind: BasicTextCharacterKind, descriptorKind: DescriptorToken.Kind) -> DescriptorToken? {
            var seq = lexer
            guard
                let token = seq.peek(),
                token.kind == kind,
                let endingToken = seq.next() else
            {
                return nil
            }
            let range = token.startIndex ..< endingToken.endIndex
            lexer = seq
            return DescriptorToken(kind: descriptorKind, range: range)
        }

        for delimiter in Self.delimiters {
            if let descriptorToken = lexDelimiter(kind: delimiter.0, descriptorKind: delimiter.1) {
                return descriptorToken
            }
        }
        return nil
    }

    private static let keywords: [(String, DescriptorToken.Kind)] = [
        ("sh", .sh),
        ("wsh", .wsh),
        ("pk", .pk),
        ("pkh", .pkh),
        ("wpkh", .wpkh),
        ("combo", .combo),
        ("multi", .multi),
        ("sortedmulti", .sortedmulti),
        ("tr", .tr),
        ("addr", .addr),
        ("raw", .raw)
    ]
    
    private static func lexKeywords(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        func lexKeyword(keyword: String, kind: DescriptorToken.Kind) -> DescriptorToken? {
            var seq = lexer
            guard
                let token = seq.peek(),
                token.kind == .lowercaseLetter,
                let endingToken = seq.nextUntil(notIn: [.lowercaseLetter])
            else {
                return nil
            }
            let range = token.startIndex ..< endingToken.endIndex
            guard string[range] == keyword else {
                return nil
            }
            lexer = seq
            return DescriptorToken(kind: kind, range: range)
        }

        for keyword in Self.keywords {
            if let descriptorToken = lexKeyword(keyword: keyword.0, kind: keyword.1) {
                return descriptorToken
            }
        }
        return nil
    }
    
    private static func character(of token: BasicTextCharacter, in string: String) -> Character {
        string[token.range].first!
    }
    
    private static func substring(of range: Range<Token<BasicTextCharacterKind>.Index>, in string: String) -> String {
        String(string[range])
    }
    
    private static func isHexDigit(token: BasicTextCharacter, in string: String) -> Bool {
        CharacterSet.hexDigits.contains(character(of: token, in: string))
    }
    
    private static func isBase58(token: BasicTextCharacter, in string: String) -> Bool {
        CharacterSet.base58.contains(character(of: token, in: string))
    }
    
    private static func isAllowedInAddress(token: BasicTextCharacter, in string: String) -> Bool {
        CharacterSet.allowedInAddress.contains(character(of: token, in: string))
    }
    
    private static func lexData(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        var seq = lexer
        guard
            let token = seq.peek(),
            isHexDigit(token: token, in: string),
            let endingToken = seq.nextUntil( { !isHexDigit(token: $0, in: string) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard
            let data = Data(hex: substring(of: range, in: string)),
            data.count > 1 // reject short data as it's probably an int
        else {
            return nil
        }
        lexer = seq
        return DescriptorToken(kind: .data, range: range, payload: data)
    }
    
    private static func lexAddress(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        var seq = lexer
        guard
            let token = seq.peek(),
            isAllowedInAddress(token: token, in: string),
            let endingToken = seq.nextUntil( { !isAllowedInAddress(token: $0, in: string) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let address = Address(string: substring(of: range, in: string)) else {
            return nil
        }
        lexer = seq
        return DescriptorToken(kind: .address, range: range, payload: address)
    }
    
    private static func lexWIF(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        var seq = lexer
        guard
            let token = seq.peek(),
            isBase58(token: token, in: string),
            let endingToken = seq.nextUntil( { !isBase58(token: $0, in: string) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let wif = WIF(substring(of: range, in: string)) else {
            return nil
        }
        lexer = seq
        return DescriptorToken(kind: .wif, range: range, payload: wif)
    }

    private static func lexHDKey(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        var seq = lexer
        guard
            let token = seq.peek(),
            isBase58(token: token, in: string),
            let endingToken = seq.nextUntil( { !isBase58(token: $0, in: string) } )
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let hdKey = HDKey(base58: substring(of: range, in: string)) else {
            return nil
        }
        lexer = seq
        return DescriptorToken(kind: .hdKey, range: range, payload: hdKey)
    }
    
    private static func lexInt(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        var seq = lexer
        guard
            let token = seq.peek(),
            token.kind == .digit,
            let endingToken = seq.nextUntil(notIn: [.digit])
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        guard let value = Int(substring(of: range, in: string)) else {
            return nil
        }
        lexer = seq
        return DescriptorToken(kind: .int, range: range, payload: value)
    }
    
    private static func lexHardened(lexer: inout BasicTextCharacterLexer, string: String) -> DescriptorToken? {
        var seq = lexer
        guard
            let token = seq.peek(),
            "'h".contains(character(of: token, in: string)),
            let endingToken = seq.next()
        else {
            return nil
        }
        let range = token.startIndex ..< endingToken.endIndex
        lexer = seq
        return DescriptorToken(kind: .isHardened, range: range)
    }
}
