//
//  DescriptorLexer.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
@_implementationOnly import Flexer

public struct Descriptor {
    let derivationPath: DerivationPath
    
    public init(_ string: String) throws {
        let tokens = DescriptorLexer.lex(string: string).lookAhead
        var parser = DescriptorParser(tokens: tokens, string: string)
        self = try parser.parseTop()
    }
    
    init(derivationPath: DerivationPath) {
        self.derivationPath = derivationPath
    }
}

enum DescriptorKey {
    case ecCompressedPublicKey(ECCompressedPublicKey)
    case ecUncompressedPublicKey(ECUncompressedPublicKey)
    case ecXOnlyPublicKey(ECXOnlyPublicKey)
    case ecPrivateKey(ECPrivateKey)
    case hdKey(HDKey)
}

public struct DescriptorError: Error, CustomStringConvertible {
    let message: String
    let token: DescriptorToken?
    let string: String
    
    init(_ message: String, _ token: DescriptorToken?, string: String) {
        self.message = message
        self.token = token
        self.string = string
    }
    
    private var range: Range<Int> {
        guard let token = token else {
            return string.count ..< string.count
        }
        let a = string.distance(from: string.startIndex, to: token.startIndex)
        let b = string.distance(from: string.startIndex, to: token.endIndex)
        return a ..< b
    }

    public var description: String {
        "\(message): \(range)"
    }
}

public struct DescriptorParser {
    typealias Tokens = LookAheadSequence<[DescriptorToken]>

    var tokens: Tokens
    let string: String
    
    init(tokens: Tokens, string: String) {
        self.tokens = tokens
        self.string = string
    }
    
    private mutating func error(_ message: String) -> DescriptorError {
        DescriptorError(message, tokens.peek(), string: string)
    }
    
    mutating func parseTop() throws -> Descriptor {
        guard let derivationPath = try parseDerivationPath() else {
            throw error("Expected derivation path.")
        }
        return Descriptor(derivationPath: derivationPath)
    }
    
    mutating func parseKeyOrigin() -> DerivationPath? {
        nil
    }
    
    mutating func parseFingerprint() -> Data? {
        var seq = tokens
        guard
            let token = seq.next(),
            token.kind == .data,
            token.data.count == 4
        else {
            return nil
        }
        tokens = seq
        return token.data
    }
    
    mutating func expectFingerprint() throws -> Data {
        guard let fingerprint = parseFingerprint() else {
            throw error("Fingerprint expected.")
        }
        return fingerprint
    }
    
    mutating func parseSlash() -> Bool {
        var seq = tokens
        guard
            let token = seq.next(),
            token.kind == .slash
        else {
            return false
        }
        tokens = seq
        return true
    }
    
    mutating func parseToken(kind: DescriptorToken.Kind) -> DescriptorToken? {
        var seq = tokens
        guard
            let token = seq.next(),
            token.kind == kind
        else {
            return nil
        }
        tokens = seq
        return token
    }

    mutating func parseChildnum() -> UInt32? {
        var seq = tokens
        guard
            let token = seq.next(),
            token.kind == .int
        else {
            return nil
        }
        let i = token.int
        guard (0 ..< Int(BIP32_INITIAL_HARDENED_CHILD)).contains(i) else {
            return nil
        }
        tokens = seq
        return UInt32(i)
    }

    mutating func parseWildcard() -> Bool {
        parseToken(kind: .star) != nil
    }

    mutating func parseOpenBracket() -> Bool {
        parseToken(kind: .openBracket) != nil
    }

    mutating func parseCloseBracket() -> Bool {
        parseToken(kind: .closeBracket) != nil
    }
    
    mutating func expectCloseBracket() throws {
        guard parseCloseBracket() else {
            throw error("Expected close bracket.")
        }
    }

    mutating func parseIndex() -> DerivationStep.Index? {
        if parseWildcard() {
            return .wildcard
        }
        if let childNum = parseChildnum() {
            return .childNum(childNum)
        }
        return nil
    }
    
    mutating func expectIndex() throws -> DerivationStep.Index {
        guard let index = parseIndex() else {
            throw error("Expected index.")
        }
        return index
    }
    
    mutating func parseIsHardened() -> Bool {
        var seq = tokens
        guard
            let token = seq.next(),
            token.kind == .isHardened
        else {
            return false
        }
        tokens = seq
        return true
    }
    
    mutating func parseDerivationStep() throws -> DerivationStep? {
        guard parseSlash() else {
            return nil
        }
        let index = try expectIndex()
        let isHardened = parseIsHardened()
        return DerivationStep(index, isHardened: isHardened)
    }
    
    mutating func parseDerivationSteps(allowFinalWildcard: Bool) throws -> [DerivationStep] {
        var steps: [DerivationStep] = []
        while let step = try parseDerivationStep() {
            steps.append(step)
        }
        if !steps.isEmpty {
            guard steps.dropLast().allSatisfy({ $0.index != .wildcard }) else {
                if allowFinalWildcard {
                    throw error("Wildcard not allowed except on last step.")
                } else {
                    throw error("Wildcard not allowed.")
                }
            }
            if !allowFinalWildcard {
                guard steps.last!.index != .wildcard else {
                    throw error("Wildcard not allowed.")
                }
            }
        }
        return steps
    }
    
    mutating func parseDerivationPath() throws -> DerivationPath? {
        guard parseOpenBracket() else {
            return nil
        }
        let fingerprint = try expectFingerprint()
        let steps = try parseDerivationSteps(allowFinalWildcard: false)
        try expectCloseBracket()
        return DerivationPath(steps: steps, origin: .fingerprint(fingerprint))
    }
    
    mutating func parseKey() throws -> DescriptorKey? {
        var seq = tokens
        guard
            let token = seq.next()
        else {
            return nil
        }
        let result: DescriptorKey?
        switch token.kind {
        case .data:
            let data = token.data
            if
                data.count == ECCompressedPublicKey.keyLen,
                [0x02, 0x03].contains(data[0])
            {
                result = .ecCompressedPublicKey(ECCompressedPublicKey(data)!)
            } else if data.count == ECUncompressedPublicKey.keyLen {
                result = .ecUncompressedPublicKey(ECUncompressedPublicKey(data)!)
            } else if data.count == ECXOnlyPublicKey.keyLen {
                result = .ecXOnlyPublicKey(ECXOnlyPublicKey(data)!)
            } else {
                result = nil
            }
        case .wif:
            result = .ecPrivateKey(token.wif.key)
        case .hdKey:
            result = .hdKey(token.hdKey)
        default:
            result = nil
        }

        if let result = result {
            tokens = seq
            return result
        }
        
        return nil
    }
}
