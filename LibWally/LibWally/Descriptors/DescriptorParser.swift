//
//  DescriptorLexer.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
@_implementationOnly import Flexer


public final class DescriptorParser: Parser {
    typealias Tokens = LookAheadSequence<[DescriptorToken]>
    typealias Transaction = ParseTransaction<DescriptorParser>
    typealias Error = DescriptorError<DescriptorToken>

    let source: String
    var tokens: Tokens
    
    init(tokens: [DescriptorToken], source: String) {
        self.tokens = tokens.lookAhead
        self.source = source
    }
    
    func error(_ message: String) -> Error {
        Error(message, tokens.peek(), source: source)
    }
    
    func parseTop() throws -> Descriptor {
        guard let key = try parseKey() else {
            throw error("Expected derivation path.")
        }
        return Descriptor(key: key)
    }
    
    func parseKeyOrigin() -> DerivationPath? {
        nil
    }
    
    func parseFingerprint() -> Data? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .data,
            token.data.count == 4
        else {
            return nil
        }
        transaction.commit()
        return token.data
    }
    
    func expectFingerprint() throws -> Data {
        guard let fingerprint = parseFingerprint() else {
            throw error("Fingerprint expected.")
        }
        return fingerprint
    }
    
    func parseSlash() -> Bool {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .slash
        else {
            return false
        }
        transaction.commit()
        return true
    }
    
    func parseToken(kind: DescriptorToken.Kind) -> DescriptorToken? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == kind
        else {
            return nil
        }
        transaction.commit()
        return token
    }

    func parseChildnum() -> UInt32? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .int
        else {
            return nil
        }
        let i = token.int
        guard (0 ..< Int(BIP32_INITIAL_HARDENED_CHILD)).contains(i) else {
            return nil
        }
        transaction.commit()
        return UInt32(i)
    }

    func parseWildcard() -> Bool {
        parseToken(kind: .star) != nil
    }

    func parseOpenBracket() -> Bool {
        parseToken(kind: .openBracket) != nil
    }

    func parseCloseBracket() -> Bool {
        parseToken(kind: .closeBracket) != nil
    }
    
    func expectCloseBracket() throws {
        guard parseCloseBracket() else {
            throw error("Expected close bracket.")
        }
    }

    func parseIndex() -> DerivationStep.Index? {
        if parseWildcard() {
            return .wildcard
        }
        if let childNum = parseChildnum() {
            return .childNum(childNum)
        }
        return nil
    }
    
    func expectIndex() throws -> DerivationStep.Index {
        guard let index = parseIndex() else {
            throw error("Expected index.")
        }
        return index
    }
    
    func parseIsHardened() -> Bool {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .isHardened
        else {
            return false
        }
        transaction.commit()
        return true
    }
    
    func parseDerivationStep() throws -> DerivationStep? {
        guard parseSlash() else {
            return nil
        }
        let index = try expectIndex()
        let isHardened = parseIsHardened()
        return DerivationStep(index, isHardened: isHardened)
    }
    
    func parseDerivationSteps(allowFinalWildcard: Bool) throws -> [DerivationStep] {
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
    
    func parseOrigin() throws -> DerivationPath {
        guard parseOpenBracket() else {
            return .init()
        }
        let fingerprint = try expectFingerprint()
        let steps = try parseDerivationSteps(allowFinalWildcard: false)
        try expectCloseBracket()
        return DerivationPath(steps: steps, origin: .fingerprint(fingerprint))
    }
    
    func parseKey() throws -> DescriptorKeyExpression? {
        let transaction = Transaction(self)

        let origin = try parseOrigin()
        
        guard
            let token = tokens.next()
        else {
            return nil
        }
        let resultKey: DescriptorKeyExpression.Key?
        switch token.kind {
        case .data:
            let data = token.data
            if
                data.count == ECCompressedPublicKey.keyLen,
                [0x02, 0x03].contains(data[0])
            {
                resultKey = .ecCompressedPublicKey(ECCompressedPublicKey(data)!)
            } else if data.count == ECUncompressedPublicKey.keyLen {
                resultKey = .ecUncompressedPublicKey(ECUncompressedPublicKey(data)!)
            } else if data.count == ECXOnlyPublicKey.keyLen {
                resultKey = .ecXOnlyPublicKey(ECXOnlyPublicKey(data)!)
            } else {
                resultKey = nil
            }
        case .wif:
            resultKey = .wif(token.wif)
        case .hdKey:
            let key = token.hdKey
            let childSteps = try parseDerivationSteps(allowFinalWildcard: true)
            let children = DerivationPath(steps: childSteps)
            let key2 = HDKey(key: key.wally_ext_key, parent: origin, children: children)
            resultKey = .hdKey(key2)
        default:
            resultKey = nil
        }

        guard let result = resultKey else {
            return nil
        }
        
        transaction.commit()
        return DescriptorKeyExpression(origin: origin, key: result)
    }
}
