//
//  DescriptorLexer.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
@_implementationOnly import Flexer
@_implementationOnly import WolfBase

final class DescriptorParser: Parser {
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
    
    func parse() throws -> DescriptorFunction {
        if let raw = try parseRaw() {
            return raw
        }
        if let pk = try parsePK() {
            return pk
        }
        if let pkh = try parsePKH() {
            return pkh
        }
        if let wpkh = try parseWPKH() {
            return wpkh
        }
        if let multi = try parseMulti() {
            return multi
        }
        if let sh = try parseSH() {
            return sh
        }
        if let addr = try parseAddr() {
            return addr
        }
        throw error("Expected top level function.")
    }
    
    func parseFingerprint() -> UInt32? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .data,
            token.data.count == 4
        else {
            return nil
        }
        transaction.commit()
        return deserialize(UInt32.self, token.data)
    }
    
    func expectFingerprint() throws -> UInt32 {
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

    func parseKind(_ kind: DescriptorToken.Kind) -> Bool {
        parseToken(kind: kind) != nil
    }
    
    func parseInt() -> Int? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .int
        else {
            return nil
        }
        let i = token.int
        transaction.commit()
        return i
    }
    
    func expectInt() throws -> Int {
        guard let i = parseInt() else {
            throw error("Expected integer.")
        }
        return i
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
        parseKind(.star)
    }

    func parseOpenParen() -> Bool {
        parseKind(.openParen)
    }
    
    func expectOpenParen() throws {
        guard parseOpenParen() else {
            throw error("Expected open parenthesis.")
        }
    }

    func parseCloseParen() -> Bool {
        parseKind(.closeParen)
    }
    
    func expectCloseParen() throws {
        guard parseCloseParen() else {
            throw error("Expected close parenthesis.")
        }
    }

    func parseOpenBracket() -> Bool {
        parseKind(.openBracket)
    }

    func parseCloseBracket() -> Bool {
        parseKind(.closeBracket)
    }
    
    func expectCloseBracket() throws {
        guard parseCloseBracket() else {
            throw error("Expected close bracket.")
        }
    }
    
    func parseComma() -> Bool {
        parseKind(.comma)
    }
    
    func expectComma() throws {
        guard parseComma() else {
            throw error("Expected comma.")
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
    
    func parseData() -> Data? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .data
        else {
            return nil
        }
        transaction.commit()
        return token.data
    }
    
    func expectData() throws -> Data {
        guard let data = parseData() else {
            throw error("Expected data.")
        }
        return data
    }

    func parseKey(allowUncompressed: Bool = true) throws -> DescriptorKeyExpression? {
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
            } else if
                allowUncompressed,
                data.count == ECUncompressedPublicKey.keyLen
            {
                resultKey = .ecUncompressedPublicKey(ECUncompressedPublicKey(data)!)
            // } else if data.count == ECXOnlyPublicKey.keyLen {
            //     resultKey = .ecXOnlyPublicKey(ECXOnlyPublicKey(data)!)
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
    
    func expectKey(allowUncompressed: Bool = true) throws -> DescriptorKeyExpression {
        guard let key = try parseKey(allowUncompressed: allowUncompressed) else {
            throw error("Expected key expression.")
        }
        return key
    }
    
    func expectKeyList(allowUncompressed: Bool = true) throws -> [DescriptorKeyExpression] {
        let transaction = Transaction(self)
        var result: [DescriptorKeyExpression] = []
        while parseComma() {
            try result.append(expectKey(allowUncompressed: allowUncompressed))
        }
        guard !result.isEmpty else {
            throw error("Expected list of keys.")
        }
        transaction.commit()
        return result
    }
    
    func parseAddress() -> Address? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .address
        else {
            return nil
        }
        transaction.commit()
        return token.address
    }

    func expectAddress() throws -> Address {
        guard let address = parseAddress() else {
            throw error("Expected address.")
        }
        return address
    }
    
    func parseScript() -> Script? {
        let transaction = Transaction(self)
        guard
            let token = tokens.next(),
            token.kind == .data
        else {
            return nil
        }
        let script = Script(token.data)
        guard script.operations != nil else {
            return nil
        }
        transaction.commit()
        return script
    }
    
    func expectScript() throws -> Script {
        guard let script = parseScript() else {
            throw error("Expected script.")
        }
        return script
    }

    func parseRaw() throws -> DescriptorRaw? {
        guard parseKind(.raw) else {
            return nil
        }
        try expectOpenParen()
        let data = try expectData()
        try expectCloseParen()
        return DescriptorRaw(data: data)
    }
    
    func parsePK() throws -> DescriptorPK? {
        guard parseKind(.pk) else {
            return nil
        }
        try expectOpenParen()
        let key = try expectKey()
        try expectCloseParen()
        return DescriptorPK(key: key)
    }
    
    func parsePKH() throws -> DescriptorPKH? {
        guard parseKind(.pkh) else {
            return nil
        }
        try expectOpenParen()
        let key = try expectKey()
        try expectCloseParen()
        return DescriptorPKH(key: key)
    }
    
    func parseWPKH() throws -> DescriptorWPKH? {
        guard parseKind(.wpkh) else {
            return nil
        }
        try expectOpenParen()
        let key = try expectKey()
        try expectCloseParen()
        return DescriptorWPKH(key: key)
    }

    func parseSH() throws -> DescriptorSH? {
        guard parseKind(.sh) else {
            return nil
        }
        try expectOpenParen()
        let script = try expectScript()
        try expectCloseParen()
        return DescriptorSH(script: script)
    }

    func parseAddr() throws -> Address? {
        guard parseKind(.addr) else {
            return nil
        }
        try expectOpenParen()
        let address = try expectAddress()
        try expectCloseParen()
        return address
    }
    
    func parseMulti() throws -> DescriptorMulti? {
        let isSorted: Bool
        if parseKind(.multi) {
            isSorted = false
        } else if parseKind(.sortedmulti) {
            isSorted = true
        } else {
            return nil
        }
        try expectOpenParen()
        let threshold = try expectInt()
        let keys = try expectKeyList(allowUncompressed: false)
        try expectCloseParen()
        return DescriptorMulti(threshold: threshold, keys: keys, isSorted: isSorted)
    }
}

struct DescriptorRaw: DescriptorFunction {
    let data: Data
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> ScriptPubKey? {
        ScriptPubKey(Script(data))
    }
}

struct DescriptorPK: DescriptorFunction {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> ScriptPubKey? {
        guard let data = key.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.data(data), .op(.op_checksig)]))
    }
}

struct DescriptorPKH: DescriptorFunction {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> ScriptPubKey? {
        guard let data = key.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_dup), .op(.op_hash160), .data(data.hash160), .op(.op_equalverify), .op(.op_checksig)]))
    }
}

struct DescriptorWPKH: DescriptorFunction {
    let key: DescriptorKeyExpression
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> ScriptPubKey? {
        guard let data = key.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) else {
            return nil
        }
        return ScriptPubKey(Script(ops: [.op(.op_0), .data(data.hash160)]))
    }
}

struct DescriptorSH: DescriptorFunction {
    let script: Script
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> ScriptPubKey? {
        ScriptPubKey(Script(ops: [.op(.op_hash160), .data(script.data.hash160), .op(.op_equal)]))
    }
}

extension Address: DescriptorFunction {
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> ScriptPubKey? {
        scriptPubKey
    }
}

struct DescriptorMulti: DescriptorFunction {
    let threshold: Int
    let keys: [DescriptorKeyExpression]
    let isSorted: Bool
    
    func scriptPubKey(wildcardChildNum: UInt32?, privateKeyProvider: PrivateKeyProvider?) -> ScriptPubKey? {
        var ops: [ScriptOperation] = []
        ops.append(.op(ScriptOpcode(int: threshold)!))
        
        var rawKeys = keys.compactMap { $0.pubKeyData(wildcardChildNum: wildcardChildNum, privateKeyProvider: privateKeyProvider) }
        guard rawKeys.count == keys.count else {
            return nil
        }
        if isSorted {
            rawKeys.sort { $0.lexicographicallyPrecedes($1) }
        }
        for rawKey in rawKeys {
            ops.append(.data(rawKey))
        }
        ops.append(.op(ScriptOpcode(int: keys.count)!))
        ops.append(.op(.op_checkmultisig))
        return ScriptPubKey(Script(ops: ops))
    }
}
