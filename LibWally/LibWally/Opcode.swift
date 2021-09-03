//
//  Opcode.swift
//  LibWally
//
//  Created by Wolf McNally on 9/3/21.
//

import Foundation

public enum Opcode {
    case literal(Int)
    case data(Data)
    
    case op_false
    case op_true
    
    case op_nop
    case op_ver
    case op_if
    case op_notif
    case op_verif
    case op_vernotif
    case op_else
    case op_endif
    case op_verify
    case op_return

    case op_toaltstack
    case op_fromaltstack
    case op_2drop
    case op_2dup
    case op_3dup
    case op_2over
    case op_2rot
    case op_2swap
    case op_ifdup
    case op_depth
    case op_drop
    case op_dup
    case op_nip
    case op_over
    case op_pick
    case op_roll
    case op_rot
    case op_swap
    case op_tuck

    case op_cat
    case op_substr
    case op_left
    case op_right
    case op_size

    case op_invert
    case op_and
    case op_or
    case op_xor
    case op_equal
    case op_equalverify
    case op_reserved1
    case op_reserved2

    case op_1add
    case op_1sub
    case op_2mul
    case op_2div
    case op_negate
    case op_abs
    case op_not
    case op_0notequal

    case op_add
    case op_sub
    case op_mul
    case op_div
    case op_mod
    case op_lshift
    case op_rshift

    case op_booland
    case op_boolor
    case op_numequal
    case op_numequalverify
    case op_numnotequal
    case op_lessthan
    case op_greaterthan
    case op_lessthanorequal
    case op_greaterthanorequal
    case op_min
    case op_max

    case op_within

    case op_ripemd160
    case op_sha1
    case op_sha256
    case op_hash160
    case op_hash256
    case op_codeseparator
    case op_checksig
    case op_checksigverify
    case op_checkmultisig
    case op_checkmultisigverify

    case op_nop1
    case op_checklocktimeverify
    case op_checksequenceverify
    case op_nop4
    case op_nop5
    case op_nop6
    case op_nop7
    case op_nop8
    case op_nop9
    case op_nop10

    case op_invalidopcode

    var serialized: Data? {
        switch self {
        case .literal(let value):
            return Self.serialize(int: value)
        case .data(let data):
            return Self.serialize(data: data)
        default:
            return Self.serialize(opcode: self)
        }
    }
    
    private static func serialize(int value: Int) -> Data? {
        switch value {
        case -1:
            return Data([0x48]) // OP_1NEGATE
        case 0:
            return Data([0x00]) // OP_0
        case 1...16:
            return Data([UInt8(value) - 1 + 0x51]) // OP_1
        default:
            return nil
        }
    }
    
    private static func serialize(data: Data) -> Data? {
        var result = Data()
        guard let countData = serialize(count: data.count) else {
            return nil
        }
        result.append(countData)
        result.append(data)
        return result
    }
    
    private static func serialize(count: Int) -> Data? {
        var result = Data()
        switch count {
        case 0...75:
            result.append(UInt8(count))
        case 76...Int(UInt8.max):
            result.append(UInt8(0x4c)) // OP_PUSHDATA1
            result.append(UInt8(count))
        case (Int(UInt8.max) + 1)...Int(UInt16.max):
            result.append(UInt8(0x4d)) // OP_PUSHDATA2
            result.append(Data(UInt16(count).serialized.reversed()))
        case (Int(UInt16.max) + 1)...Int(UInt32.max):
            result.append(UInt8(0x4e)) // OP_PUSHDATA4
            result.append(Data(UInt32(count).serialized.reversed()))
        default:
            return nil
        }
        return result
    }
    
    private var name: String? {
        guard
            let v = value,
            let s = Self.nameForValue[v]
        else {
            return nil
        }
        
        return s
    }
    
    private static func serialize(opcode: Opcode) -> Data? {
        guard let value = opcode.value else {
            return nil
        }
        return Data([value])
    }
    
    private static let opcodeForValue: [UInt8 : Opcode] = [
//        0x00 : .op_0,
//        0x00 : .op_false,
//        0x4c : .op_pushdata1,
//        0x4d : .op_pushdata2,
//        0x4e : .op_pushdata4,
//        0x4f : .op_1negate,
//        0x50 : .op_reserved,
//        0x51 : .op_1,
//        0x51 : .op_true,
//        0x52 : .op_2,
//        0x53 : .op_3,
//        0x54 : .op_4,
//        0x55 : .op_5,
//        0x56 : .op_6,
//        0x57 : .op_7,
//        0x58 : .op_8,
//        0x59 : .op_9,
//        0x5a : .op_10,
//        0x5b : .op_11,
//        0x5c : .op_12,
//        0x5d : .op_13,
//        0x5e : .op_14,
//        0x5f : .op_15,
//        0x60 : .op_16,

        0x61 : .op_nop,
        0x62 : .op_ver,
        0x63 : .op_if,
        0x64 : .op_notif,
        0x65 : .op_verif,
        0x66 : .op_vernotif,
        0x67 : .op_else,
        0x68 : .op_endif,
        0x69 : .op_verify,
        0x6a : .op_return,

        0x6b : .op_toaltstack,
        0x6c : .op_fromaltstack,
        0x6d : .op_2drop,
        0x6e : .op_2dup,
        0x6f : .op_3dup,
        0x70 : .op_2over,
        0x71 : .op_2rot,
        0x72 : .op_2swap,
        0x73 : .op_ifdup,
        0x74 : .op_depth,
        0x75 : .op_drop,
        0x76 : .op_dup,
        0x77 : .op_nip,
        0x78 : .op_over,
        0x79 : .op_pick,
        0x7a : .op_roll,
        0x7b : .op_rot,
        0x7c : .op_swap,
        0x7d : .op_tuck,

        0x7e : .op_cat,
        0x7f : .op_substr,
        0x80 : .op_left,
        0x81 : .op_right,
        0x82 : .op_size,

        0x83 : .op_invert,
        0x84 : .op_and,
        0x85 : .op_or,
        0x86 : .op_xor,
        0x87 : .op_equal,
        0x88 : .op_equalverify,
        0x89 : .op_reserved1,
        0x8a : .op_reserved2,

        0x8b : .op_1add,
        0x8c : .op_1sub,
        0x8d : .op_2mul,
        0x8e : .op_2div,
        0x8f : .op_negate,
        0x90 : .op_abs,
        0x91 : .op_not,
        0x92 : .op_0notequal,

        0x93 : .op_add,
        0x94 : .op_sub,
        0x95 : .op_mul,
        0x96 : .op_div,
        0x97 : .op_mod,
        0x98 : .op_lshift,
        0x99 : .op_rshift,

        0x9a : .op_booland,
        0x9b : .op_boolor,
        0x9c : .op_numequal,
        0x9d : .op_numequalverify,
        0x9e : .op_numnotequal,
        0x9f : .op_lessthan,
        0xa0 : .op_greaterthan,
        0xa1 : .op_lessthanorequal,
        0xa2 : .op_greaterthanorequal,
        0xa3 : .op_min,
        0xa4 : .op_max,

        0xa5 : .op_within,

        0xa6 : .op_ripemd160,
        0xa7 : .op_sha1,
        0xa8 : .op_sha256,
        0xa9 : .op_hash160,
        0xaa : .op_hash256,
        0xab : .op_codeseparator,
        0xac : .op_checksig,
        0xad : .op_checksigverify,
        0xae : .op_checkmultisig,
        0xaf : .op_checkmultisigverify,

        0xb0 : .op_nop1,
        0xb1 : .op_checklocktimeverify,
        0xb2 : .op_checksequenceverify,
        0xb3 : .op_nop4,
        0xb4 : .op_nop5,
        0xb5 : .op_nop6,
        0xb6 : .op_nop7,
        0xb7 : .op_nop8,
        0xb8 : .op_nop9,
        0xb9 : .op_nop10,

        0xff : .op_invalidopcode,
    ]
    
    private static let nameForValue: [UInt8: String] = [
        0x00 : "0",
        0x51 : "1",
        
        0x50 : "RESERVED",
        0x61 : "NOP",
        0x62 : "VER",
        0x63 : "IF",
        0x64 : "NOTIF",
        0x65 : "VERIF",
        0x66 : "VERNOTIF",
        0x67 : "ELSE",
        0x68 : "ENDIF",
        0x69 : "VERIFY",
        0x6a : "RETURN",

        0x6b : "TOALTSTACK",
        0x6c : "FROMALTSTACK",
        0x6d : "2DROP",
        0x6e : "2DUP",
        0x6f : "3DUP",
        0x70 : "2OVER",
        0x71 : "2ROT",
        0x72 : "2SWAP",
        0x73 : "IFDUP",
        0x74 : "DEPTH",
        0x75 : "DROP",
        0x76 : "DUP",
        0x77 : "NIP",
        0x78 : "OVER",
        0x79 : "PICK",
        0x7a : "ROLL",
        0x7b : "ROT",
        0x7c : "SWAP",
        0x7d : "TUCK",

        0x7e : "CAT",
        0x7f : "SUBSTR",
        0x80 : "LEFT",
        0x81 : "RIGHT",
        0x82 : "SIZE",

        0x83 : "INVERT",
        0x84 : "AND",
        0x85 : "OR",
        0x86 : "XOR",
        0x87 : "EQUAL",
        0x88 : "EQUALVERIFY",
        0x89 : "RESERVED1",
        0x8a : "RESERVED2",

        0x8b : "1ADD",
        0x8c : "1SUB",
        0x8d : "2MUL",
        0x8e : "2DIV",
        0x8f : "NEGATE",
        0x90 : "ABS",
        0x91 : "NOT",
        0x92 : "0NOTEQUAL",

        0x93 : "ADD",
        0x94 : "SUB",
        0x95 : "MUL",
        0x96 : "DIV",
        0x97 : "MOD",
        0x98 : "LSHIFT",
        0x99 : "RSHIFT",

        0x9a : "BOOLAND",
        0x9b : "BOOLOR",
        0x9c : "NUMEQUAL",
        0x9d : "NUMEQUALVERIFY",
        0x9e : "NUMNOTEQUAL",
        0x9f : "LESSTHAN",
        0xa0 : "GREATERTHAN",
        0xa1 : "LESSTHANOREQUAL",
        0xa2 : "GREATERTHANOREQUAL",
        0xa3 : "MIN",
        0xa4 : "MAX",

        0xa5 : "WITHIN",

        0xa6 : "RIPEMD160",
        0xa7 : "SHA1",
        0xa8 : "SHA256",
        0xa9 : "HASH160",
        0xaa : "HASH256",
        0xab : "CODESEPARATOR",
        0xac : "CHECKSIG",
        0xad : "CHECKSIGVERIFY",
        0xae : "CHECKMULTISIG",
        0xaf : "CHECKMULTISIGVERIFY",

        0xb0 : "NOP1",
        0xb1 : "CHECKLOCKTIMEVERIFY",
        0xb2 : "CHECKSEQUENCEVERIFY",
        0xb3 : "NOP4",
        0xb4 : "NOP5",
        0xb5 : "NOP6",
        0xb6 : "NOP7",
        0xb7 : "NOP8",
        0xb8 : "NOP9",
        0xb9 : "NOP10"
    ]
    
    private static let valueForName: [String: UInt8] = [
        "RESERVED" : 0x50,
        "NOP" : 0x61,
        "VER" : 0x62,
        "IF" : 0x63,
        "NOTIF" : 0x64,
        "VERIF" : 0x65,
        "VERNOTIF" : 0x66,
        "ELSE" : 0x67,
        "ENDIF" : 0x68,
        "VERIFY" : 0x69,
        "RETURN" : 0x6a,
        
        "TOALTSTACK" : 0x6b,
        "FROMALTSTACK" : 0x6c,
        "2DROP" : 0x6d,
        "2DUP" : 0x6e,
        "3DUP" : 0x6f,
        "2OVER" : 0x70,
        "2ROT" : 0x71,
        "2SWAP" : 0x72,
        "IFDUP" : 0x73,
        "DEPTH" : 0x74,
        "DROP" : 0x75,
        "DUP" : 0x76,
        "NIP" : 0x77,
        "OVER" : 0x78,
        "PICK" : 0x79,
        "ROLL" : 0x7a,
        "ROT" : 0x7b,
        "SWAP" : 0x7c,
        "TUCK" : 0x7d,

        "CAT" : 0x7e,
        "SUBSTR" : 0x7f,
        "LEFT" : 0x80,
        "RIGHT" : 0x81,
        "SIZE" : 0x82,

        "INVERT" : 0x83,
        "AND" : 0x84,
        "OR" : 0x85,
        "XOR" : 0x86,
        "EQUAL" : 0x87,
        "EQUALVERIFY" : 0x88,
        "RESERVED1" : 0x89,
        "RESERVED2" : 0x8a,

        "1ADD" : 0x8b,
        "1SUB" : 0x8c,
        "2MUL" : 0x8d,
        "2DIV" : 0x8e,
        "NEGATE" : 0x8f,
        "ABS" : 0x90,
        "NOT" : 0x91,
        "0NOTEQUAL" : 0x92,

        "ADD" : 0x93,
        "SUB" : 0x94,
        "MUL" : 0x95,
        "DIV" : 0x96,
        "MOD" : 0x97,
        "LSHIFT" : 0x98,
        "RSHIFT" : 0x99,

        "BOOLAND" : 0x9a,
        "BOOLOR" : 0x9b,
        "NUMEQUAL" : 0x9c,
        "NUMEQUALVERIFY" : 0x9d,
        "NUMNOTEQUAL" : 0x9e,
        "LESSTHAN" : 0x9f,
        "GREATERTHAN" : 0xa0,
        "LESSTHANOREQUAL" : 0xa1,
        "GREATERTHANOREQUAL" : 0xa2,
        "MIN" : 0xa3,
        "MAX" : 0xa4,

        "WITHIN" : 0xa5,

        "RIPEMD160" : 0xa6,
        "SHA1" : 0xa7,
        "SHA256" : 0xa8,
        "HASH160" : 0xa9,
        "HASH256" : 0xaa,
        "CODESEPARATOR" : 0xab,
        "CHECKSIG" : 0xac,
        "CHECKSIGVERIFY" : 0xad,
        "CHECKMULTISIG" : 0xae,
        "CHECKMULTISIGVERIFY" : 0xaf,

        "NOP1" : 0xb0,
        "CHECKLOCKTIMEVERIFY" : 0xb1,
        "NOP2" : 0xb1,
        "CHECKSEQUENCEVERIFY" : 0xb2,
        "NOP3" : 0xb2,
        "NOP4" : 0xb3,
        "NOP5" : 0xb4,
        "NOP6" : 0xb5,
        "NOP7" : 0xb6,
        "NOP8" : 0xb7,
        "NOP9" : 0xb8,
        "NOP10" : 0xb9
    ]
    
    private var value: UInt8? {
        switch self {
        case .op_false: return 0x00
//        case .op_pushdata1: return 0x4c
//        case .op_pushdata2: return 0x4d
//        case .op_pushdata4: return 0x4e
//        case .op_1negate: return 0x4f
//        case .op_reserved: return 0x50
        case .op_true: return 0x51
//        case .op_2: return 0x52
//        case .op_3: return 0x53
//        case .op_4: return 0x54
//        case .op_5: return 0x55
//        case .op_6: return 0x56
//        case .op_7: return 0x57
//        case .op_8: return 0x58
//        case .op_9: return 0x59
//        case .op_10: return 0x5a
//        case .op_11: return 0x5b
//        case .op_12: return 0x5c
//        case .op_13: return 0x5d
//        case .op_14: return 0x5e
//        case .op_15: return 0x5f
//        case .op_16: return 0x60

        case .op_nop: return 0x61
        case .op_ver: return 0x62
        case .op_if: return 0x63
        case .op_notif: return 0x64
        case .op_verif: return 0x65
        case .op_vernotif: return 0x66
        case .op_else: return 0x67
        case .op_endif: return 0x68
        case .op_verify: return 0x69
        case .op_return: return 0x6a
        case .op_toaltstack: return 0x6b
        case .op_fromaltstack: return 0x6c
        case .op_2drop: return 0x6d
        case .op_2dup: return 0x6e
        case .op_3dup: return 0x6f

        case .op_2over: return 0x70
        case .op_2rot: return 0x71
        case .op_2swap: return 0x72
        case .op_ifdup: return 0x73
        case .op_depth: return 0x74
        case .op_drop: return 0x75
        case .op_dup: return 0x76
        case .op_nip: return 0x77
        case .op_over: return 0x78
        case .op_pick: return 0x79
        case .op_roll: return 0x7a
        case .op_rot: return 0x7b
        case .op_swap: return 0x7c
        case .op_tuck: return 0x7d
        case .op_cat: return 0x7e
        case .op_substr: return 0x7f

        case .op_left: return 0x80
        case .op_right: return 0x81
        case .op_size: return 0x82
        case .op_invert: return 0x83
        case .op_and: return 0x84
        case .op_or: return 0x85
        case .op_xor: return 0x86
        case .op_equal: return 0x87
        case .op_equalverify: return 0x88
        case .op_reserved1: return 0x89
        case .op_reserved2: return 0x8a
        case .op_1add: return 0x8b
        case .op_1sub: return 0x8c
        case .op_2mul: return 0x8d
        case .op_2div: return 0x8e
        case .op_negate: return 0x8f

        case .op_abs: return 0x90
        case .op_not: return 0x91
        case .op_0notequal: return 0x92
        case .op_add: return 0x93
        case .op_sub: return 0x94
        case .op_mul: return 0x95
        case .op_div: return 0x96
        case .op_mod: return 0x97
        case .op_lshift: return 0x98
        case .op_rshift: return 0x99
        case .op_booland: return 0x9a
        case .op_boolor: return 0x9b
        case .op_numequal: return 0x9c
        case .op_numequalverify: return 0x9d
        case .op_numnotequal: return 0x9e
        case .op_lessthan: return 0x9f

        case .op_greaterthan: return 0xa0
        case .op_lessthanorequal: return 0xa1
        case .op_greaterthanorequal: return 0xa2
        case .op_min: return 0xa3
        case .op_max: return 0xa4
        case .op_within: return 0xa5
        case .op_ripemd160: return 0xa6
        case .op_sha1: return 0xa7
        case .op_sha256: return 0xa8
        case .op_hash160: return 0xa9
        case .op_hash256: return 0xaa
        case .op_codeseparator: return 0xab
        case .op_checksig: return 0xac
        case .op_checksigverify: return 0xad
        case .op_checkmultisig: return 0xae
        case .op_checkmultisigverify: return 0xaf

        case .op_nop1: return 0xb0
        case .op_checklocktimeverify: return 0xb1
        case .op_checksequenceverify: return 0xb2
        case .op_nop4: return 0xb3
        case .op_nop5: return 0xb4
        case .op_nop6: return 0xb5
        case .op_nop7: return 0xb6
        case .op_nop8: return 0xb7
        case .op_nop9: return 0xb8
        case .op_nop10: return 0xb9
            
        default: return nil
        }
    }
}

extension Opcode {
    public init(data: Data) {
        self = .data(data)
    }
    
    public init?(hex: String) {
        guard let data = Data(hex: hex) else {
            return nil
        }
        self = .data(data)
    }
}

extension Opcode : CustomStringConvertible {
    public var description: String {
        switch self {
        case .literal(let value):
            return String(describing: value)
        case .data(let data):
            return "[\(data.hex)]"
        default:
            return name ?? "UNKNOWN"
        }
    }
}

extension Opcode : ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: BooleanLiteralType) {
        switch value {
        case true:
            self = .op_true
        case false:
            self = .op_false
        }
    }
}

extension Opcode : ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.init(data: Data(hex: value)!)
    }
}

extension Opcode : ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) {
        self = .literal(value)
    }
}

//public struct Script {
//    public let data: Data
//
//    private static var opToName: [UInt8 : String] = {
//        var result: [UInt8 : String] = [:]
//
//        for op in Opcode.allCases {
//            let s = String(String(describing: op).dropFirst(3))
//            assert(result[op.rawValue] == nil)
//            result[op.rawValue] = s
//        }
//
//        assert(result.count == 256)
//
//        return result
//    }()
//
//    public static func name(for op: Opcode) -> String {
//        String(describing: op).dropFirst(3).uppercased()
//    }
//
//}
