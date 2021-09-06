//
//  Operation.swift
//  LibWally
//
//  Created by Wolf McNally on 9/5/21.
//

import Foundation
@_implementationOnly import WolfBase

public enum Operation: Equatable {
    case data(Data)
    case op(Opcode)
    
    public init(_ data: Data) {
        self = .data(data)
    }
    
    public init(_ opcode: Opcode) {
        self = .op(opcode)
    }
    
    public init?(_ string: String) {
        if let opcode = Opcode(name: string) {
            self = .op(opcode)
        } else if let data = Data(hex: string) {
            self = .data(data)
        } else {
            return nil
        }
    }

    public var serialized: Data {
        var result = Data()
        switch self {
        case .op(let opcode):
            result.append(opcode.rawValue)
        case .data(let data):
            let count = data.count
            switch count {
            case 0x00...0x4b:
                result.append(UInt8(count))
                result.append(data)
            case 0x4c...0xff:
                result.append(Opcode.op_pushdata1.rawValue)
                result.append(serialize(UInt8(count), littleEndian: true))
                result.append(data)
            case 0x100...0xffff:
                result.append(Opcode.op_pushdata2.rawValue)
                result.append(serialize(UInt16(count), littleEndian: true))
                result.append(data)
            case 0x10000...0xffffffff:
                result.append(Opcode.op_pushdata4.rawValue)
                result.append(serialize(UInt32(count), littleEndian: true))
                result.append(data)
            default:
                fatalError()
            }
        }
        return result
    }
}
