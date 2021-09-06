//
//  OpcodeTests.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/3/21.
//

import XCTest
@testable import LibWally

class OpcodeTests: XCTestCase {
    func testConversions() {
        for op in Opcode.ops {
            let (symbol, name, rawValue) = op
            XCTAssertEqual(symbol.rawValue, rawValue)
            XCTAssertEqual(Opcode(rawValue: rawValue), symbol)
            XCTAssertEqual(symbol.name, name)
            XCTAssertEqual(Opcode(name: name), symbol)
        }
    }
    
    func testAliases() {
        XCTAssertEqual(Opcode(name: "op_0"), .op_false)
        XCTAssertEqual(Opcode(name: "OP_1"), .op_true)
        XCTAssertEqual(Opcode(name: "OP_NOP2"), .op_checklocktimeverify)
        XCTAssertEqual(Opcode(name: "OP_NOP3"), .op_checksequenceverify)
    }
}
