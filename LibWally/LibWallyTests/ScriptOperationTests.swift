//
//  ScriptOperationTests.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/6/21.
//

import XCTest
import LibWally
import WolfBase

class ScriptOperationTests: XCTestCase {
    func testInit() {
        let ops: [ScriptOperation] = [.data(Data(hex: "00112233")!), .op(.op_equalverify)]
        XCTAssertEqual(ops†, "[00112233, OP_EQUALVERIFY]")
    }
    
    func testInitFromString() {
        let ops: [ScriptOperation] = [.init("00112233")!, .init("OP_EQUALVERIFY")!]
        XCTAssertEqual(ops†, "[00112233, OP_EQUALVERIFY]")
    }
    
    func testSerialize() {
        XCTAssertEqual(ScriptOperation(Data(repeating: 0, count: 1)).serialized.hex, "0100")
        XCTAssertEqual(ScriptOperation(Data(repeating: 0, count: 2)).serialized.hex, "020000")
        XCTAssertEqual(ScriptOperation(Data(repeating: 0, count: 0x4d)).serialized.hex, "4c4d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        XCTAssertEqual(ScriptOperation(Data(repeating: 0, count: 0x105)).serialized.hex, "4d0501000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    }
}
