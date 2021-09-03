//
//  OpcodeTests.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/3/21.
//

import XCTest
import LibWally

class OpcodeTests: XCTestCase {
    func testExample() throws {
//        XCTAssertEqual(Script.name(for: .op_checksig), "CHECKSIG")
        let o: [Opcode] = [1, "0012", .op_checksig, false]
    }
}
