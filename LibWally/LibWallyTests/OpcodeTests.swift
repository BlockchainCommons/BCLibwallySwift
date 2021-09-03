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
//        let o: [Opcode] = [1, "0012", .op_checksig, false, true]
//        let o: [Opcode] = [false]
        let o: [Opcode] = [
            .op_dup, .op_hash160, "89ABCDEFABBAABBAABBAABBAABBAABBAABBAABBA", .op_equalverify, .op_checksig
        ]
        print(o.map({$0.description}).joined(separator: " ").flanked("[", "]"))
    }
}

extension String {
    func flanked(_ leading: String, _ trailing: String) -> String {
        leading + self + trailing
    }
}
