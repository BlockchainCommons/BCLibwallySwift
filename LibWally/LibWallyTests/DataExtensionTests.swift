//
//  DataExtensionTests.swift
//  DataExtensionTests
//
//  Created by Sjors Provoost on 05/12/2019.
//  Copyright © 2019 Sjors Provoost. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import LibWally

class DataExtensionTests: XCTestCase {
    func testHexString() throws {
        let hex = "01234567890abcde"
        let data = try Data(hex: hex)
        XCTAssertEqual(data.hex, hex)
    }

    func testToBase58() throws {
        let data = try Data(hex: "01234567890abcde")
        XCTAssertEqual(data.base58, "2FEDkTt23zPwhDwc")
    }

    func testFromBase58() throws {
        let base58 = "2FEDkTt23zPwhDwc"
        let data = try Data(base58: base58)
        XCTAssertEqual(data.hex, "01234567890abcde")
    }

    func testInvalidCharacter() {
        let base58 = "💩"
        XCTAssertThrowsError(try Data(base58: base58))
    }
}
