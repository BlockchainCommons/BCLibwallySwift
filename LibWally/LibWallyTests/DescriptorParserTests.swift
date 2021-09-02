//
//  DescriptorParserTests.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/1/21.
//

import XCTest
import LibWally

class DescriptorParserTests: XCTestCase {
    func testExample() throws {
        try print(Descriptor("[01234567]"))
        try print(Descriptor("[01234567/1/2/3/4]"))
        try print(Descriptor("[01234567/1'/2'/3'/4']"))
        try print(Descriptor("[01234567/1h/2h/3h/4h]"))
    }
}
