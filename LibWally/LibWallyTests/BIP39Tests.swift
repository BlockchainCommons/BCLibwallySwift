//
//  BIP39Tests.swift
//  BIP39Tests
//
//  Created by Sjors on 27/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md.
//

import XCTest
@testable import LibWally

class BIP39Tests: XCTestCase {
    let validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    let validMnemonic24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testGetWordList() {
        // Check length
        XCTAssertEqual(BIP39Words.count, 2048)
        
        // Check first word
        XCTAssertEqual(BIP39Words.first, "abandon")
    }
    
    func testMnemonicIsValid() {
        XCTAssertTrue(BIP39Mnemonic.isValid(validMnemonic))
        XCTAssertFalse(BIP39Mnemonic.isValid("notavalidword"))
        XCTAssertFalse(BIP39Mnemonic.isValid("abandon"))
        XCTAssertFalse(BIP39Mnemonic.isValid(["abandon", "abandon"]))
    }
    
    func testInitializeMnemonic() throws {
        let mnemonic = try BIP39Mnemonic(words: validMnemonic)
        XCTAssertEqual(mnemonic.words, validMnemonic.components(separatedBy: " "))
    }
    
    func testInitializeMnemonicFromBytes() throws {
        let bytes = [Int8](repeating: 0, count: 32)
        let entropy = BIP39Entropy(Data(bytes: bytes, count: 32))
        let mnemonic = try BIP39Mnemonic(entropy: entropy)
        XCTAssertEqual(mnemonic.words, validMnemonic24.components(separatedBy: " "))
    }
    
    func testInitializeInvalidMnemonic() {
        XCTAssertThrowsError(try BIP39Mnemonic(words: ["notavalidword"]))
    }
    
    func testMnemonicLosslessStringConvertible() throws {
        let mnemonic = try BIP39Mnemonic(words: validMnemonic)
        XCTAssertEqual(mnemonic.description, validMnemonic)
    }
    
    func testMnemonicToEntropy() throws {
        let mnemonic = try BIP39Mnemonic(words: validMnemonic)
        XCTAssertEqual(mnemonic.entropy.description, "00000000000000000000000000000000")
        let mnemonic2 = try BIP39Mnemonic(words: "legal winner thank year wave sausage worth useful legal winner thank yellow")
        XCTAssertEqual(mnemonic2.entropy.description, "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
    }
    
    func testEntropyToMnemonic() throws {
        let expectedMnemonic = try BIP39Mnemonic(words: "legal winner thank year wave sausage worth useful legal winner thank yellow")
        let entropy = try BIP39Entropy(hex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        let mnemonic = try BIP39Mnemonic(entropy: entropy)
        XCTAssertEqual(mnemonic, expectedMnemonic)
    }
    
    
    func testEntropyLosslessStringConvertible() throws {
        let entropy = try BIP39Entropy(hex: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        XCTAssertEqual(entropy.description, "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
    }
    
    func testMnemonicToSeedHexString() throws {
        let mnemonic = try BIP39Mnemonic(words: validMnemonic)
        XCTAssertEqual(mnemonic.seedHex("TREZOR").description, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
        XCTAssertEqual(mnemonic.seedHex().description, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
        XCTAssertEqual(mnemonic.seedHex("").description, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
    }
    
    func testSeedLosslessStringConvertible() throws {
        let mnemonic = try BIP39Mnemonic(words: validMnemonic)
        let expectedSeed = mnemonic.seedHex("TREZOR")
        let parsedSeed = try BIP39Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
        XCTAssertEqual(parsedSeed, expectedSeed)
    }


}
