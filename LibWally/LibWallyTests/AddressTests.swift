//
//  AddressTests.swift
//  AddressTests
//
//  Created by Bitcoin Dev on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import LibWally

class AddressTests: XCTestCase {
    let hdKey = try! HDKey("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
    let hdKeyTestnet = try! HDKey("tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ")


    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testDeriveLegacyAddress() {
        let address = hdKey.address(.payToPubKeyHash)
        XCTAssertEqual(address.description, "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")
    }

    func testDeriveLegacyAddressTestnet() {
        let address = hdKeyTestnet.address(.payToPubKeyHash)
        XCTAssertEqual(address.description, "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
    }

    
    func testDeriveWrappedSegWitAddress() {
        let address = hdKey.address(.payToScriptHashPayToWitnessPubKeyHash)
        XCTAssertEqual(address.description, "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
    }
    
    func testDeriveWrappedSegWitAddressTestnet() {
        let address = hdKeyTestnet.address(.payToScriptHashPayToWitnessPubKeyHash)
        XCTAssertEqual(address.description, "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
    }
    
    
    func testDeriveNativeSegWitAddress() {
        let address = hdKey.address(.payToWitnessPubKeyHash)
        XCTAssertEqual(address.description, "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")
    }
    
    func testDeriveNativeSegWitAddressTestnet() {
        let address = hdKeyTestnet.address(.payToWitnessPubKeyHash)
        XCTAssertEqual(address.description, "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
    }
    
    func testParseLegacyAddress() throws {
        let address = try Address("1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")
        XCTAssertEqual(address.scriptPubKey, try ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac"))
    }
    
    func testParseWrappedSegWitAddress() throws {
        let address = try Address("3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
        XCTAssertEqual(address.scriptPubKey, try ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987"))
    }
    
    func testParseNativeSegWitAddress() throws {
        let address = try Address("bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")
        XCTAssertEqual(address.scriptPubKey, try ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe"))
    }
    
    func testParseWIF() throws {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        let key = try Key(wif, .mainnet, isCompressed: false)
        XCTAssertEqual(key.data.hex, "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        XCTAssertEqual(key.network, .mainnet)
        XCTAssertEqual(key.isCompressed, false)
    }

    func testToWIF() throws {
        // https://en.bitcoin.it/wiki/Wallet_import_format
        let data = try Data(hex: "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        let key = try Key(data, .mainnet, isCompressed: false)
        XCTAssertEqual(key.wif, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    }

}
