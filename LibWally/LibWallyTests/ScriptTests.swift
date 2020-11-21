//
//  ScriptTests.swift
//  ScriptTests
//
//  Created by Sjors on 14/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import LibWally
import CLibWally

class ScriptTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testDetectScriptPubKeyTypeP2PKH() throws {
        let scriptPubKey = try ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
        XCTAssertEqual(scriptPubKey.type, .payToPubKeyHash)
    }

    func testDetectScriptPubKeyTypeP2SH() throws {
        let scriptPubKey = try ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")
        XCTAssertEqual(scriptPubKey.type, .payToScriptHash)
    }

    func testDetectScriptPubKeyTypeNativeSegWit() throws {
        let scriptPubKey = try ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        XCTAssertEqual(scriptPubKey.type, .payToWitnessPubKeyHash)
    }

    func testDetectScriptPubKeyTypeOpReturn() throws {
        let scriptPubKey = try ScriptPubKey(hex: "6a13636861726c6579206c6f766573206865696469")
        XCTAssertEqual(scriptPubKey.type, .opReturn)
    }

    func testScriptSigP2PKH() throws {
        let pubKey = try PubKey(Data(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"), .mainnet)
        var scriptSig = ScriptSig(.payToPubKeyHash(pubKey))
        XCTAssertEqual(scriptSig.type, ScriptSigType.payToPubKeyHash(pubKey))
        XCTAssertEqual(scriptSig.render(.signed), nil)

        XCTAssertEqual(scriptSig.signature, nil)

        XCTAssertEqual(scriptSig.render(.feeWorstCase)?.count, 2 + Int(EC_SIGNATURE_DER_MAX_LOW_R_LEN) + 1 + pubKey.data.count)

        scriptSig.signature = try Signature(hex: "01")
        let sigHashByte = try Data(hex: "01") // SIGHASH_ALL
        let signaturePush = try Data(hex: "02") + scriptSig.signature! + sigHashByte
        let pubKeyPush = Data([UInt8(pubKey.data.count)]) + pubKey.data
        XCTAssertEqual(scriptSig.render(.signed)?.hex, (signaturePush + pubKeyPush).hex)
    }

    func testWitnessP2WPKH() throws {
        let pubKey = try PubKey(Data(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"), .mainnet)
        let witness = Witness(.payToWitnessPubKeyHash(pubKey))
        XCTAssertEqual(witness.dummy, true)
        XCTAssertEqual(witness.stack?.pointee.num_items, 2)
        XCTAssertEqual(witness.scriptCode.hex, "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
        let signedWitness = try Witness(.payToWitnessPubKeyHash(pubKey), Signature(hex: "01"))
        XCTAssertEqual(signedWitness.stack?.pointee.num_items, 2)

    }

    func testMultisig() throws {
        let pubKey1 = try PubKey(Data(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"), .mainnet) // [3442193e/0'/1]
        let pubKey2 = try PubKey(Data(hex: "022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a554737"), .mainnet) // [bd16bee5/0'/1]
        let multisig = ScriptPubKey(multisig: [pubKey1, pubKey2], threshold: 2)
        XCTAssertEqual(multisig.type, .multiSig)
        XCTAssertEqual(multisig.bytes.hex, "5221022e3d55c64908832291348d1faa74bff4ae1047e9777a28b26b064e410a5547372103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c52ae")
        XCTAssertEqual(multisig.witnessProgram.hex, "0020ce8c526b7a6c9491ed33861f4492299c86ffa8567a75286535f317ddede3062a")

        let address = try Address(multisig, .mainnet)
        XCTAssertEqual(address.address, "bc1qe6x9y6m6dj2frmfnsc05fy3fnjr0l2zk0f6jsef47vtamm0rqc4qnfnxm0")
    }
    
    func testScriptPubKeyAddress() throws {
        let scriptPubKeyPKH = try ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
        XCTAssertEqual(scriptPubKeyPKH.type, .payToPubKeyHash)
        XCTAssertEqual(try Address(scriptPubKeyPKH, .mainnet).description, "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj")
        XCTAssertEqual(try Address(scriptPubKeyPKH, .testnet).description, "mxvewdhKCenLkYgNa8irv1UM2omEWPMdEE")
    
        let scriptPubKeyP2SH = try ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")
        XCTAssertEqual(scriptPubKeyP2SH.type, .payToScriptHash)
        XCTAssertEqual(try Address(scriptPubKeyP2SH, .mainnet).description, "3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu")
        XCTAssertEqual(try Address(scriptPubKeyP2SH, .testnet).description, "2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD")

        let scriptP2WPKH = try ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        XCTAssertEqual(scriptP2WPKH.type, .payToWitnessPubKeyHash)
        XCTAssertEqual(try Address(scriptP2WPKH, .mainnet).description, "bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt")
        
        let scriptP2WSH = try ScriptPubKey(hex: "0020f8608e6e5b537f8fc8182eb113cf40f564b99cf99d87170c4f1ac259074ee8fd")
        XCTAssertEqual(scriptP2WSH.type, .payToWitnessScriptHash)
        XCTAssertEqual(try Address(scriptP2WSH, .mainnet).description, "bc1qlpsgumjm2dlcljqc96c38n6q74jtn88enkr3wrz0rtp9jp6war7s2h4lrs")
    }
}
