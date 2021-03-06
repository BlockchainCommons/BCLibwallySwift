//
//  TransactionTests.swift
//  TransactionTests
//
//  Created by Sjors Provoost on 18/06/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import LibWally

class TransactionTests: XCTestCase {
    let scriptPubKey = try! ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
    let pubKey = try! PubKey(Data(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"), network: .mainnet)

    func testFromHash() throws {
        let hash = "0000000000000000000000000000000000000000000000000000000000000000"
        let tx = try Transaction(hex: hash)
        XCTAssertEqual(tx.hash!.hex, hash)

        XCTAssertThrowsError(try Transaction(hex: "00")) // Wrong length
    }

    func testOutput() {
        let output = TxOutput(scriptPubKey: scriptPubKey, amount: 1000, network: .mainnet)
        XCTAssertNotNil(output)
        XCTAssertEqual(output.amount, 1000)
        XCTAssertEqual(output.scriptPubKey, scriptPubKey)
    }

    func testInput() throws {
        let prevTx = try Transaction(hex: "0000000000000000000000000000000000000000000000000000000000000000")
        let vout: UInt32 = 0
        let amount: Satoshi = 1000
        let scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))

        let input = try TxInput(txHash: prevTx.hash!, vout: vout, amount: amount, scriptSig: scriptSig, witness: nil, scriptPubKey: scriptPubKey)
        XCTAssertEqual(input.txHash, prevTx.hash)
        XCTAssertEqual(input.vout, 0)
        XCTAssertEqual(input.sequence, 0xFFFFFFFF)
        XCTAssertEqual(input.scriptSig!.type, scriptSig.type)
        XCTAssertEqual(input.isSigned, false)
    }

    func testComposeTransaction() throws {
        // Input
        let prevTx = try Transaction(hex: "0000000000000000000000000000000000000000000000000000000000000000")
        let vout: UInt32 = 0
        let amount: Satoshi = 1000
        let scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))
        let txInput = try TxInput(txHash: prevTx.hash!, vout: vout, amount: amount, scriptSig: scriptSig, witness: nil, scriptPubKey: scriptPubKey)

        // Output:
        let txOutput = TxOutput(scriptPubKey: scriptPubKey, amount: 1000, network: .mainnet)

        // Transaction
        let tx = Transaction(inputs: [txInput], outputs: [txOutput])
        XCTAssertNil(tx.hash)
        let wtx = tx.tx!.pointee
        XCTAssertEqual(wtx.version, 1)
        XCTAssertEqual(wtx.num_inputs, 1)
        XCTAssertEqual(wtx.num_outputs, 1)
    }
    
    func testDeserialize() throws {
        let hex = "01000000010000000000000000000000000000000000000000000000000000000000000000000000006a47304402203d274300310c06582d0186fc197106120c4838fa5d686fe3aa0478033c35b97802205379758b11b869ede2f5ab13a738493a93571268d66b2a875ae148625bd20578012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711cffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac00000000"
        let tx = try Transaction(hex: hex)
        XCTAssertEqual(tx.description, hex)
    }
    
}

class TransactionInstanceTests: XCTestCase {
    let legacyInputBytes: Int = 192
    let nativeSegWitInputBytes: Int = 113
    let wrappedSegWitInputBytes: Int = 136

    // From: legacy P2PKH address 1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj
    // To: legacy P2PKH address 1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj
    let scriptPubKey1 = try! ScriptPubKey(hex: "76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac")
    let pubKey = try! PubKey(Data(hex: "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"), network: .mainnet)
    var tx1: Transaction! = nil
    var tx2: Transaction! = nil
    var tx3: Transaction! = nil
    var hdKey: HDKey! = nil // private key for signing
    
    override func setUp() {
        // Input (legacy P2PKH)
        let prevTx = try! Transaction(hex: "0000000000000000000000000000000000000000000000000000000000000000")
        let vout: UInt32 = 0
        let amount1: Satoshi = 1000 + Satoshi(legacyInputBytes)
        let scriptSig = ScriptSig(type: .payToPubKeyHash(pubKey))
        let txInput1 = try! TxInput(txHash: prevTx.hash!, vout: vout, amount: amount1, scriptSig: scriptSig, witness: nil, scriptPubKey: scriptPubKey1)

        // Input (native SegWit)
        let witness = Witness(type: .payToWitnessPubKeyHash(pubKey))
        let amount2: Satoshi = 1000 + Satoshi(nativeSegWitInputBytes)
        let scriptPubKey2 = try! ScriptPubKey(hex: "0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")
        let txInput2 = try! TxInput(txHash: prevTx.hash!, vout: vout, amount: amount2, scriptSig: nil, witness: witness, scriptPubKey: scriptPubKey2)

        // Input (wrapped SegWit)
        let witness3 = Witness(type: .payToScriptHashPayToWitnessPubKeyHash(pubKey))
        let amount3: Satoshi = 1000 + Satoshi(wrappedSegWitInputBytes)
        let scriptPubKey3 = try! ScriptPubKey(hex: "a91486cc442a97817c245ce90ed0d31d6dbcde3841f987")
        let txInput3 = try! TxInput(txHash: prevTx.hash!, vout: vout, amount: amount3, scriptSig: nil, witness: witness3, scriptPubKey: scriptPubKey3)
        
        // Output:
        let txOutput = TxOutput(scriptPubKey: scriptPubKey1, amount: 1000, network: .mainnet)
        
        // Transaction spending legacy
        tx1 = Transaction(inputs: [txInput1], outputs: [txOutput])
        
        // Transaction spending native SegWit
        tx2 = Transaction(inputs: [txInput2], outputs: [txOutput])
        
        // Transaction spending wrapped SegWit
        tx3 = Transaction(inputs: [txInput3], outputs: [txOutput])
        
        // Corresponding private key
        hdKey = try! HDKey(base58: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
    }

    func testTotalIn() throws {
        XCTAssertEqual(tx1.totalIn, 1000 + Satoshi(legacyInputBytes))
        XCTAssertEqual(tx2.totalIn, 1000 + Satoshi(nativeSegWitInputBytes))
        XCTAssertEqual(tx3.totalIn, 1000 + Satoshi(wrappedSegWitInputBytes))
        
        let tx4 = try Transaction(hex: "0000000000000000000000000000000000000000000000000000000000000000")
        XCTAssertNil(tx4.totalIn)
        
    }
    
    func testTotalOut() throws {
        XCTAssertEqual(tx1.totalOut, 1000)
        
        let tx2 = try Transaction(hex: "0000000000000000000000000000000000000000000000000000000000000000")
        XCTAssertNil(tx2.totalOut)

    }
    
    func testFunded() {
        XCTAssertEqual(tx1.isFunded, true)
    }
    
    func testSize() throws {
        XCTAssertEqual(tx1.vbytes, legacyInputBytes)
        XCTAssertEqual(tx2.vbytes, nativeSegWitInputBytes)
        XCTAssertEqual(tx3.vbytes, wrappedSegWitInputBytes)

        let tx4 = try Transaction(hex: "0000000000000000000000000000000000000000000000000000000000000000")
        XCTAssertNil(tx4.vbytes)
        
    }
    
    func testFee() {
        XCTAssertEqual(tx1.fee, Satoshi(legacyInputBytes))
    }
    
    func testFeeRate() {
        XCTAssertEqual(tx1.feeRate, 1.0)
        XCTAssertEqual(tx2.feeRate, 1.0)
        XCTAssertEqual(tx3.feeRate, 1.0)
    }
    
    func testSign() throws {
        let signedTx = try tx1.signed(with: [hdKey])
        XCTAssertTrue(signedTx.inputs![0].isSigned)
        XCTAssertEqual(signedTx.description, "01000000010000000000000000000000000000000000000000000000000000000000000000000000006a47304402203d274300310c06582d0186fc197106120c4838fa5d686fe3aa0478033c35b97802205379758b11b869ede2f5ab13a738493a93571268d66b2a875ae148625bd20578012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711cffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac00000000")

        XCTAssertEqual(signedTx.vbytes, legacyInputBytes - 1)
    }
    
    func testSignNativeSegWit() throws {
        let signedTx = try tx2.signed(with: [hdKey])
        XCTAssertTrue(signedTx.inputs![0].isSigned)
        XCTAssertEqual(signedTx.description, "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac0247304402204094361e267c39fb942b3d30c6efb96de32ea0f81e87fc36c53e00de2c24555c022069f368ac9cacea21be7b5e7a7c1dad01aa244e437161d000408343a4d6f5da0e012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c00000000")

        XCTAssertEqual(signedTx.vbytes, nativeSegWitInputBytes)
    }

    func testSignWrappedSegWit() throws {
        let signedTx = try tx3.signed(with: [hdKey])
        XCTAssertTrue(signedTx.inputs![0].isSigned)
        XCTAssertEqual(signedTx.description, "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000017160014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbeffffffff01e8030000000000001976a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac024730440220514e02e6d4aff5e1bfcf72a98eab3a415176c757e2bf6feb7ccb893f8ffcf09b022048fe33e6a1dc80585f30aac20f58442d711739ac07d192a3a7867a1dbef6b38d012103501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c00000000")

        XCTAssertEqual(signedTx.vbytes, wrappedSegWitInputBytes)
    }

}
