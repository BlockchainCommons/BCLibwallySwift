//
//  EthereumTests.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/15/21.
//

import XCTest
import LibWally
import WolfBase

class EthereumTests: XCTestCase {
    func testKeccak256() {
        func test(_ input: String, _ expected: String) {
            XCTAssertEqual(Ethereum.keccak256(Data(hex: input)!).hex, expected)
        }
        
        // Test vectors from: https://bob.nem.ninja/test-vectors.html
        test("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        test("cc", "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a")
        test("41fb", "a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2")
        test("1f877c", "627d7bc1491b2ab127282827b8de2d276b13d7d70fb4c5957fdf20655bc7ac30")
        test("c1ecfdfc", "b149e766d7612eaf7d55f74e1a4fdd63709a8115b14f61fcd22aa4abc8b8e122")
        test("9f2fcc7c90de090d6b87cd7e9718c1ea6cb21118fc2d5de9f97e5db6ac1e9c10", "24dd2ee02482144f539f810d2caa8a7b75d0fa33657e47932122d273c3f6f6d1")
    }

    func testAccount() {
        let mnemonic = "surge mind remove galaxy define nephew surge helmet shine hurry voyage dawn"
        let account = Ethereum.Account(mnemonic: mnemonic)!
        XCTAssertEqual(account.bip39†, mnemonic)
        XCTAssertEqual(account.bip39Seed†, "414e34710a1ed4e25fb9f3568c6a81e8b7823f3f6ebd83012a7b8d9305914db074b68bf4b9b162c11a90648498736a527c2fb3f58693eada4b9c88c7f00f00a4")
        XCTAssertEqual(account.masterKey†, "xprv9s21ZrQH143K4TAgo7AZM1q8qTsQdfwMBeDHkzvbn7nadYjGPhqCzZrSTw72ykMRdUnUzvuJyfCH5W3NA7AK5MnWuBL8BYms3GSX7CHQth2")
        XCTAssertEqual(account.accountKey†, "xprvA3Feztt4T2Y2HFVzytE7xak14RkeMeEGSQNQV6CwY8UKg2GpgJPepTN8qFKT2dJrvjDiRkCj4FbmLpszVja4Rdhmu2MQPPspKrD82iinDNp")
        XCTAssertEqual(account.accountPrivateKey†, "c668cea9dc7ad3e2ab81c059dfe48970f10277279853f825464815825876e99f")
        XCTAssertEqual(account.accountPublicKey†, "045d6ad3906f3cb2264a3081feaf97c82b89fd94fa1d95e7a582c771932209a49c05aafef2885c719c7fe64fdd5169ac9d062a8e13e248148f684df1b673a673d1")
        XCTAssertEqual(account.address†, "0x23eafe61740052028664870b02bd17bf9905c1ea")
        XCTAssertEqual(account.shortAddress†, "23ea...c1ea")
    }
}
