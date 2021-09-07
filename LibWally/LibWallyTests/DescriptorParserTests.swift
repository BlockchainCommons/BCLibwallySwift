//
//  DescriptorParserTests.swift
//  LibWallyTests
//
//  Created by Wolf McNally on 9/1/21.
//

import XCTest
import LibWally

class DescriptorParserTests: XCTestCase {
    func testRaw() throws {
        try XCTAssertEqual(Descriptor("raw(76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac)").scriptPubKey.description, "pkh:OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG")
    }
    
    func testPK() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = HDKey(base58: tprv)!
        let ecPub = hdKey.pubKey.hex
        let ecPubUncompressed = hdKey.pubKey.uncompressed.hex
        let wif = hdKey.privKey!.wif
        let tpub = hdKey.xpub
        
        try XCTAssertEqual(Descriptor("pk(\(ecPub))").scriptPubKey.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(ecPubUncompressed))").scriptPubKey.description, "pk:04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(wif))").scriptPubKey.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(tprv))").scriptPubKey.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(tpub))").scriptPubKey.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
    }
    
    func testPKH() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = HDKey(base58: tprv)!
        let ecPub = hdKey.pubKey.hex
        let ecPubUncompressed = hdKey.pubKey.uncompressed.hex
        let wif = hdKey.privKey!.wif
        let tpub = hdKey.xpub
        
        try XCTAssertEqual(Descriptor("pkh(\(ecPub))").scriptPubKey.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(ecPubUncompressed))").scriptPubKey.description, "pkh:OP_DUP OP_HASH160 335f3a94aeed3518f0baedc04330945e3dd0744b OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(wif))").scriptPubKey.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(tprv))").scriptPubKey.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(tpub))").scriptPubKey.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
    }
    
    func testWPKH() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = HDKey(base58: tprv)!
        let ecPub = hdKey.pubKey.hex
        let ecPubUncompressed = hdKey.pubKey.uncompressed.hex
        let wif = hdKey.privKey!.wif
        let tpub = hdKey.xpub
        
        try XCTAssertEqual(Descriptor("wpkh(\(ecPub))").scriptPubKey.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
        try XCTAssertEqual(Descriptor("wpkh(\(ecPubUncompressed))").scriptPubKey.description, "wpkh:OP_0 335f3a94aeed3518f0baedc04330945e3dd0744b")
        try XCTAssertEqual(Descriptor("wpkh(\(wif))").scriptPubKey.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
        try XCTAssertEqual(Descriptor("wpkh(\(tprv))").scriptPubKey.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
        try XCTAssertEqual(Descriptor("wpkh(\(tpub))").scriptPubKey.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
    }
    
    func testMulti() throws {
        let m1 = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
        try XCTAssertEqual(Descriptor(m1).scriptPubKey.description, "multi:OP_1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc OP_2 OP_CHECKMULTISIG")
        
        let m2 = "multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)"
        try XCTAssertEqual(Descriptor(m2).scriptPubKey.description, "multi:OP_2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb 03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a OP_3 OP_CHECKMULTISIG")
    }

    func testAddr() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        let hdKey = HDKey(base58: tprv)!
        let addressp2pkh = Address(hdKey: hdKey, type: .payToPubKeyHash)!.string
        XCTAssertEqual(addressp2pkh, "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
        try XCTAssertEqual(Descriptor("addr(\(addressp2pkh))").scriptPubKey.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        let p2shp2wpkh = Address(hdKey: hdKey, type: .payToScriptHashPayToWitnessPubKeyHash)!.string
        XCTAssertEqual(p2shp2wpkh, "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
        try XCTAssertEqual(Descriptor("addr(\(p2shp2wpkh))").scriptPubKey.description, "sh:OP_HASH160 8fb371a0195598d96e634b9eddb645fa1f128e11 OP_EQUAL")
        let p2wpkh = Address(hdKey: hdKey, type: .payToWitnessPubKeyHash)!.string
        XCTAssertEqual(p2wpkh, "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
        try XCTAssertEqual(Descriptor("addr(\(p2wpkh))").scriptPubKey.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
    }
}
