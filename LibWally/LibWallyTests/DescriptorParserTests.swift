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
        try XCTAssertEqual(Descriptor("raw(76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac)").scriptPubKey()?.description, "pkh:OP_DUP OP_HASH160 bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe OP_EQUALVERIFY OP_CHECKSIG")
    }
    
    func testPK() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = HDKey(base58: tprv)!
        let ecPub = hdKey.pubKey.hex
        let ecPubUncompressed = hdKey.pubKey.uncompressed.hex
        let wif = hdKey.privKey!.wif
        let tpub = hdKey.xpub
        
        try XCTAssertEqual(Descriptor("pk(\(ecPub))").scriptPubKey()?.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(ecPubUncompressed))").scriptPubKey()?.description, "pk:04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(wif))").scriptPubKey()?.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(tprv))").scriptPubKey()?.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pk(\(tpub))").scriptPubKey()?.description, "pk:03e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f2 OP_CHECKSIG")
    }
    
    func testPKH() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = HDKey(base58: tprv)!
        let ecPub = hdKey.pubKey.hex
        let ecPubUncompressed = hdKey.pubKey.uncompressed.hex
        let wif = hdKey.privKey!.wif
        let tpub = hdKey.xpub
        
        try XCTAssertEqual(Descriptor("pkh(\(ecPub))").scriptPubKey()?.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(ecPubUncompressed))").scriptPubKey()?.description, "pkh:OP_DUP OP_HASH160 335f3a94aeed3518f0baedc04330945e3dd0744b OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(wif))").scriptPubKey()?.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(tprv))").scriptPubKey()?.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        try XCTAssertEqual(Descriptor("pkh(\(tpub))").scriptPubKey()?.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
    }
    
    func testWPKH() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        
        let hdKey = HDKey(base58: tprv)!
        let ecPub = hdKey.pubKey.hex
        let ecPubUncompressed = hdKey.pubKey.uncompressed.hex
        let wif = hdKey.privKey!.wif
        let tpub = hdKey.xpub
        
        try XCTAssertEqual(Descriptor("wpkh(\(ecPub))").scriptPubKey()?.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
        try XCTAssertEqual(Descriptor("wpkh(\(ecPubUncompressed))").scriptPubKey()?.description, "wpkh:OP_0 335f3a94aeed3518f0baedc04330945e3dd0744b")
        try XCTAssertEqual(Descriptor("wpkh(\(wif))").scriptPubKey()?.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
        try XCTAssertEqual(Descriptor("wpkh(\(tprv))").scriptPubKey()?.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
        try XCTAssertEqual(Descriptor("wpkh(\(tpub))").scriptPubKey()?.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
    }
    
    func testMulti() throws {
        let m1 = "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)"
        try XCTAssertEqual(Descriptor(m1).scriptPubKey()?.description, "multi:OP_1 022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc OP_2 OP_CHECKMULTISIG")
        
        let m2 = "multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)"
        try XCTAssertEqual(Descriptor(m2).scriptPubKey()?.description, "multi:OP_2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb 03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a OP_3 OP_CHECKMULTISIG")
    }
    
    func testSortedMulti1() throws {
        func test(_ keys: [String], _ expectedScript: String, _ expectedAddress: String) throws {
            let k = keys.joined(separator: ",")
            let desc = try Descriptor("sortedmulti(2,\(k))")
            XCTAssertEqual(desc.scriptPubKey()?.hex, expectedScript)
//            let address = Wally.address(from: desc.scriptPubKey()!, network: .mainnet)
            let address = Address(scriptPubKey: desc.scriptPubKey()!, network: .mainnet)!.string
//            print(address)
            XCTAssertEqual(address, expectedAddress)
        }

        // https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki#test-vectors

        try test(
            [
                "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"
            ],
            "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae",
//            "39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z"
            "bc1qknwt9mhqpd7hrjrvpqz57zjqk28xlp2h90te6v22en0m3uctnams3pq5ce"
        )

        try test(
            [
                "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404"
            ],
            "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed021027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e772102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b40453ae",
//            "3CKHTjBKxCARLzwABMu9yD85kvtm7WnMfH"
            "bc1qud6dmdcc27eg8s5hsy6a075gs49w65l6xtc4cplp6m2d4ggh43wqew2vqs"
        )

        try test(
            [
                "030000000000000000000000000000000000004141414141414141414141414141",
                "020000000000000000000000000000000000004141414141414141414141414141",
                "020000000000000000000000000000000000004141414141414141414141414140",
                "030000000000000000000000000000000000004141414141414141414141414140"
            ],
            "522102000000000000000000000000000000000000414141414141414141414141414021020000000000000000000000000000000000004141414141414141414141414141210300000000000000000000000000000000000041414141414141414141414141402103000000000000000000000000000000000000414141414141414141414141414154ae",
//            "32V85igBri9zcfBRVupVvwK18NFtS37FuD"
            "bc1q43l9uw4l5q3d3eltdvf785atcpfys8wad6z4rv6mltnzrzasq0jqp0lwze"
        )

        try test(
            [
                "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18"
            ],
            "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc1821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
//            "3Q4sF6tv9wsdqu2NtARzNCpQgwifm2rAba"
            "bc1q0uyls9kc4acv9ntqw6u096t53jlld4frp4rscrf8fruddhu62p6sy9507s"
        )
    }
    
    func testSortedMulti2() throws {
        let source = "sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH)"
        try XCTAssertEqual(Descriptor(source).scriptPubKey()?.asm, "OP_1 02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea 03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7 OP_2 OP_CHECKMULTISIG")
    }

    func testAddr() throws {
        let tprv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        let hdKey = HDKey(base58: tprv)!
        let addressp2pkh = Address(hdKey: hdKey, type: .payToPubKeyHash)!.string
        XCTAssertEqual(addressp2pkh, "mnicNaAVzyGdFvDa9VkMrjgNdnr2wHBWxk")
        try XCTAssertEqual(Descriptor("addr(\(addressp2pkh))").scriptPubKey()?.description, "pkh:OP_DUP OP_HASH160 4efd3ded47d967e4122982422c9d84db60503972 OP_EQUALVERIFY OP_CHECKSIG")
        let p2shp2wpkh = Address(hdKey: hdKey, type: .payToScriptHashPayToWitnessPubKeyHash)!.string
        XCTAssertEqual(p2shp2wpkh, "2N6M3ah9EoggimNz5pnAmQwnpE1Z3ya3V7A")
        try XCTAssertEqual(Descriptor("addr(\(p2shp2wpkh))").scriptPubKey()?.description, "sh:OP_HASH160 8fb371a0195598d96e634b9eddb645fa1f128e11 OP_EQUAL")
        let p2wpkh = Address(hdKey: hdKey, type: .payToWitnessPubKeyHash)!.string
        XCTAssertEqual(p2wpkh, "tb1qfm7nmm28m9n7gy3fsfpze8vymds9qwtjwn4w7y")
        try XCTAssertEqual(Descriptor("addr(\(p2wpkh))").scriptPubKey()?.description, "wpkh:OP_0 4efd3ded47d967e4122982422c9d84db60503972")
    }
    
    func testHDKey1() throws {
        let source = "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)"
        let desc = try Descriptor(source)
        XCTAssertNil(desc.scriptPubKey()) // requires wildcard
        XCTAssertEqual(desc.scriptPubKey(wildcardChildNum: 0)?.description, "pkh:OP_DUP OP_HASH160 2a05c214617c9b0434c92d0583200a85ef61818f OP_EQUALVERIFY OP_CHECKSIG")
        XCTAssertEqual(desc.scriptPubKey(wildcardChildNum: 1)?.description, "pkh:OP_DUP OP_HASH160 49b2f81eea1ecb5bc97d78f2d8f89d9c861c3cf2 OP_EQUALVERIFY OP_CHECKSIG")
    }
    
    func testHDKey2() throws {
        let masterKey = HDKey(base58: "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA")!
        let purposePath = DerivationPath(string: "44'")!
        let purposePrivateKey = masterKey.derive(path: purposePath)!
        
        let accountPath = DerivationPath(string: "0'/0'")!
        let children = DerivationPath(string: "1'/*")!
        let accountPrivateKey = purposePrivateKey.derive(path: accountPath, children: children)!
        XCTAssertEqual(accountPrivateKey.fullDescription, "[4efd3ded/44h/0h/0h]tprv8m6wpfnU18pDmiCbMcw9TmBJmYZASBbh7id31gAaszC2uuX7WysJYxj3yUztBSa38gmxiSLU6czfx3RTNmBC9ctr9XpmHxcFEMYUHEbSksf/1h/*")

        let accountPublicKey = accountPrivateKey.public
        XCTAssertEqual(accountPublicKey.fullDescription, "[4efd3ded/44h/0h/0h]tpubDHnyy5pi9WVtfBEPFGbjsAqRLa56bWnbh2DpJCCtJFzRkPmt9NgtjTLv9bkDqLaNr6PgYE1Ki1QhQXWVmSTJUVkTVavpEvH4vr2UWwzq18k/1h/*")
        
        let source = "pkh(\(accountPublicKey.fullDescription))"
        let desc = try Descriptor(source)
        XCTAssertNil(desc.scriptPubKey(wildcardChildNum: 0)) // requires private key.
        
        let lookup: [UInt32 : HDKey] = [
            masterKey.fingerprint : masterKey
        ]
        
        let fullPath = purposePath + accountPath
        XCTAssertEqual(fullPath.description, "44h/0h/0h")
        
        func privateKeyProvider(key: HDKey) -> HDKey? {
            guard
                case let .fingerprint(originFingerprint) = key.parent.origin,
                let masterKey = lookup[originFingerprint],
                let privateKey = masterKey.derive(path: fullPath)
            else {
                return nil
            }
            return privateKey
        }
        
        XCTAssertEqual(desc.scriptPubKey(wildcardChildNum: 0, privateKeyProvider: privateKeyProvider)?.description, "pkh:OP_DUP OP_HASH160 c3d4f598ec80d57820226529645b7805d078cab0 OP_EQUALVERIFY OP_CHECKSIG")
    }
}
