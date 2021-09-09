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
    
    func test_SH_WPKH() throws {
        let a = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey()!.description, "sh:OP_HASH160 cc6ffbc0bf31af759451068f90ba7a0272b6b332 OP_EQUAL")
    }
    
    func test_WSH_PKH() throws {
        let a = "wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey()!.description, "wsh:OP_0 fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f")
    }
    
    func test_SH_WSH_PKH() throws {
        let a = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey()!.description, "sh:OP_HASH160 55e8d5e8ee4f3604aba23c71c2684fa0a56a3a12 OP_EQUAL")
    }
    
    func test_SH_MULTI() throws {
        let a = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey()!.description, "sh:OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL")
    }
    
    func test_SH_SORTEDMULTI() throws {
        let a = "sh(sortedmulti(2,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey()!.description, "sh:OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL")
    }
    
    func test_WSH_MULTI() throws {
        let a = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey()!.description, "wsh:OP_0 773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a")
    }
    
    func test_SH_WSH_MULTI() throws {
        let a = "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey()!.description, "sh:OP_HASH160 aec509e284f909f769bb7dda299a717c87cc97ac OP_EQUAL")
    }
    
    func test_WSH_MULTI_HD() throws {
        let a = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
        try XCTAssertEqual(Descriptor(a).scriptPubKey(wildcardChildNum: 0)!.description, "wsh:OP_0 64969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b")
    }
    
    func test_WSH_MULTI_HD_2() throws {
        // This test vector from: https://bitcoindevkit.org/descriptors/
        let a = "wsh(multi(2,tprv8ZgxMBicQKsPePmENhT9N9yiSfTtDoC1f39P7nNmgEyCB6Nm4Qiv1muq4CykB9jtnQg2VitBrWh8PJU8LHzoGMHTrS2VKBSgAz7Ssjf9S3P/0/*,tpubDBYDcH8P2PedrEN3HxWYJJJMZEdgnrqMsjeKpPNzwe7jmGwk5M3HRdSf5vudAXwrJPfUsfvUPFooKWmz79Lh111U51RNotagXiGNeJe3i6t/1/*))"
        let desc = try Descriptor(a)
        let scriptPubKey0 = desc.scriptPubKey(wildcardChildNum: 0)!
        let scriptPubKey1 = desc.scriptPubKey(wildcardChildNum: 1)!
        XCTAssertEqual(Address(scriptPubKey: scriptPubKey0, network: .testnet)!.string, "tb1qqsat6c82fvdy73rfzye8f7nwxcz3xny7t56azl73g95mt3tmzvgs9a8vjs")
        XCTAssertEqual(Address(scriptPubKey: scriptPubKey1, network: .testnet)!.string, "tb1q7sgx6gscgtau57jduend6a8l445ahpk3dt3u5zu58rx5qm27lhkqgfdjdr")
    }
    
    func testCombo1() throws {
        // https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
        let comboCompressed = "combo(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)"
        let desc = try Descriptor(comboCompressed)
        XCTAssertTrue(desc.isCombo)
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pk)?.description, "pk:022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 OP_CHECKSIG")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pkh)?.description, "pkh:OP_DUP OP_HASH160 9652d86bedf43ad264362e6e6eba6eb764508127 OP_EQUALVERIFY OP_CHECKSIG")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .wpkh)?.description, "wpkh:OP_0 9652d86bedf43ad264362e6e6eba6eb764508127")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .sh_wpkh)?.description, "sh:OP_HASH160 edcbce4e0cce791e8ddb72705133fa3566145fa6 OP_EQUAL")
    }
    
    func testCombo2() throws {
        // https://github.com/bitcoin/bips/blob/master/bip-0384.mediawiki
        let comboUncompressed = "combo(04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27)"
        let desc = try Descriptor(comboUncompressed)
        XCTAssertTrue(desc.isCombo)
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pk)?.description, "pk:04e220e776d811c44075a4a260734445c8967865f5357ba98ead3bc6a6552c36f22fa358bbfca32197efabe42755e5ab36c73b9bfee5b6ada22807cb125c1b7a27 OP_CHECKSIG")
        XCTAssertEqual(desc.scriptPubKey(comboOutput: .pkh)?.description, "pkh:OP_DUP OP_HASH160 335f3a94aeed3518f0baedc04330945e3dd0744b OP_EQUALVERIFY OP_CHECKSIG")
        XCTAssertNil(desc.scriptPubKey(comboOutput: .wpkh))
        XCTAssertNil(desc.scriptPubKey(comboOutput: .sh_wpkh))
    }
}
