//
//  BIP32Tests.swift
//  BIP32Tests 
//
//  Created by Sjors on 29/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import XCTest
@testable import LibWally

class BIP32Tests: XCTestCase {
    let bip39Seed = BIP39.Seed(hex: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")!
    
    func testSeedToHDKey() {
        let hdKey = HDKey(bip39Seed: bip39Seed)!
        XCTAssertEqual(hdKey.description, "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF")
    }
    
    func testBase58ToHDKey() {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = HDKey(base58: xpriv)!
        XCTAssertEqual(hdKey.description, xpriv)
        
        XCTAssertNil(HDKey(base58: "invalid"))
    }
    
    func testXpriv() {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = HDKey(base58: xpriv)!
        
        XCTAssertEqual(hdKey.xpriv, xpriv)
    }
    
    func testXpub() {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = HDKey(base58: xpriv)!
        
        XCTAssertEqual(hdKey.xpub, xpub)
    }
    
    func testTpub() {
        let tpriv = "tprv8gzC1wn3dmCrBiqDFrqhw9XXgy5t4mzeL5SdWayHBHz1GmWbRKoqDBSwDLfunPAWxMqZ9bdGsdpTiYUfYiWypv4Wfj9g7AYX5K3H9gRYNCA"
        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let hdKey = HDKey(base58: tpriv)!
        
        XCTAssertEqual(hdKey.xpub, tpub)
    }
    
    func testPubKey() {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = HDKey(base58: xpub)!
        XCTAssertEqual(hdKey.pubKey.data.hex, "02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd")
    }
    
    func testParseXpub() {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = HDKey(base58: xpub)!
        XCTAssertEqual(hdKey.description, xpub)
        XCTAssertEqual(hdKey.xpub, xpub)
        XCTAssertNil(hdKey.xpriv)
    }

    func testParseTpub() {
        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let hdKey = HDKey(base58: tpub)!
        XCTAssertEqual(hdKey.description, tpub)
        XCTAssertEqual(hdKey.xpub, tpub)
        XCTAssertNil(hdKey.xpriv)
    }
    
    func testFingerPint() {
        let hdKey = HDKey(bip39Seed: bip39Seed)!
        XCTAssertEqual(hdKey.fingerprintData.hex, "b4e3f5ed")
    }
    
    func testMasterKeyFingerPint() {
        let hdKey = HDKey(bip39Seed: bip39Seed)!
        XCTAssertEqual(hdKey.masterKeyFingerprint?.hex, "b4e3f5ed")

        let childKey = HDKey(bip39Seed: bip39Seed)!.derive(path: DerivationPath(index: 0)!)!
        XCTAssertEqual(childKey.masterKeyFingerprint?.hex, "b4e3f5ed")
        
        let tpub = "tpubDDgEAMpHn8tX5Bs19WWJLZBeFzbpE7BYuP3Qo71abZnQ7FmN3idRPg4oPWt2Q6Uf9huGv7AGMTu8M2BaCxAdThQArjLWLDLpxVX2gYfh2YJ"
        let key = HDKey(base58: tpub, masterKeyFingerprint: 0xb4e3f5ed)!
        XCTAssertEqual(key.masterKeyFingerprint?.hex, "b4e3f5ed")
    }
    
    func testInferFingerprintAtDepthZero() {
        let masterKeyXpriv = "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
        let key = HDKey(base58: masterKeyXpriv)!
        XCTAssertEqual(key.masterKeyFingerprint?.hex, "d90c6a4f")
    }
    
    func testRelativePathFromString() {
        let path = DerivationPath(string: "0'/0")!
        XCTAssertEqual(path.steps, [.init(0, isHardened: true)!, .init(0)!])
        XCTAssertEqual(path.description, "0h/0")
    }
    
    func testAbsolutePathFromString() {
        let path = DerivationPath(string: "m/0'/0")! // 0' and 0h are treated the same
        XCTAssertEqual(path.steps, [.init(0, isHardened: true)!, .init(0)!])
        XCTAssertEqual(path.description, "m/0h/0") // description always uses h instead of '
    }
    
    func testRelativePathFromInt() {
        var path: DerivationPath
        path = DerivationPath(index: 0)!
        XCTAssertEqual(path.steps, [.init(0)!])
        XCTAssertEqual(path.description, "0")
        XCTAssertNil(DerivationPath(index: Int(UINT32_MAX)))
    }
    
    func testAbsolutePathFromInt() {
        var path: DerivationPath
        path = DerivationPath(index: 0, origin: .master)!
        XCTAssertEqual(path.description, "m/0")
        XCTAssertNil(DerivationPath(index: Int(UINT32_MAX)))
    }
    
    func testDerive() {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = HDKey(base58: xpriv)!
        
        let derivation = DerivationPath(index: 0)!
        let childKey = hdKey.derive(path: derivation)!

        XCTAssertNotNil(childKey.xpriv)
        XCTAssertEqual(childKey.xpriv!, "xprv9vEG8CuCbvqnJXhr1ZTHZYJcYqGMZ8dkphAUT2CDZsfqewNpq42oSiFgBXXYwDWAHXVbHew4uBfiHNAahRGJ8kUWwqwTGSXUb4wrbWz9eqo")
    }
    
    func testDeriveHardened() {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = HDKey(base58: xpriv)!
        
        let derivation = DerivationPath(step: .init(0, isHardened: true)!)!
        let childKey = hdKey.derive(path: derivation)!

        XCTAssertNotNil(childKey.xpriv)
        XCTAssertEqual(childKey.xpriv!, "xprv9vEG8CuLwbNkVNhb56dXckENNiU1SZEgwEAokv1yLodVwsHMRbAFyUMoMd5uyKEgPDgEPBwNfa42v5HYvCvT1ymQo1LQv9h5LtkBMvQD55b")
    }
    
    func testDerivePath() {
        let xpriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
        let hdKey = HDKey(base58: xpriv)!

        let path = DerivationPath(string: "m/0'/0")!

        let childKey = hdKey.derive(path: path)!
        
        XCTAssertNotNil(childKey.xpriv)
        XCTAssertEqual(childKey.xpriv!, "xprv9xcgxEx7PAbqP2YSijYjX38Vo6dV4i7g9ApmPRAkofDzQ6Hf4c3nBNRfW4EKSm2uhk4FBbjNFGjhZrATqLVKM2JjhsxSrUsDdJYK4UKhyQt")
    }
    
    func testDeriveFromXpub() {
        let xpub = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy"
        let hdKey = HDKey(base58: xpub)!
        
        let path = DerivationPath(string: "m/0")!
        let childKey = hdKey.derive(path: path)!
        
        XCTAssertNotNil(childKey.xpub)
        XCTAssertEqual(childKey.xpub, "xpub69DcXiS6SJQ5X1nK7azHvgFM6s6qxbMcBv65FQbq8DCpXjhyNbM3zWaA2p4L7Na2siUqFvyuK9W11J6GjqQhtPeJkeadtSpFcf6XLdKsZLZ")
        XCTAssertNil(childKey.xpriv)
        
        let hardenedPath = DerivationPath(string: "m/0'")!

        XCTAssertNil(hdKey.derive(path: hardenedPath))
    }

    func testDeriveWithAbsolutePath() {
        // Derivation is at depth 4
        let xpub = "xpub6E64WfdQwBGz85XhbZryr9gUGUPBgoSu5WV6tJWpzAvgAmpVpdPHkT3XYm9R5J6MeWzvLQoz4q845taC9Q28XutbptxAmg7q8QPkjvTL4oi"
        let hdKey = HDKey(base58: xpub)!
        
        let relativePath = DerivationPath(string: "0/0")!
        let expectedChildKey = hdKey.derive(path: relativePath)!
        
        // This should ignore the first 4 levels
        let absolutePath = DerivationPath(string: "m/48h/0h/0h/2h/0/0")!
        let childKey = hdKey.derive(path: absolutePath)!
        
        XCTAssertEqual(childKey.xpub, expectedChildKey.xpub)
    }
}
