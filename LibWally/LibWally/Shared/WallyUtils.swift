//
//  WallyUtils.swift
//  LibWally
//
//  Created by Wolf McNally on 8/25/21.
//

import Foundation
@_implementationOnly import WolfBase

public enum Wally {
}

extension Wally {
    public static func key(from parentKey: WallyExtKey, childNum: UInt32, isPrivate: Bool) -> WallyExtKey? {
        withUnsafePointer(to: parentKey) { parentPointer in
            let flags = UInt32(isPrivate ? BIP32_FLAG_KEY_PRIVATE : BIP32_FLAG_KEY_PUBLIC)
            var derivedKey = WallyExtKey()
            guard bip32_key_from_parent(parentPointer, childNum, flags, &derivedKey) == WALLY_OK else {
                return nil
            }
            return derivedKey
        }
    }
    
    public static func fingerprintData(for key: WallyExtKey) -> Data {
        // This doesn't work with a non-derivable key, because LibWally thinks it's invalid.
        //var bytes = [UInt8](repeating: 0, count: Int(BIP32_KEY_FINGERPRINT_LEN))
        //precondition(bip32_key_get_fingerprint(&hdkey, &bytes, bytes.count) == WALLY_OK)
        //return Data(bytes)

        hash160(key.pub_key).prefix(Int(BIP32_KEY_FINGERPRINT_LEN))
    }
    
    public static func fingerprint(for key: WallyExtKey) -> UInt32 {
        deserialize(UInt32.self, fingerprintData(for: key))!
    }
    
    public static func updateHash160(in key: inout WallyExtKey) {
        let hash160Size = MemoryLayout.size(ofValue: key.hash160)
        withUnsafeByteBuffer(of: key.pub_key) { pub_key in
            withUnsafeMutableByteBuffer(of: &key.hash160) { hash160 in
                precondition(wally_hash160(
                    pub_key.baseAddress!, Int(EC_PUBLIC_KEY_LEN),
                    hash160.baseAddress!, hash160Size
                ) == WALLY_OK)
            }
        }
    }
    
    public static func updatePublicKey(in key: inout WallyExtKey) {
        withUnsafeByteBuffer(of: key.priv_key) { priv_key in
            withUnsafeMutableByteBuffer(of: &key.pub_key) { pub_key in
                precondition(wally_ec_public_key_from_private_key(
                    priv_key.baseAddress! + 1, Int(EC_PRIVATE_KEY_LEN),
                    pub_key.baseAddress!, Int(EC_PUBLIC_KEY_LEN)
                ) == WALLY_OK)
            }
        }
    }
}

extension Wally {
    public static func ecPublicKeyFromPrivateKey(data: Data) -> Data {
        data.withUnsafeByteBuffer { inputBytes in
            var result = Data(count: Int(EC_PUBLIC_KEY_LEN))
            result.withUnsafeMutableByteBuffer { outputBytes in
                precondition(
                    wally_ec_public_key_from_private_key(
                        inputBytes.baseAddress,
                        inputBytes.count,
                        outputBytes.baseAddress,
                        outputBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func ecPublicKeyDecompress(data: Data) -> Data {
        data.withUnsafeByteBuffer { inputBytes in
            var result = Data(count: Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN))
            result.withUnsafeMutableByteBuffer { outputBytes in
                precondition(
                    wally_ec_public_key_decompress(
                        inputBytes.baseAddress,
                        inputBytes.count,
                        outputBytes.baseAddress,
                        outputBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func ecPublicKeyCompress(data: Data) -> Data {
        data.withUnsafeByteBuffer { inputBytes in
            var result = Data(count: Int(EC_PUBLIC_KEY_LEN))
            result.withUnsafeMutableByteBuffer { outputBytes in
                precondition(
                    wally_ec_public_key_negate(
                        inputBytes.baseAddress,
                        inputBytes.count,
                        outputBytes.baseAddress,
                        outputBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func hash160(_ data: Data) -> Data {
        data.withUnsafeByteBuffer { inBytes in
            var result = Data(count: Int(HASH160_LEN))
            result.withUnsafeMutableByteBuffer { outBytes in
                precondition(
                    wally_hash160(
                        inBytes.baseAddress,
                        inBytes.count,
                        outBytes.baseAddress,
                        outBytes.count
                    ) == WALLY_OK
                )
            }
            return result
        }
    }
    
    public static func hash160<T>(_ input: T) -> Data {
        withUnsafeByteBuffer(of: input) { inBytes in
            var result = Data(repeating: 0, count: Int(HASH160_LEN))
            result.withUnsafeMutableByteBuffer { outBytes in
                precondition(
                    wally_hash160(
                        inBytes.baseAddress,
                        inBytes.count,
                        outBytes.baseAddress,
                        outBytes.count
                    ) == WALLY_OK)
            }
            return result
        }
    }
}

extension Wally {
    public static func hdKey(bip39Seed seed: BIP39.Seed, network: Network) -> WallyExtKey? {
        let flags = network.wallyBIP32Version(isPrivate: true)
        var key = WallyExtKey()
        let result = seed.data.withUnsafeByteBuffer { buf in
            bip32_key_from_seed(buf.baseAddress, buf.count, flags, 0, &key)
        }
        guard result == WALLY_OK else {
            return nil
        }
        return key
    }
}

extension Wally {
    public static func ecPrivateKeyVerify(_ privKey: Data) -> Bool {
        privKey.withUnsafeByteBuffer {
            wally_ec_private_key_verify($0.baseAddress, $0.count) == WALLY_OK
        }
    }
    
    public static func ecSigFromBytes(privKey: Data, messageHash: Data) -> Data {
        privKey.withUnsafeByteBuffer { privKeyBytes in
            messageHash.withUnsafeByteBuffer { messageHashBytes in
                var compactSig = [UInt8](repeating: 0, count: Int(EC_SIGNATURE_LEN))
                precondition(wally_ec_sig_from_bytes(privKeyBytes.baseAddress, privKeyBytes.count, messageHashBytes.baseAddress, messageHashBytes.count, UInt32(EC_FLAG_ECDSA | EC_FLAG_GRIND_R), &compactSig, compactSig.count) == WALLY_OK)
                return Data(compactSig)
            }
        }
    }
    
    public static func ecSigVerify(key: WallyExtKey, messageHash: Data, compactSig: Data) -> Bool {
        withUnsafeByteBuffer(of: key.pub_key) { pubKeyBytes in
            messageHash.withUnsafeByteBuffer { messageHashBytes in
                compactSig.withUnsafeByteBuffer { compactSigBytes in
                    wally_ec_sig_verify(pubKeyBytes.baseAddress, pubKeyBytes.count, messageHashBytes.baseAddress, messageHashBytes.count, UInt32(EC_FLAG_ECDSA), compactSigBytes.baseAddress, compactSigBytes.count) == WALLY_OK
                }
            }
        }
    }
    
    public static func ecSigNormalize(compactSig: Data) -> Data {
        compactSig.withUnsafeByteBuffer { compactSigBytes in
            var sigNormBytes = [UInt8](repeating: 0, count: Int(EC_SIGNATURE_LEN))
            precondition(wally_ec_sig_normalize(compactSigBytes.baseAddress, compactSigBytes.count, &sigNormBytes, Int(EC_SIGNATURE_LEN)) == WALLY_OK)
            return Data(sigNormBytes)
        }
    }
    
    public static func ecSigToDer(sigNorm: Data) -> Data {
        sigNorm.withUnsafeByteBuffer { sigNormBytes in
            var sig_bytes = [UInt8](repeating: 0, count: Int(EC_SIGNATURE_DER_MAX_LEN))
            var sig_bytes_written = 0
            precondition(wally_ec_sig_to_der(sigNormBytes.baseAddress, sigNormBytes.count, &sig_bytes, Int(EC_SIGNATURE_DER_MAX_LEN), &sig_bytes_written) == WALLY_OK)
            return Data(bytes: sig_bytes, count: sig_bytes_written)
        }
    }
}

extension Wally {
    public static func bip39Encode(data: Data) -> String {
        data.withUnsafeByteBuffer { bytes in
            var output: UnsafeMutablePointer<CChar>! = nil
            defer {
                wally_free_string(output)
            }
            precondition(bip39_mnemonic_from_bytes(nil, bytes.baseAddress, bytes.count, &output) == WALLY_OK)
            return String(cString: output)
        }
    }
    
    public static func bip39Decode(mnemonic: String) -> Data? {
        mnemonic.withCString { chars in
            var output = [UInt8](repeating: 0, count: mnemonic.count)
            var written = 0
            guard bip39_mnemonic_to_bytes(nil, chars, &output, output.count, &written) == WALLY_OK else {
                return nil
            }
            precondition((0...output.count).contains(written))
            return Data(bytes: output, count: written)
        }
    }
    
    public static func bip39AllWords() -> [String] {
        var words: [String] = []
        var WL: OpaquePointer?
        precondition(bip39_get_wordlist(nil, &WL) == WALLY_OK)
        for i in 0..<BIP39_WORDLIST_LEN {
            var word: UnsafeMutablePointer<Int8>?
            defer {
                wally_free_string(word)
            }
            precondition(bip39_get_word(WL, Int(i), &word) == WALLY_OK)
            words.append(String(cString: word!))
        }
        return words
    }
}

extension Data {
    public var hash160: Data {
        Wally.hash160(self)
    }
}

extension WallyExtKey: CustomStringConvertible {
    public var description: String {
        let chain_code = Data(of: self.chain_code).hex
        let parent160 = Data(of: self.parent160).hex
        let depth = self.depth
        let priv_key = Data(of: self.priv_key).hex
        let child_num = self.child_num
        let hash160 = Data(of: self.hash160).hex
        let version = self.version
        let pub_key = Data(of: self.pub_key).hex
        
        return "WallyExtKey(chain_code: \(chain_code), parent160: \(parent160), depth: \(depth), priv_key: \(priv_key), child_num: \(child_num), hash160: \(hash160), version: \(version), pub_key: \(pub_key))"
    }
    
    public var isPrivate: Bool {
        return priv_key.0 == BIP32_FLAG_KEY_PRIVATE
    }
    
    public var isMaster: Bool {
        return depth == 0
    }
    
    public static func version_is_valid(ver: UInt32, flags: UInt32) -> Bool
    {
        if ver == BIP32_VER_MAIN_PRIVATE || ver == BIP32_VER_TEST_PRIVATE {
            return true
        }

        return flags == BIP32_FLAG_KEY_PUBLIC &&
               (ver == BIP32_VER_MAIN_PUBLIC || ver == BIP32_VER_TEST_PUBLIC)
    }

    public func checkValid() {
        let ver_flags = isPrivate ? UInt32(BIP32_FLAG_KEY_PRIVATE) : UInt32(BIP32_FLAG_KEY_PUBLIC)
        precondition(Self.version_is_valid(ver: version, flags: ver_flags))
        //precondition(!Data(of: chain_code).isAllZero)
        precondition(pub_key.0 == 0x2 || pub_key.0 == 0x3)
        precondition(!Data(of: pub_key).dropFirst().isAllZero)
        precondition(priv_key.0 == BIP32_FLAG_KEY_PUBLIC || priv_key.0 == BIP32_FLAG_KEY_PRIVATE)
        precondition(!isPrivate || !Data(of: priv_key).dropFirst().isAllZero)
        precondition(!isMaster || Data(of: parent160).isAllZero)
    }
    
    public var network: Network? {
        switch version {
        case UInt32(BIP32_VER_MAIN_PRIVATE), UInt32(BIP32_VER_MAIN_PUBLIC):
            return .mainnet
        case UInt32(BIP32_VER_TEST_PRIVATE), UInt32(BIP32_VER_TEST_PUBLIC):
            return .testnet
        default:
            return nil
        }
    }
}
