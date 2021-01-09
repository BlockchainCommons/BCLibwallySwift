//
//  DataExtension.swift
//  DataExtension
//
//  Created by Sjors on 28/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation

extension Data {
    init(hex: String) throws {
        let len = hex.count / 2
        var data = Data(capacity: len)
        for i in 0..<len {
            let j = hex.index(hex.startIndex, offsetBy: i*2)
            let k = hex.index(j, offsetBy: 2)
            let bytes = hex[j..<k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                throw LibWallyError("Invalid hex format.")
            }
        }
        self = data
    }

    init(base58: String) throws {
        let len = base58.count + Int(BASE58_CHECKSUM_LEN) // base58 has more characters than the number of bytes we need
        var bytes_out = [UInt8](repeating: 0, count: len)
        var written = 0
        guard wally_base58_to_bytes(base58, UInt32(BASE58_FLAG_CHECKSUM), &bytes_out, len, &written) == WALLY_OK else {
            throw LibWallyError("Invalid base58 format.")
        }
        self = Data(bytes: bytes_out, count: written)
    }

    var hex: String {
        self.reduce("", { $0 + String(format: "%02x", $1) })
    }

    var base58: String {
        var output: UnsafeMutablePointer<Int8>?
        defer {
            wally_free_string(output)
        }
        self.withUnsafeByteBuffer { buf in
            precondition(wally_base58_from_bytes(buf.baseAddress, buf.count, UInt32(BASE58_FLAG_CHECKSUM), &output) == WALLY_OK)
        }
        precondition(output != nil)
        return String(cString: output!)
    }

    @inlinable func withUnsafeByteBuffer<ResultType>(_ body: (UnsafeBufferPointer<UInt8>) throws -> ResultType) rethrows -> ResultType {
        try withUnsafeBytes { rawBuf in
            try body(rawBuf.bindMemory(to: UInt8.self))
        }
    }

    init<A>(of a: A) {
        let d = Swift.withUnsafeBytes(of: a) {
            Data($0)
        }
        self = d
    }
}

@inlinable func withUnsafeByteBuffer<T, ResultType>(of value: T, _ body: (UnsafeBufferPointer<UInt8>) throws -> ResultType) rethrows -> ResultType {
    try withUnsafeBytes(of: value) { rawBuf in
        try body(rawBuf.bindMemory(to: UInt8.self))
    }
}
