//
// This is a heavily altered version of SHA2.swift found in CryptoSwift.
// I tried to remove everything that is not about SHA256.
//
// --========================================================================--
//
//  SHA2.swift
//  CryptoSwift
//
//  Created by Marcin Krzyzanowski on 24/08/14.
//  Copyright (c) 2014 Marcin Krzyzanowski. All rights reserved.
//
//  Copyright (C) 2014 Marcin Krzyżanowski <marcin.krzyzanowski@gmail.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  In no event will the authors be held liable for any damages arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,including commercial applications,
//  and to alter it and redistribute it freely, subject to the following restrictions:
//
//  - The origin of this software must not be misrepresented; you must not claim that you wrote the original software.
//    If you use this software in a product, an acknowledgment in the product documentation is required.
//  - Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
//  - This notice may not be removed or altered from any source or binary distribution.

import Foundation

public extension Data {
    func sha256() -> Data {
        let bytes: [UInt8] = Array(self)
        let result = SHA256(bytes).calculate32()
        return Data(result)
    }
}

public final class SHA256 {
    let message: [UInt8]

    init(_ message: [UInt8]) {
        self.message = message
    }

    func calculate32() -> [UInt8] {
        var tmpMessage = bitPadding(to: message, blockSize: 64, allowance: 64 / 8)

        // hash values
        var hh = [UInt32]()
        h.forEach { h -> Void in
            hh.append(UInt32(h))
        }

        // append message length, in a 64-bit big-endian integer. So now the message length is a multiple of 512 bits.
        tmpMessage += arrayOfBytes(value: message.count * 8, length: 64 / 8)

        // Process the message in successive 512-bit chunks:
        let chunkSizeBytes = 512 / 8 // 64
        for chunk in BytesSequence(chunkSize: chunkSizeBytes, data: tmpMessage) {
            // break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15, big-endian
            // Extend the sixteen 32-bit words into sixty-four 32-bit words:
            var M = [UInt32](repeating: 0, count: k.count)
            for x in 0 ..< M.count {
                switch x {
                    case 0 ... 15:
                        let start = chunk.startIndex + (x * MemoryLayout<UInt32>.size)
                        let end = start + MemoryLayout<UInt32>.size
                        let le = chunk[start ..< end].toUInt32Array()[0]
                        M[x] = le.bigEndian
                    default:
                        let s0 = rotateRight(M[x - 15], by: 7) ^ rotateRight(M[x - 15], by: 18) ^ (M[x - 15] >> 3)
                        let s1 = rotateRight(M[x - 2], by: 17) ^ rotateRight(M[x - 2], by: 19) ^ (M[x - 2] >> 10)
                        M[x] = M[x - 16] &+ s0 &+ M[x - 7] &+ s1
                }
            }

            var A = hh[0]
            var B = hh[1]
            var C = hh[2]
            var D = hh[3]
            var E = hh[4]
            var F = hh[5]
            var G = hh[6]
            var H = hh[7]

            // Main loop
            for j in 0 ..< k.count {
                let s0 = rotateRight(A, by: 2) ^ rotateRight(A, by: 13) ^ rotateRight(A, by: 22)
                let maj = (A & B) ^ (A & C) ^ (B & C)
                let t2 = s0 &+ maj
                let s1 = rotateRight(E, by: 6) ^ rotateRight(E, by: 11) ^ rotateRight(E, by: 25)
                let ch = (E & F) ^ ((~E) & G)
                let t1 = H &+ s1 &+ ch &+ UInt32(k[j]) &+ M[j]

                H = G
                G = F
                F = E
                E = D &+ t1
                D = C
                C = B
                B = A
                A = t1 &+ t2
            }

            hh[0] = (hh[0] &+ A)
            hh[1] = (hh[1] &+ B)
            hh[2] = (hh[2] &+ C)
            hh[3] = (hh[3] &+ D)
            hh[4] = (hh[4] &+ E)
            hh[5] = (hh[5] &+ F)
            hh[6] = (hh[6] &+ G)
            hh[7] = (hh[7] &+ H)
        }

        // Produce the final hash value (big-endian) as a 160 bit number:
        var result = [UInt8]()
        result.reserveCapacity(hh.count / 4)
        ArraySlice(hh).forEach {
            let item = $0.bigEndian
            let toAppend: [UInt8] = [UInt8(item & 0xFF), UInt8((item >> 8) & 0xFF), UInt8((item >> 16) & 0xFF), UInt8((item >> 24) & 0xFF)]
            result += toAppend
        }
        return result
    }

    private lazy var h: [UInt64] = {
        [0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19]
    }()

    private lazy var k: [UInt64] = {
        [
            0x428A_2F98,
            0x7137_4491,
            0xB5C0_FBCF,
            0xE9B5_DBA5,
            0x3956_C25B,
            0x59F1_11F1,
            0x923F_82A4,
            0xAB1C_5ED5,
            0xD807_AA98,
            0x1283_5B01,
            0x2431_85BE,
            0x550C_7DC3,
            0x72BE_5D74,
            0x80DE_B1FE,
            0x9BDC_06A7,
            0xC19B_F174,
            0xE49B_69C1,
            0xEFBE_4786,
            0x0FC1_9DC6,
            0x240C_A1CC,
            0x2DE9_2C6F,
            0x4A74_84AA,
            0x5CB0_A9DC,
            0x76F9_88DA,
            0x983E_5152,
            0xA831_C66D,
            0xB003_27C8,
            0xBF59_7FC7,
            0xC6E0_0BF3,
            0xD5A7_9147,
            0x06CA_6351,
            0x1429_2967,
            0x27B7_0A85,
            0x2E1B_2138,
            0x4D2C_6DFC,
            0x5338_0D13,
            0x650A_7354,
            0x766A_0ABB,
            0x81C2_C92E,
            0x9272_2C85,
            0xA2BF_E8A1,
            0xA81A_664B,
            0xC24B_8B70,
            0xC76C_51A3,
            0xD192_E819,
            0xD699_0624,
            0xF40E_3585,
            0x106A_A070,
            0x19A4_C116,
            0x1E37_6C08,
            0x2748_774C,
            0x34B0_BCB5,
            0x391C_0CB3,
            0x4ED8_AA4A,
            0x5B9C_CA4F,
            0x682E_6FF3,
            0x748F_82EE,
            0x78A5_636F,
            0x84C8_7814,
            0x8CC7_0208,
            0x90BE_FFFA,
            0xA450_6CEB,
            0xBEF9_A3F7,
            0xC671_78F2,
        ]
    }()

    private func rotateRight(_ value: UInt32, by: UInt32) -> UInt32 {
        return (value >> by) | (value << (32 - by))
    }

    private func arrayOfBytes<T>(value: T, length: Int? = nil) -> [UInt8] {
        let totalBytes = length ?? MemoryLayout<T>.size

        let valuePointer = UnsafeMutablePointer<T>.allocate(capacity: 1)
        valuePointer.pointee = value

        let bytesPointer = UnsafeMutablePointer<UInt8>(OpaquePointer(valuePointer))
        var bytes = [UInt8](repeating: 0, count: totalBytes)
        for j in 0 ..< min(MemoryLayout<T>.size, totalBytes) {
            bytes[totalBytes - 1 - j] = (bytesPointer + j).pointee
        }

        valuePointer.deinitialize(count: 1)
        valuePointer.deallocate()

        return bytes
    }
}

internal extension Collection where Self.Iterator.Element == UInt8, Self.Index == Int {
    func toUInt32Array() -> [UInt32] {
        var result = [UInt32]()
        result.reserveCapacity(16)
        for idx in stride(from: startIndex, to: endIndex, by: MemoryLayout<UInt32>.size) {
            var val: UInt32 = 0
            val |= count > 3 ? UInt32(self[idx.advanced(by: 3)]) << 24 : 0
            val |= count > 2 ? UInt32(self[idx.advanced(by: 2)]) << 16 : 0
            val |= count > 1 ? UInt32(self[idx.advanced(by: 1)]) << 8 : 0
            val |= !isEmpty ? UInt32(self[idx]) : 0
            result.append(val)
        }

        return result
    }
}

internal func bitPadding(to data: [UInt8], blockSize: Int, allowance: Int = 0) -> [UInt8] {
    var tmp = data

    // Step 1. Append Padding Bits
    tmp.append(0x80) // append one bit (UInt8 with one bit) to message

    // append "0" bit until message length in bits ≡ 448 (mod 512)
    var msgLength = tmp.count
    var counter = 0

    while msgLength % blockSize != (blockSize - allowance) {
        counter += 1
        msgLength += 1
    }

    tmp += [UInt8](repeating: 0, count: counter)
    return tmp
}

internal struct BytesSequence<D: RandomAccessCollection>: Sequence where D.Iterator.Element == UInt8,
    D.Index == Int {
    let chunkSize: Int
    let data: D

    func makeIterator() -> AnyIterator<D.SubSequence> {
        var offset = data.startIndex
        return AnyIterator {
            let end = Swift.min(self.chunkSize, self.data.count - offset)
            let result = self.data[offset ..< offset + end]
            offset = offset.advanced(by: result.count)
            if !result.isEmpty {
                return result
            }
            return nil
        }
    }
}
