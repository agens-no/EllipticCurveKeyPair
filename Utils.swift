/**
 *  Copyright (c) 2017 Håvard Fossli.
 *
 *  Licensed under the MIT license, as follows:
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

import Foundation
import EllipticCurveKeyPair

extension String: Error {}

@available(iOS 10, *)
func verifyAndLog(manager: EllipticCurveKeyPair.Manager, signed: Data, digest: Data, algorithm: EllipticCurveKeyPair.Algorithm) throws {
    do {
        let verified = try manager.verify(signature: signed, originalDigest: digest, algorithm: algorithm)
        guard verified == true else {
            fatalError("Could not verify signature. Probably invalid keypair.")
        }
        print("Signature verified")
    } catch let error {
        fatalError("Could not verify signature. Probably invalid keypair \(error).")
    }
    
    var publicKeyBase = (try? manager.publicKey().data().DER.base64EncodedString()) ?? "error fetching public key"
    publicKeyBase.insert("\n", at: publicKeyBase.index(publicKeyBase.startIndex, offsetBy: 64))
    
    var shell: [String] = []
    shell.append("\n\n#! /bin/sh")
    shell.append("echo \(digest.map { String(format: "%02hhx", $0) }.joined()) | xxd -r -p > dataToSign.dat")
    shell.append("echo \(signed.map { String(format: "%02hhx", $0) }.joined()) | xxd -r -p > signature.dat")
    shell.append("cat > key.pem <<EOF\n-----BEGIN PUBLIC KEY-----\n\(publicKeyBase)\n-----END PUBLIC KEY-----\nEOF")
    shell.append("/usr/local/opt/openssl/bin/openssl dgst -\(algorithm.rawValue) -verify key.pem -signature signature.dat dataToSign.dat")
    print(shell.joined(separator: "\n"))
}

extension DispatchQueue {
    
    static func roundTrip<T, Y>(_ block: () throws -> T,
                                       thenAsync: @escaping (T) throws -> Y,
                                       thenOnMain: @escaping (Y) throws -> Void,
                                       catchToMain: @escaping (Error) -> Void) {
        do {
            let resultFromMain = try block()
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let resultFromBackground = try thenAsync(resultFromMain)
                    DispatchQueue.main.async {
                        do {
                            try thenOnMain(resultFromBackground)
                        } catch {
                            catchToMain(error)
                        }
                    }
                } catch {
                    DispatchQueue.main.async {
                        catchToMain(error)
                    }
                }
            }
        } catch {
            catchToMain(error)
        }
    }
}

func delay( _ delay: Double, queue: DispatchQueue = DispatchQueue.main, completion: @escaping () -> () ) {
    queue.asyncAfter(deadline: DispatchTime.now() + Double(Int64(delay * Double(NSEC_PER_SEC))) / Double(NSEC_PER_SEC)) { () -> Void in
        completion()
    }
}

@available(iOS 10, *)
func supportedAlgorithms(key: SecKey) -> [SecKeyAlgorithm] {
    var supports = [SecKeyAlgorithm]()
    for algorithm in allAlgorithms() {
        for i in 0...4 {
            let operationType = SecKeyOperationType(rawValue: i)!
            if SecKeyIsAlgorithmSupported(key, operationType, algorithm) {
                supports.append(algorithm)
            }
        }
    }
    return supports
}

@available(iOS 10, *)
func allAlgorithms() -> [SecKeyAlgorithm] {
    return [.rsaSignatureRaw,
            .rsaSignatureDigestPKCS1v15Raw,
            .rsaSignatureDigestPKCS1v15SHA1,
            .rsaSignatureDigestPKCS1v15SHA224,
            .rsaSignatureDigestPKCS1v15SHA256,
            .rsaSignatureDigestPKCS1v15SHA384,
            .rsaSignatureDigestPKCS1v15SHA512,
            .rsaSignatureMessagePKCS1v15SHA1,
            .rsaSignatureMessagePKCS1v15SHA224,
            .rsaSignatureMessagePKCS1v15SHA256,
            .rsaSignatureMessagePKCS1v15SHA384,
            .rsaSignatureMessagePKCS1v15SHA512,
            .ecdsaSignatureRFC4754,
            .ecdsaSignatureDigestX962,
            .ecdsaSignatureDigestX962SHA1,
            .ecdsaSignatureDigestX962SHA224,
            .ecdsaSignatureDigestX962SHA256,
            .ecdsaSignatureDigestX962SHA384,
            .ecdsaSignatureDigestX962SHA512,
            .ecdsaSignatureMessageX962SHA1,
            .ecdsaSignatureMessageX962SHA224,
            .ecdsaSignatureMessageX962SHA256,
            .ecdsaSignatureMessageX962SHA384,
            .ecdsaSignatureMessageX962SHA512,
            .rsaEncryptionRaw,
            .rsaEncryptionPKCS1,
            .rsaEncryptionOAEPSHA1,
            .rsaEncryptionOAEPSHA224,
            .rsaEncryptionOAEPSHA256,
            .rsaEncryptionOAEPSHA384,
            .rsaEncryptionOAEPSHA512,
            .rsaEncryptionOAEPSHA1AESGCM,
            .rsaEncryptionOAEPSHA224AESGCM,
            .rsaEncryptionOAEPSHA256AESGCM,
            .rsaEncryptionOAEPSHA384AESGCM,
            .rsaEncryptionOAEPSHA512AESGCM,
            .eciesEncryptionStandardX963SHA1AESGCM,
            .eciesEncryptionStandardX963SHA224AESGCM,
            .eciesEncryptionStandardX963SHA256AESGCM,
            .eciesEncryptionStandardX963SHA384AESGCM,
            .eciesEncryptionStandardX963SHA512AESGCM,
            .eciesEncryptionCofactorX963SHA1AESGCM,
            .eciesEncryptionCofactorX963SHA224AESGCM,
            .eciesEncryptionCofactorX963SHA256AESGCM,
            .eciesEncryptionCofactorX963SHA384AESGCM,
            .eciesEncryptionCofactorX963SHA512AESGCM,
            .ecdhKeyExchangeStandard,
            .ecdhKeyExchangeStandardX963SHA1,
            .ecdhKeyExchangeStandardX963SHA224,
            .ecdhKeyExchangeStandardX963SHA256,
            .ecdhKeyExchangeStandardX963SHA384,
            .ecdhKeyExchangeStandardX963SHA512,
            .ecdhKeyExchangeCofactor,
            .ecdhKeyExchangeCofactorX963SHA1,
            .ecdhKeyExchangeCofactorX963SHA224,
            .ecdhKeyExchangeCofactorX963SHA256,
            .ecdhKeyExchangeCofactorX963SHA384,
            .ecdhKeyExchangeCofactorX963SHA512]
}

