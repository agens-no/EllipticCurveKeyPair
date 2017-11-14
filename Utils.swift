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

func verifyAndLog(manager: EllipticCurveKeyPair.Manager, signed: Data, digest: Data) {
    do {
        let verified = try manager.verify(signature: signed, originalDigest: digest)
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
    shell.append("/usr/local/opt/openssl/bin/openssl dgst -sha256 -verify key.pem -signature signature.dat dataToSign.dat")
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
let allAlgorithms = [SecKeyAlgorithm.rsaSignatureRaw, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15Raw, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA1, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA224, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA384, SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA512, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA1, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA224, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512, SecKeyAlgorithm.ecdsaSignatureRFC4754, SecKeyAlgorithm.ecdsaSignatureDigestX962, SecKeyAlgorithm.ecdsaSignatureDigestX962SHA1, SecKeyAlgorithm.ecdsaSignatureDigestX962SHA224, SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256, SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384, SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512, SecKeyAlgorithm.rsaEncryptionRaw, SecKeyAlgorithm.rsaEncryptionPKCS1, SecKeyAlgorithm.rsaEncryptionOAEPSHA1, SecKeyAlgorithm.rsaEncryptionOAEPSHA224, SecKeyAlgorithm.rsaEncryptionOAEPSHA256, SecKeyAlgorithm.rsaEncryptionOAEPSHA384, SecKeyAlgorithm.rsaEncryptionOAEPSHA512, SecKeyAlgorithm.rsaEncryptionOAEPSHA1AESGCM, SecKeyAlgorithm.rsaEncryptionOAEPSHA224AESGCM, SecKeyAlgorithm.rsaEncryptionOAEPSHA256AESGCM, SecKeyAlgorithm.rsaEncryptionOAEPSHA384AESGCM, SecKeyAlgorithm.rsaEncryptionOAEPSHA512AESGCM, SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM, SecKeyAlgorithm.eciesEncryptionStandardX963SHA224AESGCM, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM, SecKeyAlgorithm.eciesEncryptionStandardX963SHA512AESGCM, SecKeyAlgorithm.eciesEncryptionCofactorX963SHA1AESGCM, SecKeyAlgorithm.eciesEncryptionCofactorX963SHA224AESGCM, SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM, SecKeyAlgorithm.eciesEncryptionCofactorX963SHA384AESGCM, SecKeyAlgorithm.eciesEncryptionCofactorX963SHA512AESGCM, SecKeyAlgorithm.ecdhKeyExchangeStandard, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA1, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA224, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA384, SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA512, SecKeyAlgorithm.ecdhKeyExchangeCofactor, SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA1, SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA224, SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA256, SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA384, SecKeyAlgorithm.ecdhKeyExchangeCofactorX963SHA512]
