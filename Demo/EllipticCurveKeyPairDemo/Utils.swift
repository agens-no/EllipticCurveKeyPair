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
    
    var publicKeyBase = (try? manager.publicKey().data().rawWithHeaders.base64EncodedString()) ?? "error fetching public key"
    publicKeyBase.insert("\n", at: publicKeyBase.index(publicKeyBase.startIndex, offsetBy: 64))
    
    var shell: [String] = []
    shell.append("\n\n#! /bin/sh")
    shell.append("echo \(digest.map { String(format: "%02hhx", $0) }.joined()) | xxd -r -p > dataToSign.dat")
    shell.append("echo \(signed.map { String(format: "%02hhx", $0) }.joined()) | xxd -r -p > signature.dat")
    shell.append("cat > key.pem <<EOF\n-----BEGIN PUBLIC KEY-----\n\(publicKeyBase)\n-----END PUBLIC KEY-----\nEOF")
    shell.append("/usr/local/opt/openssl/bin/openssl dgst -sha256 -verify key.pem -signature signature.dat dataToSign.dat")
    print(shell.joined(separator: "\n"))
}
