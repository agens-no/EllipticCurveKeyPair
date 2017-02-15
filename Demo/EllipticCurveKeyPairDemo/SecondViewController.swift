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

import UIKit

class SecondViewController: UIViewController {
    
    struct Shared {
        static let keypair: EllipticCurveKeyPair.Manager = {
            let publicLabel = "no.agens.sign.public"
            let privateLabel = "no.agens.sign.private"
            let prompt = "Confirm payment"
            let sha256: (Data) -> Data = { return ELCKPCommonCryptoAccess.sha256Digest(for: $0) }
            let helper = EllipticCurveKeyPair.Helper(publicLabel: publicLabel, privateLabel: privateLabel, operationPrompt: prompt, sha256: sha256)
            return EllipticCurveKeyPair.Manager(helper: helper)
        }()
    }
    
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var digestTextView: UITextView!
    @IBOutlet weak var signatureTextView: UITextView!

    override func viewDidLoad() {
        super.viewDidLoad()
        
        do {
            let key = try Shared.keypair.publicKey().data()
            publicKeyTextView.text = key.der
        } catch {
            publicKeyTextView.text = "Error: \(error)"
        }
    }
    
    @IBAction func regeneratePublicKey(_ sender: Any) {
        do {
            try Shared.keypair.deleteKeyPair()
            let key = try Shared.keypair.publicKey().data()
            publicKeyTextView.text = key.der
        } catch {
            publicKeyTextView.text = "Error: \(error)"
        }
    }
    
    var cycleIndex = 0
    let digests = ["ABC", "IS", "ABOUT", "ALL", "POTUS", "CAN", "READ"]
    
    @IBAction func createDigest(_ sender: Any) {
        cycleIndex += 1
        digestTextView.text = digests[cycleIndex % digests.count]
    }
    
    @IBAction func sign(_ sender: Any) {
        do {
            guard let digest = digestTextView.text?.data(using: .utf8) else {
                throw "Missing text in unencrypted text field"
            }
            let signature = try Shared.keypair.sign(digest)
            signatureTextView.text = signature.base64EncodedString()
            verifyAndLog(manager: Shared.keypair, signed: signature, digest: digest)
        } catch {
            publicKeyTextView.text = "Error: \(error)"
        }
    }
}

