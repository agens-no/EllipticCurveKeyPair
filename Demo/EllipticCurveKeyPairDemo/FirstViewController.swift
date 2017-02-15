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

class FirstViewController: UIViewController {
    
    struct Shared {
        static let keypair: EllipticCurveKeyPair.Manager = {
            let publicLabel = "no.agens.encrypt.public"
            let privateLabel = "no.agens.encrypt.private"
            let prompt = "Confirm payment"
            let sha256: (Data) -> Data = { return ELCKPCommonCryptoAccess.sha256Digest(for: $0) }
            let helper = EllipticCurveKeyPair.Helper(publicLabel: publicLabel, privateLabel: privateLabel, operationPrompt: prompt, sha256: sha256)
            return EllipticCurveKeyPair.Manager(helper: helper)
        }()
    }

    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var unencryptedTextView: UITextView!
    @IBOutlet weak var encryptedTextView: UITextView!
    
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

    @IBAction func encrypt(_ sender: Any) {
        do {
            guard let input = unencryptedTextView.text?.data(using: .utf8) else {
                throw "Missing/bad text in unencrypted text field"
            }
            
            guard #available(iOS 10.3, *) else {
                throw "Can not encrypt on this device (must be iOS 10.3)"
            }
            
            let result = try Shared.keypair.encrypt(input)
            encryptedTextView.text = result.base64EncodedString()
        } catch {
            encryptedTextView.text = "Error: \(error)"
        }
    }
    
    @IBAction func decrypt(_ sender: Any) {
        do {
            guard let input = Data(base64Encoded: encryptedTextView.text ?? "") else {
                throw "Missing text in unencrypted text field"
            }
            
            guard #available(iOS 10.3, *) else {
                throw "Can not encrypt on this device (must be iOS 10.3)"
            }
            
            let result = try Shared.keypair.decrypt(input)
            
            let string = String.init(data: result, encoding: .utf8)
            
            unencryptedTextView.text = string
        } catch {
            unencryptedTextView.text = "Error: \(error)"
        }
    }
}

