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
import LocalAuthentication
import EllipticCurveKeyPair

class VerifyViewController: UITableViewController {
    
    typealias EC = EllipticCurveKeyPair
    
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var digestTextView: UITextView!
    @IBOutlet weak var signatureTextView: UITextView!
    @IBOutlet weak var consoleTextView: UITextView!

    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    override func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return UITableViewAutomaticDimension
    }
    
    @IBAction func pastePublicKey(_ sender: Any) {
        publicKeyTextView.text = UIPasteboard.general.string
        tableView.reloadData()
    }
    
    @IBAction func pasteDigest(_ sender: Any) {
        digestTextView.text = UIPasteboard.general.string
        tableView.reloadData()
    }
    
    @IBAction func pasteSignature(_ sender: Any) {
        signatureTextView.text = UIPasteboard.general.string
        tableView.reloadData()
    }
    
    func log(_ string: String) {
        print(string)
        consoleTextView.text = "\(string)\n\n\(consoleTextView.text ?? String())"
        tableView.reloadData()
    }
    
    @IBAction func verify(_ sender: Any) {
        do {
            // FIXME: Support PEM and DER
            guard let publicKeyString = publicKeyTextView.text else {
                throw GenericError(message: "Could not read public key as base64")
            }
            guard let digestString = digestTextView.text, let digest = digestString.data(using: .utf8) else {
                throw GenericError(message: "Could not read digest as utf-8")
            }
            let signatureString = signatureTextView.text.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "")
            guard let signatureData = Data(base64Encoded: signatureString) else {
                throw GenericError(message: "Could not read signature as base 64")
            }
            let keyData = try EC.PublicKeyData(PEM: publicKeyString)
            let publicKey = try EC.PublicKey.temporary(data: keyData)
            let signature = EC.Signature(signatureData)
            
            try publicKey.verify(signature: signature, digest: digest, algorithm: .ecdsaSignatureMessageX962SHA256)
            log("Signature is valid ✅")
        } catch {
            log("Error: \(error)")
        }
    }
}

