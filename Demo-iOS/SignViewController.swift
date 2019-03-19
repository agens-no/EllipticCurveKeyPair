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

class SignViewController: UITableViewController {
    
    typealias EC = EllipticCurveKeyPair
    
    struct PrivateSigningKey {
        
        let label = "no.agens.signing.key"
        let prompt = "Sign transaction"
        let token = EC.Token.secureEnclaveIfAvailable
        let accessControl = EC.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
        
        func load() throws -> EC.PrivateKey {
            return try EC.PrivateKey.load(label: label, keyType: .secp256r1, token: token).context(LAContext(), localizedReason: prompt)
        }
        
        func create() throws -> EC.PrivateKey {
            return try EC.PrivateKey.createRandom(label: label, keyType: .secp256r1, accessControl: accessControl, token: token).context(LAContext(), localizedReason: prompt)
        }
        
        func delete() throws {
            try EC.PrivateKey.delete(label: label, keyType: .secp256r1)
        }
    }
    
    @IBOutlet weak var privateKeyTextView: UITextView!
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var digestTextView: UITextView!
    @IBOutlet weak var signatureBase64TextView: UITextView!
    @IBOutlet weak var signatureHexTextView: UITextView!
    @IBOutlet weak var consoleTextView: UITextView!

    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    override func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return UITableViewAutomaticDimension
    }
    
    @IBAction func regeneratePrivateKey(_ sender: Any) {
        do {
            try PrivateSigningKey().delete()
        } catch {
            log("Error: \(error)")
        }
        do {
            let privateKey = try PrivateSigningKey().create()
            publicKeyTextView.text = try privateKey.publicKey().export().PEM()
            
            do {
                privateKeyTextView.text = try privateKey.export().raw.toHexString()
            } catch {
                privateKeyTextView.text = "(not able to export key)"
                log("Error: \(error)")
            }
            tableView.reloadData()
        } catch {
            log("Error: \(error)")
        }
    }
    
    @IBAction func copyPublicKey(_ sender: Any) {
        UIPasteboard.general.string = publicKeyTextView.text
    }
    
    @IBAction func copyDigest(_ sender: Any) {
        UIPasteboard.general.string = digestTextView.text
    }
    
    @IBAction func pasteDigest(_ sender: Any) {
        digestTextView.text = UIPasteboard.general.string
        tableView.reloadData()
    }
    
    @IBAction func copySignatureInBase64(_ sender: Any) {
        UIPasteboard.general.string = signatureBase64TextView.text
    }
    
    @IBAction func copySignatureInHex(_ sender: Any) {
        UIPasteboard.general.string = signatureHexTextView.text
    }
    
    func log(_ string: String) {
        print(string)
        consoleTextView.text = "\(string)\n\n\(consoleTextView.text ?? String())"
        tableView.reloadData()
    }
    
    @IBAction func sign(_ sender: Any) {
        
        let digest = self.digestTextView.text?.data(using: .utf8)
        
        DispatchQueue.global().async {
            do {
                guard let digest = digest else {
                    throw GenericError(message: "Missing text in unencrypted text field")
                }
                let signature = try PrivateSigningKey().load().sign(digest, .ecdsaSignatureMessageX962SHA256)
                
                DispatchQueue.main.async {
                    self.signatureBase64TextView.text = signature.asn1Formatted.base64EncodedString(options: [.endLineWithLineFeed, .endLineWithCarriageReturn, .lineLength64Characters])
                    self.signatureHexTextView.text = signature.asn1Formatted.toHexString()
                    self.tableView.reloadData()
                }
            } catch {
                DispatchQueue.main.async {
                    self.log("Error: \(error)")
                }
            }
        }
    }
    
}

