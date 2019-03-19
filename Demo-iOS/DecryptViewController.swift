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

class DecryptViewController: UITableViewController {
    
    typealias EC = EllipticCurveKeyPair
    
    struct PrivateEncryptionKey {
        
        let label = "no.agens.encryption.key"
        let prompt = "Encrypt message"
        let token = EC.Token.secureEnclaveIfAvailable
        let accessControl = EC.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
        
        func load() throws -> EC.PrivateKey {
            return try EC.PrivateKey.load(label: label, keyType: .secp256r1, token: token).context(LAContext(), localizedReason: prompt)
        }
    }
    
    @IBOutlet weak var privateKeyTextView: UITextView!
    @IBOutlet weak var encryptedMessageTextView: UITextView!
    @IBOutlet weak var decryptedMessageTextView: UITextView!
    @IBOutlet weak var consoleTextView: UITextView!

    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    override func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return UITableViewAutomaticDimension
    }
    
    @IBAction func loadPrivateKey(_ sender: Any) {
        do {
            let privateKey = try PrivateEncryptionKey().load()
            do {
                privateKeyTextView.text = try privateKey.export().raw.toHexString()
            } catch {
                privateKeyTextView.text = "(not able to export key)"
                log("Error: \(error)")
            }
        } catch {
            log("Error: \(error)")
        }
        tableView.reloadData()
    }
    
    @IBAction func pastePrivateKey(_ sender: Any) {
        privateKeyTextView.text = UIPasteboard.general.string
        tableView.reloadData()
    }
    
    @IBAction func pasteEncryptedMessage(_ sender: Any) {
        encryptedMessageTextView.text = UIPasteboard.general.string
        tableView.reloadData()
    }
    
    @IBAction func copyDecryptedMessage(_ sender: Any) {
        UIPasteboard.general.string = decryptedMessageTextView.text
    }
    
    func log(_ string: String) {
        print(string)
        consoleTextView.text = "\(string)\n\n\(consoleTextView.text ?? String())"
        tableView.reloadData()
    }
    
    @IBAction func decrypt(_ sender: Any) {
        let privateKeyString = privateKeyTextView.text
        let encryptedMessage = encryptedMessageTextView.text
        
        DispatchQueue.global().async {
            do {
                // FIXME: Support PEM and DER
                guard let privateKeyString = privateKeyString else {
                    throw GenericError(message: "Could not read private key")
                }
                guard let encryptedMessage = encryptedMessage?.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: ""),
                    let encryptedData = Data(base64Encoded: encryptedMessage) else {
                        throw GenericError(message: "Could not read encrypted message as base 64")
                }
                let privateKey: EC.PrivateKey
                if privateKeyString == "(not able to export key)" {
                    privateKey = try PrivateEncryptionKey().load()
                } else {
                    //let keyData = try EC.PrivateKeyData(raw: <#T##Data#>, keyType: <#T##EllipticCurveKeyPair.KeyType#>)
                    privateKey = try PrivateEncryptionKey().load() // TODO: Load from memory
                }
                
                let decryptedData = try privateKey.decrypt(encryptedData, .eciesEncryptionStandardX963SHA256AESGCM)
                guard let decryptedMessage = String(data: decryptedData, encoding: .utf8) else {
                    throw GenericError(message: "Expected message to be utf-8")
                }
                DispatchQueue.main.async {
                    self.decryptedMessageTextView.text = decryptedMessage
                    self.log("Decrypted ✅")
                }
            } catch {
                DispatchQueue.main.async {
                    self.log("Error: \(error)")
                }
            }
        }
    }
}

