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

class EncryptionViewController: UIViewController {
    
    struct Shared {
        static let keypair: EllipticCurveKeyPair.Manager = {
            EllipticCurveKeyPair.logger = { print($0) }
            let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAlwaysThisDeviceOnly, flags: [])
            let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.touchIDAny, .privateKeyUsage])
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "no.agens.encrypt.public",
                privateLabel: "no.agens.encrypt.private",
                operationPrompt: "Decrypt",
                publicKeyAccessControl: publicAccessControl,
                privateKeyAccessControl: privateAccessControl,
                fallbackToKeychainIfSecureEnclaveIsNotAvailable: true)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }
    
    var context: LAContext! = LAContext()
    var decrypted = true

    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var encryptDecryptTitleLabel: UILabel!
    @IBOutlet weak var encryptDecryptTextView: UITextView!
    @IBOutlet weak var encryptDecryptButton: UIButton!
    @IBOutlet weak var resetButton: UIButton!
    
    enum State {
        case decrypted(String)
        case encrypted(String)
        case error(Error)
    }
    
    var state: State? {
        didSet {
            if let state = state {
                switch state {
                case let .decrypted(message):
                    encryptDecryptTextView.text = message
                    encryptDecryptButton.setTitle("Encrypt", for: .normal)
                    encryptDecryptTitleLabel.text = "Unencrypted (plain text)"
                    encryptDecryptButton.isHidden = false
                    resetButton.isHidden = true
                case let .encrypted(text):
                    encryptDecryptTextView.text = text
                    encryptDecryptButton.setTitle("Decrypt", for: .normal)
                    encryptDecryptTitleLabel.text = "Encrypted"
                    encryptDecryptButton.isHidden = false
                    resetButton.isHidden = true
                case let .error(error):
                    encryptDecryptTextView.text = "Error: \(error)"
                    encryptDecryptTitleLabel.text = "Error"
                    encryptDecryptButton.isHidden = true
                    resetButton.isHidden = false
                }
            }
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
            
        state = .decrypted("Lorem ipsum dolor sit er elit lamet")
        
        do {
            let key = try Shared.keypair.publicKey().data()
            publicKeyTextView.text = key.PEM
        } catch {
            publicKeyTextView.text = "Error: \(error)"
        }
    }
    
    @IBAction func regeneratePublicKey(_ sender: Any) {
        context = LAContext()
        do {
            try Shared.keypair.deleteKeyPair()
            let key = try Shared.keypair.publicKey().data()
            publicKeyTextView.text = key.PEM
        } catch {
            publicKeyTextView.text = "Error: \(error)"
        }
    }
    
    @IBAction func encryptOrDecrypt(_ sender: Any) {
        if case .decrypted = state! {
            encrypt()
        } else {
            decrypt()
        }
    }
    
    @IBAction func reset(_ sender: Any) {
        state = .decrypted("Lorem ipsum dolor sit er elit lamet")
    }
    
    func encrypt() {
        do {
            guard let input = encryptDecryptTextView.text?.data(using: .utf8) else {
                throw "Missing/bad text in unencrypted text field"
            }
            guard #available(iOS 10.3, *) else {
                throw "Can not encrypt on this device (must be iOS 10.3)"
            }
            let result = try Shared.keypair.encrypt(input)
            state = .encrypted(result.base64EncodedString())
        } catch {
            state = .error(error)
        }
    }
    
    func decrypt() {
        
        /*
         Using the DispatchQueue.roundTrip defined in Utils.swift is totally optional.
         What's important is that you call `decrypt` on a different thread than main.
         */
        
        DispatchQueue.roundTrip({ () -> Data in
            guard let encrypted = Data(base64Encoded: self.encryptDecryptTextView.text ?? "") else {
                throw "Missing text in unencrypted text field"
            }
            return encrypted
        }, thenAsync: { (encrypted) -> String in
            guard #available(iOS 10.3, *) else {
                throw "Can not encrypt on this device (must be iOS 10.3)"
            }
            let result = try Shared.keypair.decrypt(encrypted, authenticationContext: self.context)
            guard let decrypted = String(data: result, encoding: .utf8) else {
                throw "Could not convert decrypted data to string"
            }
            return decrypted
        }, thenOnMain: { (decrypted) in
            self.state = .decrypted(decrypted)
        }, catchToMain: { (error) in
            self.state = .error(error)
        })
    }
}

