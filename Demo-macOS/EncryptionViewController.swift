//
//  EncryptionViewController.swift
//  Demo-macOS
//
//  Created by Håvard Fossli on 15.11.2017.
//  Copyright © 2017 Agens AS. All rights reserved.
//

import Cocoa
import LocalAuthentication
import EllipticCurveKeyPair

class EncryptionViewController: NSViewController {
    
    struct Shared {
        
        static var privateKeyAccessFlags: SecAccessControlCreateFlags {
            if EllipticCurveKeyPair.Device.hasTouchID {
                return [.userPresence, .privateKeyUsage]
            } else {
                return [.devicePasscode]
            }
        }
        
        static let keypair: EllipticCurveKeyPair.Manager = {
            EllipticCurveKeyPair.logger = { print($0) }
            let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAlwaysThisDeviceOnly, flags: [])
            let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: privateKeyAccessFlags)
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "no.agens.encrypt.public",
                privateLabel: "no.agens.encrypt.private",
                operationPrompt: "Decrypt",
                publicKeyAccessControl: publicAccessControl,
                privateKeyAccessControl: privateAccessControl,
                token: .secureEnclaveIfAvailable)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }
    
    var context: LAContext! = LAContext()
    var decrypted = true
    
    @IBOutlet weak var publicKeyTextView: NSTextView!
    @IBOutlet weak var encryptDecryptTitleLabel: NSTextFieldCell!
    @IBOutlet weak var encryptDecryptTextView: NSTextView!
    @IBOutlet weak var encryptDecryptButton: NSButton!
    @IBOutlet weak var resetButton: NSButton!
    
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
                    encryptDecryptTextView.string = message
                    encryptDecryptButton.title = "Encrypt"
                    encryptDecryptTitleLabel.title = "Unencrypted (plain text)"
                    encryptDecryptButton.isHidden = false
                    resetButton.isHidden = true
                case let .encrypted(text):
                    encryptDecryptTextView.string = text
                    encryptDecryptButton.title = "Decrypt"
                    encryptDecryptTitleLabel.title = "Encrypted"
                    resetButton.isHidden = true
                case let .error(error):
                    encryptDecryptTextView.string = "Error: \(error)"
                    encryptDecryptTitleLabel.title = "Error"
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
            publicKeyTextView.string = key.PEM
        } catch {
            publicKeyTextView.string = "Error: \(error)"
        }
    }
    
    @IBAction func regeneratePublicKey(_ sender: Any) {
        context = LAContext()
        do {
            try Shared.keypair.deleteKeyPair()
            let key = try Shared.keypair.publicKey().data()
            publicKeyTextView.string = key.PEM
        } catch {
            publicKeyTextView.string = "Error: \(error)"
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
            guard let input = encryptDecryptTextView.string.data(using: .utf8) else {
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
            guard let encrypted = Data(base64Encoded: self.encryptDecryptTextView.string) else {
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
        }, thenOnMain: { encrypted, decrypted in
            self.state = .decrypted(decrypted)
        }, catchToMain: { (error) in
            self.state = .error(error)
        })
    }
    
}
