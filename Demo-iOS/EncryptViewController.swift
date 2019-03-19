//
//  EncryptViewController.swift
//  Demo-iOS
//
//  Created by Håvard Fossli on 19.03.2019.
//  Copyright © 2019 Agens AS. All rights reserved.
//

import UIKit
import LocalAuthentication
import EllipticCurveKeyPair

class EncryptViewController: UITableViewController {
    
    typealias EC = EllipticCurveKeyPair
    
    struct PrivateEncryptionKey {
        
        let label = "no.agens.encryption.key"
        let prompt = "Encrypt message"
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
    @IBOutlet weak var encryptedMessageBase64TextView: UITextView!
    @IBOutlet weak var encryptedMessageHexTextView: UITextView!
    @IBOutlet weak var consoleTextView: UITextView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    override func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return UITableViewAutomaticDimension
    }
    
    @IBAction func regeneratePrivateKey(_ sender: Any) {
        do {
            try PrivateEncryptionKey().delete()
        } catch {
            log("Error: \(error)")
        }
        do {
            let privateKey = try PrivateEncryptionKey().create()
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
    
    @IBAction func copyEncryptedMessageInBase64(_ sender: Any) {
        UIPasteboard.general.string = encryptedMessageBase64TextView.text
    }
    
    @IBAction func copyEncryptedMessageInHex(_ sender: Any) {
        UIPasteboard.general.string = encryptedMessageHexTextView.text
    }
    
    func log(_ string: String) {
        print(string)
        consoleTextView.text = "\(string)\n\n\(consoleTextView.text ?? String())"
        tableView.reloadData()
    }
    
    @IBAction func encrypt(_ sender: Any) {
        do {
            guard let digest = self.digestTextView.text?.data(using: .utf8) else {
                throw GenericError(message: "Could not read digest")
            }
            guard let publicKeyString = publicKeyTextView.text else {
                throw GenericError(message: "Could not read public key")
            }
            
            let keyData = try EC.PublicKeyData(PEM: publicKeyString)
            let publicKey = try EC.PublicKey.temporary(data: keyData)
            let encryptedMessage = try publicKey.encrypt(digest, .eciesEncryptionStandardX963SHA256AESGCM)
            
            self.encryptedMessageBase64TextView.text = encryptedMessage.base64EncodedString(options: [.endLineWithLineFeed, .endLineWithCarriageReturn, .lineLength64Characters])
            self.encryptedMessageHexTextView.text = encryptedMessage.toHexString()
            self.tableView.reloadData()
        } catch {
            self.log("Error: \(error)")
        }
    }
    
}

