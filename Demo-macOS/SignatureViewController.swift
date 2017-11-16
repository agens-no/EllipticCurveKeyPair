//
//  SignatureViewController.swift
//  Demo-macOS
//
//  Created by Håvard Fossli on 15.11.2017.
//  Copyright © 2017 Agens AS. All rights reserved.
//

import Cocoa
import LocalAuthentication
import EllipticCurveKeyPair

class SignatureViewController: NSViewController {
    
    struct Shared {
        
        static let keypair: EllipticCurveKeyPair.Manager = {
            EllipticCurveKeyPair.logger = { print($0) }
            let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAlwaysThisDeviceOnly, flags: [])
            let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: {
                return EllipticCurveKeyPair.Device.hasSecureEnclave ? [.userPresence, .privateKeyUsage] : [.userPresence]
            }())
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "no.agens.sign.public",
                privateLabel: "no.agens.sign.private",
                operationPrompt: "Sign transaction",
                publicKeyAccessControl: publicAccessControl,
                privateKeyAccessControl: privateAccessControl,
                token: .secureEnclaveIfAvailable)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }
    
    var context: LAContext! = LAContext()
    
    @IBOutlet weak var publicKeyTextView: NSTextView!
    @IBOutlet weak var digestTextView: NSTextView!
    @IBOutlet weak var signatureTextView: NSTextView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
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
    
    var cycleIndex = 0
    let digests = ["Lorem ipsum dolor sit amet", "mei nibh tritani ex", "exerci periculis instructior est ad"]
    
    @IBAction func createDigest(_ sender: Any) {
        cycleIndex += 1
        digestTextView.string = digests[cycleIndex % digests.count]
    }
    
    @IBAction func sign(_ sender: Any) {
        
        /*
         Using the DispatchQueue.roundTrip defined in Utils.swift is totally optional.
         What's important is that you call `sign` on a different thread than main.
         */
        
        DispatchQueue.roundTrip({
            guard let digest = "foo".data(using: .utf8) else {
                throw "Missing text in unencrypted text field"
            }
            return digest
        }, thenAsync: { digest in
            return try Shared.keypair.sign(digest, algorithm: .sha256, authenticationContext: self.context)
        }, thenOnMain: { digest, signature in
            try Shared.keypair.verify(signature: signature, originalDigest: digest, algorithm: .sha256)
            try printVerifySignatureInOpenssl(manager: Shared.keypair, signed: signature, digest: digest, shaAlgorithm: "sha256")
            self.signatureTextView.string = signature.base64EncodedString()
        }, catchToMain: { error in
            self.signatureTextView.string = "Error: \(error)"
        })
    } 
    
}
