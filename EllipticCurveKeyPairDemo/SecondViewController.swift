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

func delay( _ delay: Double, queue: DispatchQueue = DispatchQueue.main, completion: @escaping () -> () ) {
    queue.asyncAfter(deadline: DispatchTime.now() + Double(Int64(delay * Double(NSEC_PER_SEC))) / Double(NSEC_PER_SEC)) { () -> Void in
        completion()
    }
}


class SecondViewController: UIViewController {
    
    struct Shared {
        static let keypair: EllipticCurveKeyPair.Manager = {
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "no.agens.sign.public",
                privateLabel: "no.agens.sign.private",
                operationPrompt: "Confirm payment",
                accessControl: try! SecAccessControl.create(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage]),
                fallbackToKeychainIfSecureEnclaveIsNotAvailable: true)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }
    
    var context: LAContext! = LAContext()
    
    @IBOutlet weak var publicKeyTextView: UITextView!
    @IBOutlet weak var digestTextView: UITextView!
    @IBOutlet weak var signatureTextView: UITextView!

    override func viewDidLoad() {
        super.viewDidLoad()
        
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
    
    var cycleIndex = 0
    let digests = ["Lorem ipsum dolor sit amet", "mei nibh tritani ex", "exerci periculis instructior est ad"]
    
    @IBAction func createDigest(_ sender: Any) {
        cycleIndex += 1
        digestTextView.text = digests[cycleIndex % digests.count]
    }
    
    @IBAction func sign(_ sender: Any) {
        
        /*
         Using the DispatchQueue.roundTrip is totally optional.
         What's important is that you call `sign` on a different thread than main.
         */
        
        DispatchQueue.roundTrip({
            guard let digest = self.digestTextView.text?.data(using: .utf8) else {
                throw "Missing text in unencrypted text field"
            }
            return digest
        }, thenAsync: { digest in
            return try Shared.keypair.sign(digest, authenticationContext: self.context)
        }, thenOnMain: { signature in
            self.signatureTextView.text = signature.base64EncodedString()
        }, catchToMain: { error in
            self.signatureTextView.text = "Error: \(error)"
        })
    }
    
}

