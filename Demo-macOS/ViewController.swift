//
//  ViewController.swift
//  Demo-macOS
//
//  Created by Håvard Fossli on 13.11.2017.
//  Copyright © 2017 Agens AS. All rights reserved.
//

import Cocoa
import LocalAuthentication
import EllipticCurveKeyPair

class ViewController: NSViewController {
    
    @IBOutlet weak var signature: SignatureViewController!

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }


}

