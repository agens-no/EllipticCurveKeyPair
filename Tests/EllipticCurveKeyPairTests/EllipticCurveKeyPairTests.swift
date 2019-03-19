//
//  EllipticCurveKeyPairTests.swift
//  Agens AS
//
//  Created by Håvard Fossli on 19.10.2017.
//  Copyright © 2017 Agens AS. All rights reserved.
//

import Foundation
import XCTest
import EllipticCurveKeyPair

class EllipticCurveKeyPairTests: XCTestCase {
    
    typealias EC = EllipticCurveKeyPair
    
    var index = 0
    func randomLabel() -> String {
        index += 1
        return "key.\(type(of: self)).\(index)"
    }
    
    func testCreateLoadAndDelete() {
        
        let label = randomLabel()
        let token = EC.Token.keychain
        let accessControl = EC.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
        
        do { // Create
            let _ = try EC.PrivateKey.createRandom(label: label, keyType: .secp256r1, accessControl: accessControl, token: token)
        } catch {
            XCTFail("\(error)")
        }
        
        do { // Load
            let _ = try EC.PrivateKey.load(label: label, keyType: .secp256r1, token: token)
        } catch {
            XCTFail("\(error)")
        }
        
        do { // Delete
            try EC.PrivateKey.delete(label: label, keyType: .secp256r1)
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testDoubleCreate() {
        
        let label = "no.agens.sign.public"
        let token = EC.Token.keychain
        let accessControl = EC.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
        
        do { // Create
            let _ = try EC.PrivateKey.createRandom(label: label, keyType: .secp256r1, accessControl: accessControl, token: token)
        } catch {
            XCTFail("\(error)")
        }
        
        do { // Load
            let _ = try EC.PrivateKey.load(label: label, keyType: .secp256r1, token: token)
        } catch {
            XCTFail("\(error)")
        }
        
        do { // Delete
            try EC.PrivateKey.delete(label: label, keyType: .secp256r1)
        } catch {
            XCTFail("\(error)")
        }
    }
}
