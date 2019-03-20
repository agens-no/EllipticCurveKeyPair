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

class PrivateKeyTests: XCTestCase {
    
    typealias EC = EllipticCurveKeyPair
    
    var index = 0
    func randomLabel() -> String {
        index += 1
        return "key.\(type(of: self)).\(index)"
    }
    
    func testCreateLoadAndDelete() {
        
        let label = randomLabel()
        let accessControl = EC.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
        
        do { // Create
            let _ = try EC.PrivateKey.createRandom(label: label, keyType: .secp256r1, accessControl: accessControl, token: .keychain)
            let _ = try EC.PrivateKey.load(label: label, keyType: .secp256r1, token: .keychain)
            try EC.PrivateKey.delete(label: label, keyType: .secp256r1)
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testDoubleCreateGivesError() {
        
        let label = randomLabel()
        let accessControl = EC.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
        
        do { // Create
            let _ = try EC.PrivateKey.createRandom(label: label, keyType: .secp256r1, accessControl: accessControl, token: .keychain)
        } catch {
            XCTFail("\(error)")
        }
        
        do { // Create again
            let _ = try EC.PrivateKey.createRandom(label: label, keyType: .secp256r1, accessControl: accessControl, token: .keychain)
            XCTFail("Expected error, but got key")
        } catch let EC.Error.underlying(_, error) {
            XCTAssertEqual(error.domain, NSOSStatusErrorDomain)
            XCTAssertEqual(OSStatus(error.code), errSecDuplicateItem)
        } catch {
            XCTFail("Didn't expect: \(error)")
        }
    }
    
    func testDeletingNonExistentKeyFails() {
        
        let label = randomLabel()
        let accessControl = EC.AccessControl(protection: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags: [.userPresence, .privateKeyUsage])
        
        do { // Create
            let _ = try EC.PrivateKey.createRandom(label: label, keyType: .secp256r1, accessControl: accessControl, token: .keychain)
            let _ = try EC.PrivateKey.load(label: label, keyType: .secp256r1, token: .keychain)
            try EC.PrivateKey.delete(label: label, keyType: .secp256r1)
        } catch {
            XCTFail("\(error)")
        }
        
        do { // Create again
            try EC.PrivateKey.delete(label: label, keyType: .secp256r1)
            XCTFail("Expected error")
        } catch let EC.Error.underlying(_, error) {
            XCTAssertEqual(error.domain, NSOSStatusErrorDomain)
            XCTAssertEqual(OSStatus(error.code), errSecItemNotFound)
        } catch {
            XCTFail("Didn't expect: \(error)")
        }
    }
}
