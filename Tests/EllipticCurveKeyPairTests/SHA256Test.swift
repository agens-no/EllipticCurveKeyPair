//
//  SHA256Test.swift
//  EllipticCurveKeyPairDemoTests
//
//  Created by Håvard Fossli on 16.10.2017.
//  Copyright © 2017 Agens AS. All rights reserved.
//

import XCTest
import EllipticCurveKeyPair

extension Data {
    func toHexString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

class SHA256Test: XCTestCase {
    
    func testEmpty() {
        let msg = "".data(using: .utf8)!
        let result = msg.sha256().toHexString()
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // echo -n "" | openssl dgst -sha256
        XCTAssertEqual(result, expected, "Invalid conversion from msg to sha256")
    }
    
    func testAgainstKnownValue() {
        let msg = "foobar".data(using: .utf8)!
        let result = msg.sha256().toHexString()
        let expected = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2" // echo -n "foobar" | openssl dgst -sha256
        XCTAssertEqual(result, expected, "Invalid conversion from msg to sha256")
    }
    
    func testAgainstKnownValue2() {
        let msg = "æøå".data(using: .utf8)!
        let result = msg.sha256().toHexString()
        let expected = "6c228cdba89548a1af198f33819536422fb01b66e51f761cf2ec38d1fb4178a6" // echo -n "æøå" | openssl dgst -sha256
        XCTAssertEqual(result, expected, "Invalid conversion from msg to sha256")
    }
    
    func testAgainstKnownValue3() {
        let msg = "KfZ=Day*q4MsZ=_xRy4G_Uefk?^Ytr&2xL*RYY%VLyB_&c7R_dr&J+8A79suf=^".data(using: .utf8)!
        let result = msg.sha256().toHexString()
        let expected = "b754632a872b3f5ddb0e1e24b531e35eb334ee3c2957618ac4a2ac4047ed6127" // echo -n "KfZ=Day*q4MsZ=_xRy4G_Uefk?^Ytr&2xL*RYY%VLyB_&c7R_dr&J+8A79suf=^" | openssl dgst -sha256
        XCTAssertEqual(result, expected, "Invalid conversion from msg to sha256")
    }
    
    func testAgainstKnownValue4() {
        let msg = "Lorem ipsum dolor sit amet, suas consequuntur mei ad, duo eu noluisse adolescens temporibus. Mutat fuisset constituam te vis. Animal meliore cu has, ius ad recusabo complectitur. Eam at persius inermis sensibus. Mea at velit nobis dolor, vitae omnium eos an, ei dolorum pertinacia nec.".data(using: .utf8)!
        let result = msg.sha256().toHexString()
        let expected = "31902eb17aa07165b645553c14b985c1908c7d8f4f5178de61a3232f09940df7" // echo -n "Lorem ipsum dolor sit amet, suas consequuntur mei ad, duo eu noluisse adolescens temporibus. Mutat fuisset constituam te vis. Animal meliore cu has, ius ad recusabo complectitur. Eam at persius inermis sensibus. Mea at velit nobis dolor, vitae omnium eos an, ei dolorum pertinacia nec." | openssl dgst -sha256
        XCTAssertEqual(result, expected, "Invalid conversion from msg to sha256")
    }
    
    func testAgainstKnownValue5() {
        let msg = "0".data(using: .utf8)!
        let result = msg.sha256().toHexString()
        let expected = "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9" // echo -n "0" | openssl dgst -sha256
        XCTAssertEqual(result, expected, "Invalid conversion from msg to sha256")
    }
    
    static var allTests = [
        ("testEmpty", testEmpty),
        ("testAgainstKnownValue", testAgainstKnownValue),
        ("testAgainstKnownValue2", testAgainstKnownValue2),
        ("testAgainstKnownValue3", testAgainstKnownValue3),
        ("testAgainstKnownValue4", testAgainstKnownValue4),
        ("testAgainstKnownValue5", testAgainstKnownValue5),
        ]
}
