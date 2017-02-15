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


import Foundation
import Security

public struct EllipticCurveKeyPair {
    
    // A stateful manager for using the secure enclave and keychain
    public final class Manager {
        
        public init(helper: Helper) {
            self.helper = helper
        }
        
        private var cache: (`public`: PublicKey, `private`: PrivateKey)? = nil
        private let helper: Helper
        
        func deleteKeyPair() throws {
            cache = nil
            try helper.delete()
        }
        
        func publicKey() throws -> PublicKey {
            return try getKeys().public
        }
        
        func privateKey() throws -> PrivateKey {
            return try getKeys().private
        }
        
        func verify(signature: Data, originalDigest: Data) throws -> Bool {
            return try helper.verify(signature: signature, digest: originalDigest, publicKey: getKeys().public)
        }
        
        func sign(_ digest: Data) throws -> Data {
            return try helper.sign(digest, privateKey: getKeys().private)
        }
        
        @available(iOS 10.3, *)
        func encrypt(_ digest: Data) throws -> Data {
            return try helper.encrypt(digest, publicKey: getKeys().public)
        }
        
        @available(iOS 10.3, *)
        func decrypt(_ digest: Data) throws -> Data {
            return try helper.decrypt(digest, privateKey: getKeys().private)
        }
        
        func getKeys() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            if let keys = cache {
                return keys
            }
            if let keyPair = try? helper.get() {
                cache = keyPair
                return keyPair
            }
            let accessControl = try helper.accessControl(with: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
            let keyPair = try helper.generate(accessControl: accessControl)
            cache = keyPair
            return keyPair
        }
    }
    
    // A stateless helper for querying the secure enclave and keychain
    // Create a small stateful facade if necessary
    public struct Helper {
        
        // The user visible label in the device's key chain
        let publicLabel: String
        
        // The label used to identify the key in the secure enclave
        let privateLabel: String
        
        // The text presented to the user about why we need his/her fingerprint / device pin
        let operationPrompt: String
        
        // A function performing sha256 and returning the result
        let sha256: (Data) -> Data
        
        func get() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            do {
                let publicKey = try Query.getPublicKey(labeled: publicLabel)
                let privateKey = try Query.getPrivateKey(labeled: privateLabel)
                return (public: publicKey, private: privateKey)
            } catch let error {
                throw error
            }
        }
        
        func generate(accessControl: SecAccessControl) throws -> (`public`: PublicKey, `private`: PrivateKey) {
            
            let privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: privateLabel,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
                kSecUseOperationPrompt as String: self.operationPrompt,
                ]
            
            #if (arch(i386) || arch(x86_64)) && os(iOS) // simulator
                let params: [String: Any] = [
                    kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                    kSecPrivateKeyAttrs as String: privateKeyParams,
                    kSecAttrKeySizeInBits as String: 256,
                    ]
            #else // device
                let params: [String: Any] = [
                    kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                    kSecPrivateKeyAttrs as String: privateKeyParams,
                    kSecAttrKeySizeInBits as String: 256,
                    ]
            #endif
            
            var publicOptional, privateOptional: SecKey?
            let status = SecKeyGeneratePair(params as CFDictionary, &publicOptional, &privateOptional)
            guard status == errSecSuccess else {
                throw Error.underlying(message: "Could not generate keypair", osStatus: status)
            }
            guard let publicSec = publicOptional, let privateSec = privateOptional else {
                throw Error.inconcistency(message: "Created private public key pair successfully, but weren't able to retreive it")
            }
            let publicKey = PublicKey(publicSec)
            let privateKey = PrivateKey(privateSec)
            try Query.forceSavePublicKey(publicKey, label: publicLabel)
            return (public: publicKey, private: privateKey)
        }
        
        func delete() throws {
            try Query.deletePublicKey(labeled: publicLabel)
            try Query.deletePrivateKey(labeled: privateLabel)
        }
        
        func sign(_ digest: Data, privateKey: PrivateKey) throws -> Data {
            
            let digestToSign = sha256(digest)
            var digestToSignBytes = [UInt8](repeating: 0, count: digestToSign.count)
            digestToSign.copyBytes(to: &digestToSignBytes, count: digestToSign.count)
            
            var signatureBytes = [UInt8](repeating: 0, count: 128)
            var signatureLength = 128
            
            let signErr = SecKeyRawSign(privateKey.underlying, .PKCS1, &digestToSignBytes, digestToSignBytes.count, &signatureBytes, &signatureLength)
            guard signErr == errSecSuccess else {
                throw Error.underlying(message: "Could not create signature", osStatus: signErr)
            }
            
            let signature = Data(bytes: &signatureBytes, count: signatureLength)
            return signature
        }
        
        func verify(signature: Data, digest: Data, publicKey: PublicKey) throws -> Bool {
            let sha = sha256(digest)
            var shaBytes = [UInt8](repeating: 0, count: sha.count)
            sha.copyBytes(to: &shaBytes, count: sha.count)
            
            var signatureBytes = [UInt8](repeating: 0, count: signature.count)
            signature.copyBytes(to: &signatureBytes, count: signature.count)
            
            let status = SecKeyRawVerify(publicKey.underlying, .PKCS1, &shaBytes, shaBytes.count, &signatureBytes, signatureBytes.count)
            guard status == errSecSuccess else {
                throw Error.underlying(message: "Could not verify signature", osStatus: status)
            }
            return true
        }
        
        @available(iOS 10.3, *)
        func encrypt(_ digest: Data, publicKey: PublicKey) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateEncryptedData(publicKey.underlying, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, digest as CFData, &error)
            guard let data = result as? Data else {
                throw Error.fromError(error)
            }
            return data
        }
        
        @available(iOS 10.3, *)
        func decrypt(_ digest: Data, privateKey: PrivateKey) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateDecryptedData(privateKey.underlying, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, digest as CFData, &error)
            guard let data = result as? Data else {
                throw Error.fromError(error)
            }
            return data
        }
        
        @available(iOSApplicationExtension 9.0, *)
        func accessControl(with protection: CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags: SecAccessControlCreateFlags = [.userPresence, .privateKeyUsage]) throws -> SecAccessControl {
            var error: Unmanaged<CFError>?
            let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection, flags, &error)
            guard accessControl != nil else {
                if let error = error?.takeRetainedValue() as? Swift.Error {
                    throw Error.inconcistency(message: error.localizedDescription)
                } else {
                    throw Error.inconcistency(message: "Tried creating access control object with flags \(flags) and protection \(protection)")
                }
            }
            return accessControl!
        }
    }
    
    private struct Query {
        
        static func getKey(_ query: [String: Any]) throws -> SecKey {
            var raw: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &raw)
            guard status == errSecSuccess, let result = raw else {
                throw Error.underlying(message: "Could not get key for query: \(query)", osStatus: status)
            }
            return result as! SecKey
        }
        
        static func publicKeyQuery(labeled: String) -> [String:Any] {
            return [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
            ]
        }
        
        static func privateKeyQuery(labeled: String) -> [String: Any] {
            return [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
                ]
        }
        
        static func getPublicKey(labeled: String) throws -> PublicKey {
            let query = publicKeyQuery(labeled: labeled)
            return PublicKey(try getKey(query))
        }
        
        static func getPrivateKey(labeled: String) throws -> PrivateKey {
            let query = privateKeyQuery(labeled: labeled)
            return PrivateKey(try getKey(query))
        }
        
        static func deletePublicKey(labeled: String) throws {
            let query = publicKeyQuery(labeled: labeled) as CFDictionary
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.underlying(message: "Could not delete private key", osStatus: status)
            }
        }
        
        static func deletePrivateKey(labeled: String) throws {
            let query = privateKeyQuery(labeled: labeled) as CFDictionary
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.underlying(message: "Could not delete private key", osStatus: status)
            }
        }
        
        static func forceSavePublicKey(_ publicKey: PublicKey, label: String) throws {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: label,
                kSecValueRef as String: publicKey.underlying
                ]
            var raw: CFTypeRef?
            var status = SecItemAdd(query as CFDictionary, &raw)
            if status == errSecDuplicateItem {
                status = SecItemDelete(query as CFDictionary)
                status = SecItemAdd(query as CFDictionary, &raw)
            }
            guard status == errSecSuccess else {
                throw Error.underlying(message: "Could not save public key", osStatus: status)
            }
        }
    }
    
    public struct Constants {
        static var x509Header: Data = Data(bytes: [UInt8]([48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0]))
        static let noCompression: UInt8 = 4
        static var attrKeyTypeEllipticCurve: String = {
            if #available(iOS 10.0, *) {
                return kSecAttrKeyTypeECSECPrimeRandom as String
            } else {
                return kSecAttrKeyTypeEC as String
            }
        }()
    }
    
    public final class PublicKeyData {
        
        // As received from Security framework
        let raw: Data
        
        // The open ssl compatible DER format X.509
        //
        // We take the raw key and prepend an ASN.1 prefix to it. The end result is an
        // ASN.1 SubjectPublicKeyInfo structure, which is what OpenSSL is looking for.
        //
        // See the following DevForums post for more details on this.
        //
        // <https://forums.developer.apple.com/message/84684#84684>.
        lazy var rawWithHeaders: Data = {
            var result = Constants.x509Header
            result.append(self.raw)
            return result
        }()
        
        lazy var der: String = {
            var lines = String()
            lines.append("-----BEGIN PUBLIC KEY-----\n")
            lines.append(self.rawWithHeaders.base64EncodedString())
            lines.append("\n-----END PUBLIC KEY-----")
            return lines
        }()
        
        fileprivate init(_ raw: Data) {
            self.raw = raw
        }
    }
    
    public final class PublicKey {
        
        let underlying: SecKey
        private var cachedData: PublicKeyData? = nil
        
        fileprivate init(_ underlying: SecKey) {
            self.underlying = underlying
        }
        
        func data() throws -> PublicKeyData {
            if let data = cachedData {
                return data
            } else {
                let data = try queryData()
                cachedData = data
                return data
            }
        }
        
        private func queryData() throws -> PublicKeyData {
            var matchResult: AnyObject? = nil
            let query: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: underlying,
                kSecReturnData as String: true
            ]
            let status = SecItemCopyMatching(query as CFDictionary, &matchResult)
            guard status == errSecSuccess else {
                throw Error.underlying(message: "Could not generate keypair", osStatus: status)
            }
            guard let keyRaw = matchResult as? Data else {
                throw Error.inconcistency(message: "Tried reading public key bytes, but something went wrong. Expected data, but received \(matchResult)")
            }
            var firstByte: [UInt8] = [UInt8](repeating: 0, count: 1)
            keyRaw.copyBytes(to: &firstByte, count: 1)
            guard firstByte.first == Constants.noCompression else {
                throw Error.inconcistency(message: "Tried reading public key bytes, but its headers says it is compressed")
            }
            return PublicKeyData(keyRaw)
        }
    }
    
    public final class PrivateKey {
        let underlying: SecKey
        fileprivate init(_ underlying: SecKey) {
            self.underlying = underlying
        }
    }
    
    public enum Error: Swift.Error {
        // Look up OSStatus error codes on https://www.osstatus.com/
        case underlying(message: String, osStatus: OSStatus)
        case inconcistency(message: String)
        
        static func fromError(_ error: Any?) -> Error {
            if let error = error as? Swift.Error {
                return .inconcistency(message: error.localizedDescription)
            } else {
                return .inconcistency(message: "\(error)")
            }
        }
    }
}
