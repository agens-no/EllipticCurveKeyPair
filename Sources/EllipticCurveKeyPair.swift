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
import LocalAuthentication

public struct EllipticCurveKeyPair {
        
    public struct Config {
        
        // The label used to identify the public key in keychain
        let publicLabel: String
        
        // The label used to identify the private key on the secure enclave
        let privateLabel: String
        
        // The text presented to the user about why we need his/her fingerprint / device pin
        let operationPrompt: String?
        
        // The access control used to manage the access to the keypair
        let accessControl: SecAccessControl
        
        // The access control used to manage the access to the keypair
        let fallbackToKeychainIfSecureEnclaveIsNotAvailable: Bool
    }
    
    // A stateful and opiniated manager for using the secure enclave and keychain
    // If there's a problem fetching the key pair this manager will naively just recreate new keypair
    // If the device doesn't have a Secure Enclave it will store the private key in keychain just like the public key
    //
    // If the manager is "too smart" in that sense you may use this manager as an example
    // and create your own manager
    public final class Manager {
        
        let config: Config
        private var cache: (`public`: PublicKey, `private`: PrivateKey)? = nil
        private let helper: Helper
        
        init(config: Config) {
            self.config = config
            self.helper = Helper(config: config)
        }
        
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
        
        func sign(_ digest: Data, authenticationContext: LAContext? = nil) throws -> Data {
            return try helper.sign(digest, privateKey: getKeys().private.accessibleWithAuthenticationContext(authenticationContext))
        }
        
        @available(iOS 10.3, *) // API available at 10.0, but bugs made it unusable on versions lower than 10.3
        func encrypt(_ digest: Data) throws -> Data {
            return try helper.encrypt(digest, publicKey: getKeys().public)
        }
        
        @available(iOS 10.3, *) // API available at 10.0, but bugs made it unusable on versions lower than 10.3
        func decrypt(_ encrypted: Data, authenticationContext: LAContext? = nil) throws -> Data {
            return try helper.decrypt(encrypted, privateKey: getKeys().private.accessibleWithAuthenticationContext(authenticationContext))
        }
        
        func getKeys() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            
            if let keys = cache {
                return keys
            }
            
            if let keyPair = try? helper.get() {
                cache = keyPair
                return keyPair
            }
            
            do {
                let keyPair = try helper.generateAndStoreOnSecureEnclave()
                cache = keyPair
                return keyPair
            } catch {
                if case let Error.underlying(message: _, error: underlying) = error,
                    underlying.code == errSecUnimplemented || underlying.code == errSecAuthFailed,
                    config.fallbackToKeychainIfSecureEnclaveIsNotAvailable {
                    let keyPair = try helper.generateAndStoreInKeyChain()
                    cache = keyPair
                    return keyPair
                } else {
                    throw error
                }
            }
        }
        
    }
    
    // Helper is a stateless class for querying the secure enclave and keychain
    // You may create a small stateful facade around this
    // `Manager` is an example of such an opiniated facade
    public struct Helper {
        
        // The user visible label in the device's key chain
        let config: Config
        
        func get() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            do {
                let publicKey = try Query.getPublicKey(labeled: config.publicLabel)
                let privateKey = try Query.getPrivateKey(labeled: config.privateLabel)
                return (public: publicKey, private: privateKey)
            } catch let error {
                throw error
            }
        }
        
        func generateAndStoreOnSecureEnclave() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            var privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.privateLabel,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: config.accessControl,
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
                ]
            
            if let operationPrompt = config.operationPrompt {
                privateKeyParams[kSecUseOperationPrompt as String] = operationPrompt
            }
            
            let params: [String: Any] = [
                kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: privateKeyParams,
                kSecAttrKeySizeInBits as String: 256,
                ]
            
            var publicOptional, privateOptional: SecKey?
            let status = SecKeyGeneratePair(params as CFDictionary, &publicOptional, &privateOptional)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not generate keypair.", osStatus: status)
            }
            guard let publicSec = publicOptional, let privateSec = privateOptional else {
                throw Error.inconcistency(message: "Created private public key pair successfully, but weren't able to retreive it.")
            }
            let publicKey = PublicKey(publicSec)
            let privateKey = PrivateKey(privateSec)
            try Query.forceSavePublicKey(publicKey, label: config.publicLabel)
            return (public: publicKey, private: privateKey)
        }
        
        func generateAndStoreInKeyChain() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.privateLabel,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: try SecAccessControl.create(protection: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags: [.userPresence]),
                ]
            let params: [String: Any] = [
                kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                kSecPrivateKeyAttrs as String: privateKeyParams,
                kSecAttrKeySizeInBits as String: 256,
                ]
            var publicOptional, privateOptional: SecKey?
            let status = SecKeyGeneratePair(params as CFDictionary, &publicOptional, &privateOptional)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not generate keypair.", osStatus: status)
            }
            guard let publicSec = publicOptional, let privateSec = privateOptional else {
                throw Error.inconcistency(message: "Created private public key pair successfully, but weren't able to retreive it.")
            }
            let publicKey = PublicKey(publicSec)
            let privateKey = PrivateKey(privateSec)
            try Query.forceSavePublicKey(publicKey, label: config.publicLabel)
            return (public: publicKey, private: privateKey)
        }
        
        func delete() throws {
            try Query.deletePublicKey(labeled: config.publicLabel)
            try Query.deletePrivateKey(labeled: config.privateLabel)
        }
        
        func sign(_ digest: Data, privateKey: PrivateKey) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            if #available(iOS 10.0, *) {
                let digestToSign = digest.sha256()
                var error : Unmanaged<CFError>?
                let result = SecKeyCreateSignature(privateKey.underlying, .ecdsaSignatureDigestX962SHA256, digestToSign as CFData, &error)
                guard let signature = result else {
                    throw Error.fromError(error?.takeRetainedValue(), message: "Could not create signature.")
                }
                return signature as Data
            } else {
                let digestToSign = digest.sha256()
                
                var digestToSignBytes = [UInt8](repeating: 0, count: digestToSign.count)
                digestToSign.copyBytes(to: &digestToSignBytes, count: digestToSign.count)
                
                var signatureBytes = [UInt8](repeating: 0, count: 128)
                var signatureLength = 128
                
                let signErr = SecKeyRawSign(privateKey.underlying, .PKCS1, &digestToSignBytes, digestToSignBytes.count, &signatureBytes, &signatureLength)
                guard signErr == errSecSuccess else {
                    throw Error.osStatus(message: "Could not create signature.", osStatus: signErr)
                }
                
                let signature = Data(bytes: &signatureBytes, count: signatureLength)
                return signature
            }
        }
        
        func verify(signature: Data, digest: Data, publicKey: PublicKey) throws -> Bool {
            let sha = digest.sha256()
            var shaBytes = [UInt8](repeating: 0, count: sha.count)
            sha.copyBytes(to: &shaBytes, count: sha.count)
            
            var signatureBytes = [UInt8](repeating: 0, count: signature.count)
            signature.copyBytes(to: &signatureBytes, count: signature.count)
            
            let status = SecKeyRawVerify(publicKey.underlying, .PKCS1, &shaBytes, shaBytes.count, &signatureBytes, signatureBytes.count)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not verify signature.", osStatus: status)
            }
            return true
        }
        
        @available(iOS 10.3, *)
        func encrypt(_ digest: Data, publicKey: PublicKey) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateEncryptedData(publicKey.underlying, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, digest as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not encrypt.")
            }
            return data as Data
        }
        
        @available(iOS 10.3, *)
        func decrypt(_ digest: Data, privateKey: PrivateKey) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateDecryptedData(privateKey.underlying, SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM, digest as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not decrypt.")
            }
            return data as Data
        }
        
        static func logToConsoleIfExecutingOnMainThread() {
            if Thread.isMainThread {
                let _ = LogOnce.shouldNotBeMainThread
            }
        }
    }
    
    private struct LogOnce {
        static var shouldNotBeMainThread: Void = {
            print("[WARNING] \(EllipticCurveKeyPair.self): Decryption and signing should be done off main thread because LocalAuthentication may need the thread to show UI. This message is logged only once.")
        }()
    }
    
    private struct Query {
        
        static func getKey(_ query: [String: Any]) throws -> SecKey {
            var raw: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &raw)
            guard status == errSecSuccess, let result = raw else {
                throw Error.osStatus(message: "Could not get key for query: \(query)", osStatus: status)
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
                throw Error.osStatus(message: "Could not delete private key.", osStatus: status)
            }
        }
        
        static func deletePrivateKey(labeled: String) throws {
            let query = privateKeyQuery(labeled: labeled) as CFDictionary
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete private key.", osStatus: status)
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
                throw Error.osStatus(message: "Could not save public key", osStatus: status)
            }
        }
    }
    
    public struct Constants {
        static var x9_62Header: Data = Data(bytes: [UInt8]([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]))
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
        
        /*
        
        OID = 06 09 2A 86 48 CE 3D 03 01 01 07
        Comment = ANSI X9.62 named elliptic curve
        Description = prime256v1 (1 2 840 10045 3 1 1 7)
        Link = http://oid-info.com/get/1.2.840.10045.3.1.1.7
        
        OID = 06 08 2A 86 48 CE 3D 03 01 07 <---- currently in use
        Comment = ANSI X9.62 named elliptic curve
        Description = ansiX9p256r1 (1 2 840 10045 3 1 7)
        Link = http://oid-info.com/get/1.2.840.10045.3.1.7
        
        OID = 06 08 2A 86 48 CE 3D 04 03 02
        Comment = ANSI X9.62 ECDSA algorithm with SHA256
        Description = ecdsaWithSHA256 (1 2 840 10045 4 3 2)
        Link = http://oid-info.com/get/1.2.840.10045.4.3.2
        
         */
        
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
        lazy var DER: Data = {
            var result = Constants.x9_62Header
            result.append(self.raw)
            return result
        }()
        
        lazy var PEM: String = {
            var lines = String()
            lines.append("-----BEGIN PUBLIC KEY-----\n")
            lines.append(self.DER.base64EncodedString(options: .lineLength64Characters))
            lines.append("\n-----END PUBLIC KEY-----")
            return lines
        }()
        
        fileprivate init(_ raw: Data) {
            self.raw = raw
        }
    }
    
    public class Key {
        
        let underlying: SecKey
        
        fileprivate init(_ underlying: SecKey) {
            self.underlying = underlying
        }
        
        private var cachedAttributes: [String:Any]? = nil
        
        func attributes() throws -> [String:Any] {
            if let attributes = cachedAttributes {
                return attributes
            } else {
                let attributes = try queryAttributes()
                cachedAttributes = attributes
                return attributes
            }
        }
        
        private func queryAttributes() throws -> [String:Any] {
            var matchResult: AnyObject? = nil
            let query: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: underlying,
                kSecReturnAttributes as String: true
            ]
            
            let status = SecItemCopyMatching(query as CFDictionary, &matchResult)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not read attributes for key", osStatus: status)
            }
            guard let attributes = matchResult as? [String:Any] else {
                throw Error.inconcistency(message: "Tried reading key attributes something went wrong. Expected dictionary, but received \(String(describing: matchResult)).")
            }
            return attributes
        }
    }
    
    public final class PublicKey: Key {
        
        private var cachedData: PublicKeyData? = nil
        
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
                throw Error.osStatus(message: "Could not generate keypair", osStatus: status)
            }
            guard let keyRaw = matchResult as? Data else {
                throw Error.inconcistency(message: "Tried reading public key bytes, but something went wrong. Expected data, but received \(String(describing: matchResult)).")
            }
            guard keyRaw.first == Constants.noCompression else {
                throw Error.inconcistency(message: "Tried reading public key bytes, but its headers says it is compressed.")
            }
            return PublicKeyData(keyRaw)
        }
    }
    
    public final class PrivateKey: Key {
        
        func isStoredOnSecureEnclave() throws -> Bool {
            let attributes = try self.attributes()
            let attribute = attributes[kSecAttrTokenID as String] as? String
            return attribute == (kSecAttrTokenIDSecureEnclave as String)
        }
        
        func accessControl() throws -> SecAccessControl {
            let attributes = try self.attributes()
            guard let attribute = attributes[kSecAttrAccessControl as String] else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its access control.")
            }
            return attribute as! SecAccessControl
        }
        
        func label() throws -> String {
            let attributes = try self.attributes()
            guard let attribute = attributes[kSecAttrLabel as String] as? String else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its label.")
            }
            return attribute
        }
        
        func accessibleWithAuthenticationContext(_ context: LAContext?) throws -> PrivateKey {
            var query = Query.privateKeyQuery(labeled: try label())
            query[kSecUseAuthenticationContext as String] = context
            let underlying = try Query.getKey(query)
            return PrivateKey(underlying)
        }
        
    }
    
    public enum Error: LocalizedError {
        
        case underlying(message: String, error: NSError)
        case inconcistency(message: String)
        case authentication(error: LAError)
        
        public var errorDescription: String? {
            switch self {
            case let .underlying(message: message, error: error):
                return "\(message). \(error.localizedDescription)"
            case let .authentication(error: error):
                return "Authentication failed. \(error.localizedDescription)"
            case let .inconcistency(message: message):
                return "Inconcistency in setup, configuration or keychain. \(message)"
            }
        }
        
        internal static func osStatus(message: String, osStatus: OSStatus) -> Error {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(osStatus), userInfo: [
                NSLocalizedDescriptionKey: message,
                NSLocalizedRecoverySuggestionErrorKey: "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(osStatus)"
                ])
            return .underlying(message: message, error: error)
        }
        
        internal static func fromError(_ error: CFError?, message: String) -> Error {
            let any = error as Any
            if let authenticationError = any as? LAError {
                return .authentication(error: authenticationError)
            }
            if let error = error,
                let domain = CFErrorGetDomain(error) as String? {
                let code = Int(CFErrorGetCode(error))
                var userInfo = (CFErrorCopyUserInfo(error) as? [String:Any]) ?? [String:Any]()
                if userInfo[NSLocalizedRecoverySuggestionErrorKey] == nil {
                    userInfo[NSLocalizedRecoverySuggestionErrorKey] = "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(osStatus)"
                }
                let underlying = NSError(domain: domain, code: code, userInfo: userInfo)
                return .underlying(message: message, error: underlying)
            }
            return .inconcistency(message: "\(message) Unknown error occured.")
        }
        
    }
}

extension DispatchQueue {
    
    static func roundTrip<T, Y>(_ block: () throws -> T,
                                thenAsync: @escaping (T) throws -> Y,
                                thenOnMain: @escaping (Y) throws -> Void,
                                catchToMain: @escaping (Error) -> Void) {
        do {
            let resultFromMain = try block()
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let resultFromBackground = try thenAsync(resultFromMain)
                    DispatchQueue.main.async {
                        do {
                            try thenOnMain(resultFromBackground)
                        } catch {
                            catchToMain(error)
                        }
                    }
                } catch {
                    DispatchQueue.main.async {
                        catchToMain(error)
                    }
                }
            }
        } catch {
            catchToMain(error)
        }
    }
}

extension SecAccessControl {
    @available(iOSApplicationExtension 9.0, *)
    static func create(protection: CFString, flags: SecAccessControlCreateFlags) throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        let result = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection, flags, &error)
        guard let accessControl = result else {
            throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried creating access control object with flags \(flags) and protection \(protection)")
        }
        return accessControl
    }
}
