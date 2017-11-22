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

@available(OSX 10.12.1, iOS 9.0, *)
public enum EllipticCurveKeyPair {
    
    public typealias Logger = (String) -> ()
    public static var logger: Logger?
        
    public struct Config {
        
        // The label used to identify the public key in keychain
        public var publicLabel: String
        
        // The label used to identify the private key on the secure enclave
        public var privateLabel: String
        
        // The text presented to the user about why we need his/her fingerprint / device pin
        public var operationPrompt: String?
        
        // The access control used to manage the access to the public key
        public var publicKeyAccessControl: AccessControl
        
        // The access control used to manage the access to the private key
        public var privateKeyAccessControl: AccessControl
        
        // The access group e.g. "BBDV3R8HVV.no.agens.demo"
        // Useful for shared keychain items
        public var publicKeyAccessGroup: String?
        
        // The access group e.g. "BBDV3R8HVV.no.agens.demo"
        // Useful for shared keychain items
        public var privateKeyAccessGroup: String?
        
        // Should it be stored on .secureEnclave or in .keychain ?
        public var token: Token
        
        public init(publicLabel: String,
                    privateLabel: String,
                    operationPrompt: String?,
                    publicKeyAccessControl: AccessControl,
                    privateKeyAccessControl: AccessControl,
                    publicKeyAccessGroup: String? = nil,
                    privateKeyAccessGroup: String? = nil,
                    token: Token) {
            self.publicLabel = publicLabel
            self.privateLabel = privateLabel
            self.operationPrompt = operationPrompt
            self.publicKeyAccessControl = publicKeyAccessControl
            self.privateKeyAccessControl = privateKeyAccessControl
            self.publicKeyAccessGroup = publicKeyAccessGroup
            self.privateKeyAccessGroup = privateKeyAccessGroup
            self.token = token
        }
    }
    
    // A stateful and opiniated manager for using the secure enclave and keychain
    // If there's a problem fetching the key pair this manager will naively just recreate new keypair
    // If the device doesn't have a Secure Enclave it will store the private key in keychain just like the public key
    //
    // If the manager is "too smart" in that sense you may use this manager as an example
    // and create your own manager
    public final class Manager {
        
        public let config: Config
        private var cachedPublicKey: PublicKey? = nil
        private var cachedPrivateKey: PrivateKey? = nil
        private let helper: Helper
        
        public init(config: Config) {
            self.config = config
            self.helper = Helper(config: config)
        }
        
        public func deleteKeyPair() throws {
            cachedPublicKey = nil
            cachedPrivateKey = nil
            try helper.delete()
        }
        
        public func publicKey() throws -> PublicKey {
            if let key = cachedPublicKey {
                return key
            }
            do {
                let key = try helper.getPublicKey()
                cachedPublicKey = key
                return key
            } catch EllipticCurveKeyPair.Error.underlying(_, let underlying) where underlying.code == errSecItemNotFound {
                let keys = try helper.generateKeyPair()
                cachedPublicKey = keys.public
                cachedPrivateKey = keys.private
                return keys.public
            } catch {
                throw error
            }
        }
        
        public func privateKey() throws -> PrivateKey {
            if let key = cachedPrivateKey {
                return key
            }
            do {
                let key = try helper.getPrivateKey()
                cachedPrivateKey = key
                return key
            } catch EllipticCurveKeyPair.Error.underlying(_, let underlying) where underlying.code == errSecItemNotFound {
                let keys = try helper.generateKeyPair()
                cachedPublicKey = keys.public
                cachedPrivateKey = keys.private
                return keys.private
            } catch {
                throw error
            }
        }
        
        public func keys() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKey = try self.privateKey()
            let publicKey = try self.publicKey()
            return (public: publicKey, private: privateKey)
        }
        
        public func clearCache() {
            cachedPublicKey = nil
            cachedPrivateKey = nil
        }
        
        @available(iOS 10, *)
        public func sign(_ digest: Data, algorithm: Algorithm, authenticationContext: LAContext? = nil) throws -> Data {
            let privateKey = try getKeys().private.accessibleWithAuthenticationContext(authenticationContext)
            return try helper.sign(digest, privateKey: privateKey, algorithm: algorithm)
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func signUsingSha256(_ digest: Data, authenticationContext: LAContext? = nil) throws -> Data {
            #if os(iOS)
                return try helper.signUsingSha256(digest, privateKey: getKeys().private.accessibleWithAuthenticationContext(authenticationContext))
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10, *)
        public func verify(signature: Data, originalDigest: Data, algorithm: Algorithm) throws {
            try helper.verify(signature: signature, digest: originalDigest, publicKey: getKeys().public, algorithm: algorithm)
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func verifyUsingSha256(signature: Data, originalDigest: Data) throws  {
            #if os(iOS)
                try helper.verifyUsingSha256(signature: signature, digest: originalDigest, publicKey: getKeys().public)
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10.3, *) // API available at 10.0, but bugs made it unusable on versions lower than 10.3
        public func encrypt(_ digest: Data, algorithm: Algorithm = .sha256) throws -> Data {
            return try helper.encrypt(digest, publicKey: getKeys().public, algorithm: algorithm)
        }
        
        @available(iOS 10.3, *) // API available at 10.0, but bugs made it unusable on versions lower than 10.3
        public func decrypt(_ encrypted: Data, algorithm: Algorithm = .sha256, authenticationContext: LAContext? = nil) throws -> Data {
            return try helper.decrypt(encrypted, privateKey: getKeys().private.accessibleWithAuthenticationContext(authenticationContext), algorithm: algorithm)
        }
        
        public func getKeys() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            
            if let keys = cache {
                return keys
            }
            
            if let keyPair = try? helper.get() {
                cache = keyPair
                return keyPair
            }
            
            let keyPair = try helper.generateKeyPair()
            cache = keyPair
            return keyPair
        }
        
    }
    
    // Helper is a stateless class for querying the secure enclave and keychain
    // You may create a small stateful facade around this
    // `Manager` is an example of such an opiniated facade
    public struct Helper {
        
        // The user visible label in the device's key chain
        public let config: Config
        
        public func getPublicKey() throws -> PublicKey {
            return try Query.getPublicKey(labeled: config.publicLabel, accessGroup: config.publicKeyAccessGroup)
        }
        
        public func getPrivateKey() throws -> PrivateKey {
            return try Query.getPrivateKey(labeled: config.privateLabel, accessGroup: config.privateKeyAccessGroup)
        }
        
        public func getKeys() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKey = try getPrivateKey()
            let publicKey = try getPublicKey()
            return (public: publicKey, private: privateKey)
        }
        
        public func generateKeyPair() throws -> (`public`: PublicKey, `private`: PrivateKey) {
            guard config.privateLabel != config.publicLabel else{
                throw Error.inconcistency(message: "Public key and private key can not have same label")
            }
            let query = try Query.generateKeyPairQuery(config: config, token: config.token)
            var publicOptional, privateOptional: SecKey?
            logger?("SecKeyGeneratePair: \(query)")
            let status = SecKeyGeneratePair(query as CFDictionary, &publicOptional, &privateOptional)
            guard status == errSecSuccess else {
                if status == errSecAuthFailed {
                    throw Error.osStatus(message: "Could not generate keypair. Security probably doesn't like the access flags you provided. Specifically if this device doesn't have secure enclave and you pass `.privateKeyUsage`. it will produce this error.", osStatus: status)
                } else {
                    throw Error.osStatus(message: "Could not generate keypair.", osStatus: status)
                }
            }
            guard let publicSec = publicOptional, let privateSec = privateOptional else {
                throw Error.inconcistency(message: "Created private public key pair successfully, but weren't able to retreive it.")
            }
            let publicKey = PublicKey(publicSec)
            let privateKey = PrivateKey(privateSec)
            try Query.forceSavePublicKey(publicKey, label: config.publicLabel)
            return (public: publicKey, private: privateKey)
        }
        
        public func delete() throws {
            try Query.deletePublicKey(labeled: config.publicLabel, accessGroup: config.publicKeyAccessGroup)
            try Query.deletePrivateKey(labeled: config.privateLabel, accessGroup: config.privateKeyAccessGroup)
        }
        
        @available(iOS 10.0, *)
        public func sign(_ digest: Data, privateKey: PrivateKey, algorithm: Algorithm) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateSignature(privateKey.underlying, algorithm.signatureMessage, digest as CFData, &error)
            guard let signature = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not create signature.")
            }
            return signature as Data
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func signUsingSha256(_ digest: Data, privateKey: PrivateKey) throws -> Data {
            #if os(iOS)
                Helper.logToConsoleIfExecutingOnMainThread()
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
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10.0, *)
        public func verify(signature: Data, digest: Data, publicKey: PublicKey, algorithm: Algorithm) throws {
            var error : Unmanaged<CFError>?
            let valid = SecKeyVerifySignature(publicKey.underlying, algorithm.signatureMessage, digest as CFData, signature as CFData, &error)
            if let error = error?.takeRetainedValue() {
                throw Error.fromError(error, message: "Could not verify signature.")
            }
            guard valid == true else {
                throw Error.inconcistency(message: "Signature yielded no error, but still marks itself as unsuccessful")
            }
        }
        
        @available(OSX, unavailable)
        @available(iOS, deprecated: 10.0, message: "This method and extra complexity will be removed when 9.0 is obsolete.")
        public func verifyUsingSha256(signature: Data, digest: Data, publicKey: PublicKey) throws {
            #if os(iOS)
                let sha = digest.sha256()
                var shaBytes = [UInt8](repeating: 0, count: sha.count)
                sha.copyBytes(to: &shaBytes, count: sha.count)
                
                var signatureBytes = [UInt8](repeating: 0, count: signature.count)
                signature.copyBytes(to: &signatureBytes, count: signature.count)
                
                let status = SecKeyRawVerify(publicKey.underlying, .PKCS1, &shaBytes, shaBytes.count, &signatureBytes, signatureBytes.count)
                guard status == errSecSuccess else {
                    throw Error.osStatus(message: "Could not verify signature.", osStatus: status)
                }
            #else
                throw Error.inconcistency(message: "Should be unreachable.")
            #endif
        }
        
        @available(iOS 10.3, *)
        public func encrypt(_ digest: Data, publicKey: PublicKey, algorithm: Algorithm) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateEncryptedData(publicKey.underlying, algorithm.encryptionEciesEcdh, digest as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not encrypt.")
            }
            return data as Data
        }
        
        @available(iOS 10.3, *)
        public func decrypt(_ encrypted: Data, privateKey: PrivateKey, algorithm: Algorithm) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateDecryptedData(privateKey.underlying, algorithm.encryptionEciesEcdh, encrypted as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not decrypt.")
            }
            return data as Data
        }
        
        public static func logToConsoleIfExecutingOnMainThread() {
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
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &raw)
            guard status == errSecSuccess, let result = raw else {
                throw Error.osStatus(message: "Could not get key for query: \(query)", osStatus: status)
            }
            return result as! SecKey
        }
        
        static func publicKeyQuery(labeled: String, accessGroup: String?) -> [String:Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
            ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            return params
        }
        
        static func privateKeyQuery(labeled: String, accessGroup: String?) -> [String: Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
                ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            return params
        }
        
        static func generateKeyPairQuery(config: Config, token: Token) throws -> [String:Any] {
            
            // private
            var privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.privateLabel,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: try config.privateKeyAccessControl.underlying(),
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
                ]
            if let operationPrompt = config.operationPrompt {
                privateKeyParams[kSecUseOperationPrompt as String] = operationPrompt
            }
            if let privateKeyAccessGroup = config.privateKeyAccessGroup {
                privateKeyParams[kSecAttrAccessGroup as String] = privateKeyAccessGroup
            }
            
            // public
            var publicKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.publicLabel,
                kSecAttrAccessControl as String: try config.publicKeyAccessControl.underlying(),
                ]
            if let publicKeyAccessGroup = config.publicKeyAccessGroup {
                publicKeyParams[kSecAttrAccessGroup as String] = publicKeyAccessGroup
            }
            
            // combined
            var params: [String: Any] = [
                kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                kSecPrivateKeyAttrs as String: privateKeyParams,
                kSecPublicKeyAttrs as String: publicKeyParams,
                kSecAttrKeySizeInBits as String: 256,
                ]
            if token == .secureEnclave {
                params[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            }
            return params
        }
        
        static func getPublicKey(labeled: String, accessGroup: String?) throws -> PublicKey {
            let query = publicKeyQuery(labeled: labeled, accessGroup: accessGroup)
            return PublicKey(try getKey(query))
        }
        
        static func getPrivateKey(labeled: String, accessGroup: String?) throws -> PrivateKey {
            let query = privateKeyQuery(labeled: labeled, accessGroup: accessGroup)
            return PrivateKey(try getKey(query))
        }
        
        static func deletePublicKey(labeled: String, accessGroup: String?) throws {
            let query = publicKeyQuery(labeled: labeled, accessGroup: accessGroup) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete private key.", osStatus: status)
            }
        }
        
        static func deletePrivateKey(labeled: String, accessGroup: String?) throws {
            let query = privateKeyQuery(labeled: labeled, accessGroup: accessGroup) as CFDictionary
            logger?("SecItemDelete: \(query)")
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
            logger?("SecItemAdd: \(query)")
            var status = SecItemAdd(query as CFDictionary, &raw)
            if status == errSecDuplicateItem {
                logger?("SecItemDelete: \(query)")
                status = SecItemDelete(query as CFDictionary)
                logger?("SecItemAdd: \(query)")
                status = SecItemAdd(query as CFDictionary, &raw)
            }
            if status == errSecInvalidRecord {
                throw Error.osStatus(message: "Could not save public key. It is possible that the access control you have provided is not supported on this OS and/or hardware.", osStatus: status)
            } else if status != errSecSuccess {
                throw Error.osStatus(message: "Could not save public key", osStatus: status)
            }
        }
    }
    
    public struct Constants {        
        public static let noCompression: UInt8 = 4
        public static let attrKeyTypeEllipticCurve: String = {
            if #available(iOS 10.0, *) {
                return kSecAttrKeyTypeECSECPrimeRandom as String
            } else {
                return kSecAttrKeyTypeEC as String
            }
        }()
    }
    
    public final class PublicKeyData {
        
        // As received from Security framework
        public let raw: Data
        
        // The open ssl compatible DER format X.509
        //
        // We take the raw key and prepend an ASN.1 headers to it. The end result is an
        // ASN.1 SubjectPublicKeyInfo structure, which is what OpenSSL is looking for.
        //
        // See the following DevForums post for more details on this.
        // https://forums.developer.apple.com/message/84684#84684
        //
        // End result looks like this
        // https://lapo.it/asn1js/#3059301306072A8648CE3D020106082A8648CE3D030107034200041F4E3F6CD8163BCC14505EBEEC9C30971098A7FA9BFD52237A3BCBBC48009162AAAFCFC871AC4579C0A180D5F207316F74088BF01A31F83E9EBDC029A533525B
        //
        public lazy var DER: Data = {
            var x9_62HeaderECHeader = [UInt8]([
                /* sequence          */ 0x30, 0x59,
                /* |-> sequence      */ 0x30, 0x13,
                /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
                /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
                /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
                ])
            var result = Data()
            result.append(Data(x9_62HeaderECHeader))
            result.append(self.raw)
            return result
        }()
        
        public lazy var PEM: String = {
            var lines = String()
            lines.append("-----BEGIN PUBLIC KEY-----\n")
            lines.append(self.DER.base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn]))
            lines.append("\n-----END PUBLIC KEY-----")
            return lines
        }()
        
        internal init(_ raw: Data) {
            self.raw = raw
        }
    }
    
    public class Key {
        
        public let underlying: SecKey
        
        internal init(_ underlying: SecKey) {
            self.underlying = underlying
        }
        
        private var cachedAttributes: [String:Any]? = nil
        
        public func attributes() throws -> [String:Any] {
            if let attributes = cachedAttributes {
                return attributes
            } else {
                let attributes = try queryAttributes()
                cachedAttributes = attributes
                return attributes
            }
        }
        
        public func label() throws -> String {
            guard let attribute = try self.attributes()[kSecAttrLabel as String] as? String else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its label.")
            }
            return attribute
        }
        
        public func accessGroup() throws -> String? {
            return try self.attributes()[kSecAttrAccessGroup as String] as? String
        }
        
        public func accessControl() throws -> SecAccessControl {
            guard let attribute = try self.attributes()[kSecAttrAccessControl as String] else {
                throw Error.inconcistency(message: "We've got a private key, but we are missing its access control.")
            }
            return attribute as! SecAccessControl
        }
        
        private func queryAttributes() throws -> [String:Any] {
            var matchResult: AnyObject? = nil
            let query: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: underlying,
                kSecReturnAttributes as String: true
            ]
            logger?("SecItemCopyMatching: \(query)")
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
        
        public func data() throws -> PublicKeyData {
            if let data = cachedData {
                return data
            } else {
                let data = try queryData()
                cachedData = data
                return data
            }
        }
        
        private func queryData() throws -> PublicKeyData {
            let keyRaw: Data
            if #available(iOS 10.0, *) {
                keyRaw = try export()
            } else {
                keyRaw = try exportWithOldApi()
            }
            guard keyRaw.first == Constants.noCompression else {
                throw Error.inconcistency(message: "Tried reading public key bytes, but its headers says it is compressed and this library only handles uncompressed keys.")
            }
            return PublicKeyData(keyRaw)
        }
        
        @available(iOS 10.0, *)
        private func export() throws -> Data {
            var error : Unmanaged<CFError>?
            guard let raw = SecKeyCopyExternalRepresentation(underlying, &error) else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried reading public key bytes.")
            }
            return raw as Data
        }
        
        private func exportWithOldApi() throws -> Data {
            var matchResult: AnyObject? = nil
            let query: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecValueRef as String: underlying,
                kSecReturnData as String: true
            ]
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &matchResult)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not generate keypair", osStatus: status)
            }
            guard let keyRaw = matchResult as? Data else {
                throw Error.inconcistency(message: "Tried reading public key bytes. Expected data, but received \(String(describing: matchResult)).")
            }
            return keyRaw
        }
    }
    
    public final class PrivateKey: Key {
        
        public private(set) var context: LAContext?
        
        public func isStoredOnSecureEnclave() throws -> Bool {
            let attribute = try self.attributes()[kSecAttrTokenID as String] as? String
            return attribute == (kSecAttrTokenIDSecureEnclave as String)
        }
        
        public func accessibleWithAuthenticationContext(_ context: LAContext?) throws -> PrivateKey {
            if self.context === context {
                return self
            }
            var query = Query.privateKeyQuery(labeled: try label(), accessGroup: try accessGroup())
            query[kSecUseAuthenticationContext as String] = context
            let underlying = try Query.getKey(query)
            let keyWithContext = PrivateKey(underlying)
            keyWithContext.context = context
            return keyWithContext
        }
    }
    
    public final class AccessControl {
        
        // E.g. kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        public let protection: CFTypeRef
        
        // E.g. [.userPresence, .privateKeyUsage]
        public let flags: SecAccessControlCreateFlags
        
        public init(protection: CFTypeRef, flags: SecAccessControlCreateFlags) {
            self.protection = protection
            self.flags = flags
        }
        
        public func underlying() throws -> SecAccessControl {
            var error: Unmanaged<CFError>?
            let result = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection, flags, &error)
            guard let accessControl = result else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried creating access control object with flags \(flags) and protection \(protection)")
            }
            return accessControl
        }
    }
    
    public enum Error: LocalizedError {
        
        case underlying(message: String, error: NSError)
        case inconcistency(message: String)
        case authentication(error: LAError)
        
        public var errorDescription: String? {
            switch self {
            case let .underlying(message: message, error: error):
                return "\(message) \(error.localizedDescription)"
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
                    userInfo[NSLocalizedRecoverySuggestionErrorKey] = "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(code)"
                }
                let underlying = NSError(domain: domain, code: code, userInfo: userInfo)
                return .underlying(message: message, error: underlying)
            }
            return .inconcistency(message: "\(message) Unknown error occured.")
        }
        
    }
    
    @available(iOS 10.0, *)
    public enum Algorithm: String {
        
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        @available(iOS 10.0, *)
        var signatureMessage: SecKeyAlgorithm {
            switch self {
            case .sha1:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1
            case .sha224:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
            case .sha256:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            case .sha384:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
            case .sha512:
                return SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
            }
        }
        
        @available(iOS 10.0, *)
        var encryptionEciesEcdh: SecKeyAlgorithm {
            switch self {
            case .sha1:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM
            case .sha224:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA224AESGCM
            case .sha256:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM
            case .sha384:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
            case .sha512:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA512AESGCM
            }
        }
    }
    
    public enum Token {
        case secureEnclave
        case keychain
        
        public static var secureEnclaveIfAvailable: Token {
            return Device.hasSecureEnclave ? .secureEnclave : .keychain
        }
    }
    
    public enum Device {
        
        public static var hasTouchID: Bool {
            if #available(OSX 10.12.2, *) {
                return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            } else {
                return false
            }
        }
        
        public static var isSimulator: Bool {
            return TARGET_OS_SIMULATOR != 0
        }
        
        public static var hasSecureEnclave: Bool {
            return hasTouchID && !isSimulator
        }
        
    }
}
