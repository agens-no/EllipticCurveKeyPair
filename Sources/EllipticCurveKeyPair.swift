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

/*
 TODO: Add support for key exchange https://stackoverflow.com/questions/46301197/elliptic-curve-diffie-hellman-in-ios-swift?rq=1
 */

@available(OSX 10.12.1, iOS 10.0, *)
public enum EllipticCurveKeyPair {}

extension EllipticCurveKeyPair {
    
    public static var logger: ((String) -> ())?
    
    public enum KeyType {
        case secp256r1 // a.k.a. prime256v1 http://oid-info.com/get/1.2.840.10045.3.1.7
        
        var keySizeInBits: Int {
            switch self {
            case .secp256r1:
                return 256
            }
        }
        
        var x9_62PublicKeyHeader: Data {
            switch self {
            case .secp256r1:
                return Data([UInt8]([
                    /* sequence          */ 0x30, 0x59,
                    /* |-> sequence      */ 0x30, 0x13,
                    /* |---> PublicKey   */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
                    /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
                    /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
                    ]))
            }
        }
    }
    
    public final class PrivateKey {
        
        public let secKey: SecKey
        public let keyType: KeyType
    
        public init(_ secKey: SecKey, keyType: KeyType) {
            self.secKey = secKey
            self.keyType = keyType
        }
        
        // Create random permanent key
        public static func createRandom(label: String, accessGroup: String? = nil, keyType: KeyType, accessControl: AccessControl, token: Token) throws -> PrivateKey {
            var params: [CFString:Any] = [:]
            params[kSecAttrLabel] = label
            params[kSecAttrAccessGroup] = accessGroup
            params[kSecClass] = kSecClassKey
            params[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            params[kSecAttrKeySizeInBits] = keyType.keySizeInBits
            params[kSecAttrAccessControl] = try accessControl.createNative()
            params[kSecAttrIsPermanent] = true
            if token == .secureEnclave {
                params[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            }
            var error: Unmanaged<CFError>?
            guard let privateSec = SecKeyCreateRandomKey(params as CFDictionary, &error) else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not create private key.")
            }
            return PrivateKey(privateSec, keyType: keyType)
        }
        
        // Load key
        public static func load(label: String, keyType: KeyType, token: Token, accessGroup: String? = nil) throws -> PrivateKey {
            var params: [CFString:Any] = [:]
            params[kSecAttrLabel] = label
            params[kSecAttrAccessGroup] = accessGroup
            params[kSecClass] = kSecClassKey
            params[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
            params[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            params[kSecAttrKeySizeInBits] = keyType.keySizeInBits
            params[kSecReturnRef] = true
            if token == .secureEnclave {
                params[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            }
            var result: AnyObject? = nil
            let status = SecItemCopyMatching(params as CFDictionary, &result)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not load private key", osStatus: status)
            }
            guard let unwrapped = result else {
                throw Error.inconcistency(message: "Could not load private key for unknown reasons")
            }
            return PrivateKey(unwrapped as! SecKey, keyType: keyType)
        }
        
        // Imports existing key and saves it in Keychain
        public static func `import`(data: PublicKeyData, label: String, accessGroup: String? = nil, accessControl: AccessControl, token: Token) throws -> PrivateKey {
            fatalError()
        }
        
        // Create random temporary in-memory key which is not stored in Keychain
        public static func temporaryRandom(keyType: KeyType, accessControl: AccessControl, token: Token) throws -> PrivateKey {
            var params: [CFString:Any] = [:]
            params[kSecClass] = kSecClassKey
            params[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
            params[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            params[kSecAttrKeySizeInBits] = keyType.keySizeInBits
            params[kSecAttrIsPermanent] = false
            params[kSecAttrAccessControl] = try accessControl.createNative()
            if token == .secureEnclave {
                params[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            }
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(params as CFDictionary, &error) else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not create privat key.")
            }
            return PrivateKey(key, keyType: keyType)
        }
        
        // Create temporary in-memory key with custom data
        // Note: This is not supported by secure enclave, therefore there is no token parameter
        public static func temporary(data: PublicKeyData, accessControl: AccessControl) throws -> PrivateKey {
            var params: [CFString:Any] = [:]
            params[kSecReturnRef] = true
            params[kSecValueData] = data.raw
            params[kSecClass] = kSecClassKey
            params[kSecAttrIsPermanent] = false
            params[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
            params[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            
            var result: CFTypeRef? = nil
            var status = SecItemAdd(params as CFDictionary, &result)
            if status == errSecDuplicateItem {
                status = SecItemCopyMatching(params as CFDictionary, &result)
            }
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not load public key", osStatus: status)
            }
            guard let unwrapped = result else {
                throw Error.inconcistency(message: "Could not load public key for unknown reasons") //FIXME:
            }
            status = SecItemDelete(params as CFDictionary)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Failed to clean up temporary key", osStatus: status)
            }
            return PrivateKey(unwrapped as! SecKey, keyType: data.keyType)
        }
        
        // Use another context for the key
        public func context(_ context: LAContext?, localizedReason: String?) throws -> PrivateKey {
            var params: [CFString:Any] = [:]
            params[kSecValueRef] = secKey
            params[kSecReturnRef] = true
            var result: CFTypeRef? = nil
            let status = SecItemCopyMatching(params as CFDictionary, &result)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not load public key", osStatus: status)
            }
            guard let unwrapped = result else {
                throw Error.inconcistency(message: "Could not load public key for unknown reasons") //FIXME:
            }
            return PrivateKey(unwrapped as! SecKey, keyType: keyType)
        }
        
        public func sign(_ data: Data, _ algorithm: SecKeyAlgorithm) throws -> Signature {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            // FIXME: hash
            let result = SecKeyCreateSignature(self.secKey, algorithm, data as CFData, &error)
            guard let signature = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not create signature.")
            }
            return Signature(signature as Data)
        }
        
        public func decrypt(_ encryptedData: Data, _ algorithm: SecKeyAlgorithm) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateDecryptedData(secKey, algorithm, encryptedData as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not decrypt.")
            }
            return data as Data
        }
        
        // Derive public key from this private key
        public func publicKey() throws -> PublicKey {
            guard let underlying = SecKeyCopyPublicKey(secKey) else {
                throw Error.inconcistency(message: "Could not copy public key for unknown reasons")
            }
            return PublicKey(underlying, keyType: keyType)
        }
        
        public static func delete(label: String, keyType: KeyType, accessGroup: String? = nil) throws {
            var params: [CFString:Any] = [:]
            params[kSecAttrLabel] = label
            params[kSecAttrAccessGroup] = accessGroup
            params[kSecClass] = kSecClassKey
            params[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            let status = SecItemDelete(params as CFDictionary)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not delete private key", osStatus: status)
            }
        }
        
        // Export the key
        // Note: private keys stored in secure enclave is not possible to export.
        public func export() throws -> PrivateKeyData {
            var error : Unmanaged<CFError>?
            guard let raw = SecKeyCopyExternalRepresentation(secKey, &error) else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried reading private key bytes.")
            }
            return try PrivateKeyData(raw: raw as Data, keyType: keyType)
        }
    }
    
    public final class PublicKey {
        
        public let secKey: SecKey
        public let keyType: KeyType
        
        public init(_ secKey: SecKey, keyType: KeyType) {
            self.secKey = secKey
            self.keyType = keyType
        }
        
        // Load key
        public static func load(label: String, accessGroup: String? = nil) throws -> PublicKey {
            fatalError()
        }
        
        // Imports existing key and saves to Keychain
        public static func `import`(data: PublicKeyData, label: String, accessGroup: String? = nil, accessControl: AccessControl? = nil) throws -> PublicKey {
            fatalError()
        }
        
        // Imports existing key and saves to Keychain
        public static func temporary(data: PublicKeyData) throws -> PublicKey {
            
            var add: [CFString:Any] = [:]
            add[kSecReturnRef] = true
            add[kSecValueData] = data.raw
            add[kSecClass] = kSecClassKey
            add[kSecAttrIsPermanent] = false
            add[kSecAttrKeyClass] = kSecAttrKeyClassPublic
            add[kSecAttrKeyType] = kSecAttrKeyTypeECSECPrimeRandom
            
            var result: CFTypeRef? = nil
            var status = SecItemAdd(add as CFDictionary, &result)
            if status == errSecDuplicateItem {
                status = SecItemCopyMatching(add as CFDictionary, &result)
            }
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Could not load public key", osStatus: status)
            }
            guard let unwrapped = result else {
                throw Error.inconcistency(message: "Could not load public key for unknown reasons") //FIXME:
            }
            status = SecItemDelete(add as CFDictionary)
            guard status == errSecSuccess else {
                throw Error.osStatus(message: "Failed to clean up temporary key", osStatus: status)
            }
            return PublicKey(unwrapped as! SecKey, keyType: data.keyType)
        }
        
        // Set the desired LAContext context for the key
        func context(_ context: LAContext?, localizedReason: String?) -> PublicKey {
            fatalError()
        }
        
        // Derive public key from this private key
        public func publicKey() throws -> PublicKey {
            guard let underlying = SecKeyCopyPublicKey(secKey) else {
                throw Error.inconcistency(message: "Could not copy public key for unknown reasons")
            }
            return PublicKey(underlying, keyType: keyType)
        }
        
        // Verify a signature
        public func verify(signature: Signature, digest: Data, algorithm: SecKeyAlgorithm) throws {
            var error : Unmanaged<CFError>?
            // FIXME: hash
            let valid = SecKeyVerifySignature(secKey, algorithm, digest as CFData, signature.asn1Formatted as CFData, &error)
            if let error = error?.takeRetainedValue() {
                throw Error.fromError(error, message: "Could not verify signature.")
            }
            guard valid == true else {
                throw Error.inconcistency(message: "Signature yielded no error, but still marks itself as unsuccessful")
            }
        }
        
        // Encrypt a message
        public func encrypt(_ digest: Data, _ algorithm: SecKeyAlgorithm) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateEncryptedData(secKey, algorithm, digest as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not encrypt.")
            }
            return data as Data
        }
        
        // Export the key
        public func export() throws -> PublicKeyData {
            var error : Unmanaged<CFError>?
            guard let raw = SecKeyCopyExternalRepresentation(secKey, &error) else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried reading public key bytes.")
            }
            return try PublicKeyData(raw: raw as Data, keyType: keyType)
        }
    }
    
    public struct Signature {
        public var asn1Formatted: Data
        public var raw: Data
        
        static func smallestBigEndian(_ bytes: Data) -> Data {
            var smallest = bytes
            while smallest.first == 0x00 {
                smallest.removeFirst()
            }
            if let firstByte = smallest.first, firstByte > 0x7f {
                return Data(bytes: [0x00]) + smallest
            } else {
                return smallest
            }
        }
        
        public init(_ bytes: Data) {
            if let decoded = Signature.decodeAsn1(bytes) {
                asn1Formatted = bytes
                raw = decoded
            } else {
                asn1Formatted = Signature.encodeAsn1(bytes)
                raw = bytes
            }
        }
        
        // https://crypto.stackexchange.com/a/1797
        static func decodeAsn1(_ bytes: Data) -> Data? {
            var parser = bytes
            guard bytes.count > 2 else { return nil }
            guard parser.popFirst() == 0x30 else { return nil }
            guard let sequenceLength = parser.popFirst() else { return nil }
            guard parser.count == sequenceLength else { return nil }
            guard parser.popFirst() == 0x02 else { return nil }
            guard let rLength = parser.popFirst() else { return nil }
            guard rLength < parser.count else { return nil }
            let r = parser.prefix(Int(rLength))
            parser.removeFirst(Int(rLength))
            guard parser.count > 2 else { return nil }
            guard parser.popFirst() == 0x02 else { return nil }
            guard let sLength = parser.popFirst() else { return nil }
            guard sLength == parser.count else { return nil }
            let s = parser.prefix(Int(sLength))
            return r + s
        }
        
        // https://crypto.stackexchange.com/a/1797
        static func encodeAsn1(_ bytes: Data) -> Data {
            let r = smallestBigEndian(bytes.prefix(bytes.count / 2))
            let s = smallestBigEndian(bytes.suffix(bytes.count / 2))
            var asn1 = Data()
            asn1.append(0x30)
            asn1.append(UInt8(2 + r.count + 2 + s.count))
            asn1.append(0x02)
            asn1.append(UInt8(r.count))
            asn1.append(r)
            asn1.append(0x02)
            asn1.append(UInt8(s.count))
            asn1.append(s)
            return asn1
        }
    }
    
    
    

    
    internal enum AccessControlCoder {
        
        internal static func decode(data: Data) -> AccessControl? {
            guard let string = String(data: data, encoding: .utf8) else {
                return nil
            }
            let values = string.split(separator: ":")
            guard let first = values.first, let last = values.last, let options = CFOptionFlags(last) else {
                return nil
            }
            let protection = String(first)
            let flags = SecAccessControlCreateFlags.init(rawValue: options)
            return AccessControl(protection: protection as CFString, flags: flags)
        }
        
        internal static func encode(_ accessControl: AccessControl) -> Data {
            let string = String(accessControl.protection) + ":" + String(accessControl.flags.rawValue)
            return string.data(using: .utf8)!
        }
        
        public static func underlying(_ c: AccessControl) throws -> SecAccessControl {
            if c.flags.contains(.privateKeyUsage) {
                let flagsWithOnlyPrivateKeyUsage: SecAccessControlCreateFlags = [.privateKeyUsage]
                guard c.flags != flagsWithOnlyPrivateKeyUsage else {
                    throw EllipticCurveKeyPair.Error.inconcistency(message: "Couldn't create access control flag. Keychain chokes if you try to create access control with only [.privateKeyUsage] on devices older than iOS 11 and macOS 10.13.x")
                }
            }
            
            var error: Unmanaged<CFError>?
            let result = SecAccessControlCreateWithFlags(kCFAllocatorDefault, c.protection as CFString, c.flags, &error)
            guard let accessControl = result else {
                throw EllipticCurveKeyPair.Error.fromError(error?.takeRetainedValue(), message: "Tried creating access control object with flags \(c.flags) and protection \(c.protection)")
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
                NSLocalizedRecoverySuggestionErrorKey: "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(osStatus) "
                ])
            return .underlying(message: message, error: error)
        }
        
        internal static func probablyAuthenticationError(underlying: NSError) -> Error {
            return Error.authentication(error: .init(_nsError: NSError(domain: LAErrorDomain, code: LAError.authenticationFailed.rawValue, userInfo: [
                NSLocalizedFailureReasonErrorKey: "Found public key, but couldn't find or access private key. The errSecItemNotFound error is sometimes wrongfully reported when LAContext authentication fails",
                NSUnderlyingErrorKey: underlying
                ])))
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
                    userInfo[NSLocalizedRecoverySuggestionErrorKey] = "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(code) "
                }
                let underlying = NSError(domain: domain, code: code, userInfo: userInfo)
                return .underlying(message: message, error: underlying)
            }
            return .inconcistency(message: "\(message) Unknown error occured.")
        }
        
    }
    
    @available(iOS 10.0, *)
    public enum Hash: String {
        
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        @available(iOS 10.0, *)
        var ecdsaSignaturePrehashed: SecKeyAlgorithm {
            switch self {
            case .sha1:
                return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA1
            case .sha224:
                return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA224
            case .sha256:
                return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256
            case .sha384:
                return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384
            case .sha512:
                return SecKeyAlgorithm.ecdsaSignatureDigestX962SHA512
            }
        }
        
        @available(iOS 10.0, *)
        var ecdsaSignatureMessage: SecKeyAlgorithm {
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
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
            case .sha384:
                return SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM
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
        
        public static var hasBiometricAuthentication: Bool {
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
            return hasBiometricAuthentication && !isSimulator
        }
        
    }
    
    private enum Helper {
        
        private struct LogOnce {
            static var shouldNotBeMainThread: Void = {
                print("[WARNING] \(EllipticCurveKeyPair.self): Decryption and signing should be done off main thread because LocalAuthentication may need the thread to show UI. This message is logged only once.")
            }()
        }
        
        internal static func logToConsoleIfExecutingOnMainThread() {
            if Thread.isMainThread {
                let _ = LogOnce.shouldNotBeMainThread
            }
        }
    }
 
    public enum KeyTypeHelper {
        
        // Maps to kSecAttrKeySizeInBits
        static func numberOfBits(_ keyType: KeyType) -> Int {
            switch keyType {
            case .secp256r1:
                return 256
            }
        }
        
        static func x9_62PublicKeyHeader(_ keyType: KeyType) -> Data {
            switch keyType {
            case .secp256r1:
                return Data([UInt8]([
                    /* sequence          */ 0x30, 0x59,
                    /* |-> sequence      */ 0x30, 0x13,
                    /* |---> PublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
                    /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // http://oid-info.com/get/1.2.840.10045.3.1.7 (ANSI X9.62 named elliptic curve)
                    /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
                    ]))
            }
        }
    }
    
    
    public enum Key {
        case `public`
        case `private`
    }
    
    public enum HashType {
        case prehashed // FIXME
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
    }
    
    public struct AccessControl {
        
        // E.g. kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        public let protection: CFString
        
        // E.g. [.userPresence, .privateKeyUsage]
        public let flags: SecAccessControlCreateFlags
        
        public init(protection: CFString, flags: SecAccessControlCreateFlags) {
            self.protection = protection
            self.flags = flags
        }
        
        public func createNative() throws -> SecAccessControl {
            var error : Unmanaged<CFError>?
            guard let nativeAccessControl = SecAccessControlCreateWithFlags(nil, protection, flags, &error) else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Access control values not valid.")
            }
            return nativeAccessControl
        }
    }
    
    public struct PrivateKeyData {
        
        // The raw bits representing this key without any ASN.1 encoding
        public let raw: Data
        
        // E.g. .secp256r1
        public let keyType: KeyType
        
        public init(raw: Data, keyType: KeyType) throws {
            self.raw = raw
            self.keyType = keyType
        }
    }
    
    public struct PublicKeyData {
        
        enum Error: Swift.Error {
            case unknownOrBadFormat
        }
        
        // The raw bits representing this key without any ASN.1 encoding
        public let raw: Data
        
        // E.g. .secp256r1
        public let keyType: KeyType
        
        public init(raw: Data, keyType: KeyType) throws {
            self.raw = raw
            self.keyType = keyType
        }
        
        public init(PEM: String) throws {
            guard let armoringBegin = PEM.range(of: "-----BEGIN PUBLIC KEY-----"),
                let armoringEnd = PEM.range(of: "-----END PUBLIC KEY-----") else {
                    throw Error.unknownOrBadFormat
            }
            guard armoringBegin.upperBound < armoringEnd.lowerBound else {
                throw Error.unknownOrBadFormat
            }
            let contentsRange = armoringBegin.upperBound..<armoringEnd.lowerBound
            let contents = PEM[contentsRange]
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
            guard let DER = Data(base64Encoded: contents) else {
                throw Error.unknownOrBadFormat
            }
            try self.init(DER: DER)
        }
        
        public init(DER: Data) throws {
            if let headerRange = DER.range(of: KeyType.secp256r1.x9_62PublicKeyHeader) {
                let raw = DER.suffix(from: headerRange.upperBound)
                try self.init(raw: raw, keyType: .secp256r1)
            } else {
                throw Error.unknownOrBadFormat
            }
        }
        
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
        public func DER() -> Data {
            return KeyTypeHelper.x9_62PublicKeyHeader(keyType) + raw
        }
        
        public func PEM() -> String {
            var lines = String()
            lines.append("-----BEGIN PUBLIC KEY-----\n")
            lines.append(self.DER().base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn, .endLineWithLineFeed]))
            lines.append("\n-----END PUBLIC KEY-----")
            return lines
        }
    }
    
 
}



    /*
    public final class Keychain {
 
        public static func generateKeyPair(publicConfig: KeyConfig, privateConfig: KeyConfig, context: LAContext?) throws -> (`public`: PublicKey, `private`: PrivateKey) {
 
 
            guard publicConfig.label != privateConfig.label else{
                throw Error.inconcistency(message: "Public key and private key can not have same label")
            }
            let query = try Queries.generateKeyPairQuery(publicConfig: publicConfig, privateConfig: privateConfig, context: context)
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
                throw Error.inconcistency(message: "Created private public key pair successfully, but weren't able to retreive it. This should not happen.")
            }
            let publicKey = PublicKey(publicSec, context: context)
            let privateKey = PrivateKey(privateSec, context: context)
            return (public: publicKey, private: privateKey)
        }
 
        static func getKey(_ query: [String: Any]) throws -> SecKey {
            var raw: CFTypeRef?
            logger?("SecItemCopyMatching: \(query)")
            let status = SecItemCopyMatching(query as CFDictionary, &raw)
            guard status == errSecSuccess, let result = raw else {
                throw Error.osStatus(message: "Could not get key for query: \(query)", osStatus: status)
            }
            return result as! SecKey
        }
 
        static func getPublicKey(labeled: String, accessGroup: String?, prompt: String?, context: LAContext) throws -> PublicKey {
            let query = Queries.publicKey(labeled: labeled, accessGroup: accessGroup)
            return PublicKey(try getKey(query), context: nil)
        }
 
        static func getPrivateKey(labeled: String, accessGroup: String?, prompt: String?, context: LAContext? = nil) throws -> PrivateKey {
            let query = Queries.privateKey(labeled: labeled, accessGroup: accessGroup, prompt: prompt, context: context)
            return PrivateKey(try getKey(query), context: context)
        }
 
        static func deletePublicKey(labeled: String, accessGroup: String?) throws {
            let query = Queries.publicKey(labeled: labeled, accessGroup: accessGroup) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete public key.", osStatus: status)
            }
        }
 
        static func deletePrivateKey(labeled: String, accessGroup: String?) throws {
            let query = Queries.privateKey(labeled: labeled, accessGroup: accessGroup, prompt: nil, context: nil) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete private key.", osStatus: status)
            }
        }
    }
 
    public struct Config {
 
        // The label used to identify the public key in keychain
        public var publicLabel: String
 
        // The label used to identify the private key on the secure enclave
        public var privateLabel: String
 
        // The text presented to the user about why we need his/her fingerprint / device pin
        // If you are passing an LAContext to sign or decrypt this value will be rejected
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
    // If the private or public key is not found this manager will naively just recreate a new keypair
    // If the device doesn't have a Secure Enclave it will store the private key in keychain just like the public key
    //
    // If you think this manager is "too smart" in that sense you may use this manager as an example
    // and create your own manager
    public final class Manager {
 
        private let config: Config
        private let helper: Helper
        private var cachedPublicKey: PublicKey? = nil
        private var cachedPrivateKey: PrivateKey? = nil
 
        public init(config: Config) {
            self.config = config
            self.helper = Helper(config: config)
        }
 
        public func deleteKeyPair() throws {
            clearCache()
            try helper.delete()
        }
 
        public func publicKey() throws -> PublicKey {
            do {
                if let key = cachedPublicKey {
                    return key
                }
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
 
        public func privateKey(context: LAContext? = nil) throws -> PrivateKey {
            do {
                if cachedPrivateKey?.context !== context {
                    cachedPrivateKey = nil
                }
                if let key = cachedPrivateKey {
                    return key
                }
                let key = try helper.getPrivateKey(context: context)
                cachedPrivateKey = key
                return key
            } catch EllipticCurveKeyPair.Error.underlying(_, let underlying) where underlying.code == errSecItemNotFound {
                if config.publicKeyAccessControl.flags.contains(.privateKeyUsage) == false, (try? helper.getPublicKey()) != nil {
                    throw Error.probablyAuthenticationError(underlying: underlying)
                }
                let keys = try helper.generateKeyPair(context: nil)
                cachedPublicKey = keys.public
                cachedPrivateKey = keys.private
                return keys.private
            } catch {
                throw error
            }
        }
 
        public func keys(context: LAContext? = nil) throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKey = try self.privateKey(context: context)
            let publicKey = try self.publicKey()
            return (public: publicKey, private: privateKey)
        }
 
        public func clearCache() {
            cachedPublicKey = nil
            cachedPrivateKey = nil
        }
 
        public func sign(_ digest: Data, hash: Hash, context: LAContext? = nil) throws -> Data {
            return try helper.sign(digest, privateKey: privateKey(context: context), hash: hash)
        }
 
        public func verify(signature: Data, originalDigest: Data, hash: Hash) throws {
            try helper.verify(signature: signature, digest: originalDigest, publicKey: publicKey(), hash: hash)
        }
 
        // Be aware that even if Apple made these API's public
        // some users reports that this is unusable on versions lower than 10.3 due to bugs
        public func encrypt(_ digest: Data, hash: Hash = .sha256) throws -> Data {
            return try helper.encrypt(digest, publicKey: publicKey(), hash: hash)
        }
 
        // Be aware that even if Apple made these API's public
        // some users reports that this is unusable on versions lower than 10.3 due to bugs
        public func decrypt(_ encrypted: Data, hash: Hash = .sha256, context: LAContext? = nil) throws -> Data {
            return try helper.decrypt(encrypted, privateKey: privateKey(context: context), hash: hash)
        }
 
    }
 
    // Helper is a stateless class for querying the secure enclave and keychain
    // You may create a small stateful facade around this
    // `Manager` is an example of such an opiniated facade
    public struct Helper {
 
        // The user visible label in the device's key chain
        public let config: Config
 
        public init() {}
 
        public func getPublicKey() throws -> PublicKey {
            return try Query.getPublicKey(labeled: config.publicLabel, accessGroup: config.publicKeyAccessGroup)
        }
 
        public func getPrivateKey(context: LAContext? = nil) throws -> PrivateKey {
            let context = context ?? LAContext()
            return try Query.getPrivateKey(labeled: config.privateLabel, accessGroup: config.privateKeyAccessGroup, prompt: config.operationPrompt, context: context)
        }
 
        public func getKeys(context: LAContext? = nil) throws -> (`public`: PublicKey, `private`: PrivateKey) {
            let privateKey = try getPrivateKey(context: context)
            let publicKey = try getPublicKey()
            return (public: publicKey, private: privateKey)
        }
 
        public func generateKeyPair(context: LAContext? = nil) throws -> (`public`: PublicKey, `private`: PrivateKey) {
            guard config.privateLabel != config.publicLabel else{
                throw Error.inconcistency(message: "Public key and private key can not have same label")
            }
            let context = context ?? LAContext()
            let query = try Query.generateKeyPairQuery(config: config, token: config.token, context: context)
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
            let privateKey = PrivateKey(privateSec, context: context)
            try Query.forceSavePublicKey(publicKey, label: config.publicLabel)
            return (public: publicKey, private: privateKey)
        }
 
        public func delete() throws {
            try Query.deletePublicKey(labeled: config.publicLabel, accessGroup: config.publicKeyAccessGroup)
            try Query.deletePrivateKey(labeled: config.privateLabel, accessGroup: config.privateKeyAccessGroup)
        }
 
        public func sign(_ digest: Data, privateKey: PrivateKey, hash: Hash) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateSignature(privateKey.underlying, hash.signatureMessage, digest as CFData, &error)
            guard let signature = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not create signature.")
            }
            return signature as Data
        }
 
        public func verify(signature: Data, digest: Data, publicKey: PublicKey, hash: Hash) throws {
            var error : Unmanaged<CFError>?
            let valid = SecKeyVerifySignature(publicKey.underlying, hash.signatureMessage, digest as CFData, signature as CFData, &error)
            if let error = error?.takeRetainedValue() {
                throw Error.fromError(error, message: "Could not verify signature.")
            }
            guard valid == true else {
                throw Error.inconcistency(message: "Signature yielded no error, but still marks itself as unsuccessful")
            }
        }
 
        public func encrypt(_ digest: Data, publicKey: PublicKey, hash: Hash) throws -> Data {
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateEncryptedData(publicKey.underlying, hash.encryptionEciesEcdh, digest as CFData, &error)
            guard let data = result else {
                throw Error.fromError(error?.takeRetainedValue(), message: "Could not encrypt.")
            }
            return data as Data
        }
 
        public func decrypt(_ encrypted: Data, privateKey: PrivateKey, hash: Hash) throws -> Data {
            Helper.logToConsoleIfExecutingOnMainThread()
            var error : Unmanaged<CFError>?
            let result = SecKeyCreateDecryptedData(privateKey.underlying, hash.encryptionEciesEcdh, encrypted as CFData, &error)
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
 
    private struct Queries {
 
        static func publicKey(labeled: String, accessGroup: String?) -> [String:Any] {
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
 
        static func privateKey(labeled: String, accessGroup: String?, prompt: String?, context: LAContext?) -> [String: Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
                ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            if let prompt = prompt {
                params[kSecUseOperationPrompt as String] = prompt
            }
            if let context = context {
                params[kSecUseAuthenticationContext as String] = context
            }
            return params
        }
 
        static func generateKeyPairQuery(publicConfig: KeyConfig, privateConfig: KeyConfig, context: LAContext?) throws -> [String:Any] {
 
            /* ========= private ========= */
            var privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: privateConfig.label,
                kSecAttrIsPermanent as String: true,
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
                ]
            if let privateKeyAccessGroup = privateConfig.accessGroup {
                privateKeyParams[kSecAttrAccessGroup as String] = privateKeyAccessGroup
            }
            if let context = context {
                privateKeyParams[kSecUseAuthenticationContext as String] = context
            }
 
            // On iOS 11 and lower: access control with empty flags doesn't work
            if !privateConfig.accessControl.flags.isEmpty {
                privateKeyParams[kSecAttrAccessControl as String] = try AccessControlCoder.underlying(privateConfig.accessControl)
            } else {
                privateKeyParams[kSecAttrAccessible as String] = privateConfig.accessControl.protection
            }
 
            if privateConfig.token == .secureEnclave {
                privateKeyParams[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
            }
 
            /* ========= public ========= */
            var publicKeyParams: [String: Any] = [
                kSecAttrLabel as String: publicConfig.label,
                ]
            if let publicKeyAccessGroup = publicConfig.accessGroup {
                publicKeyParams[kSecAttrAccessGroup as String] = publicKeyAccessGroup
            }
 
            // On iOS 11 and lower: access control with empty flags doesn't work
            if !publicConfig.accessControl.flags.isEmpty {
                publicKeyParams[kSecAttrAccessControl as String] = try AccessControlCoder.underlying(publicConfig.accessControl)
            } else {
                publicKeyParams[kSecAttrAccessible as String] = publicConfig.accessControl.protection
            }
 
            if publicConfig.token == .secureEnclave {
                throw Error.inconcistency(message: "Public key can not have .secureEnclave as token")
            }
 
            if publicConfig.type != privateConfig.type {
                throw Error.inconcistency(message: "When generating a key pair the keys must be of same type")
            }
 
            /* ========= combined ========= */
            let params: [String: Any] = [
                kSecAttrKeyType as String: Constants.attrKeyTypeEllipticCurve,
                kSecPrivateKeyAttrs as String: privateKeyParams,
                kSecPublicKeyAttrs as String: publicKeyParams,
                kSecAttrKeySizeInBits as String: KeyTypeHelper.numberOfBits(privateConfig.type),
                ]
            return params
        }
 
        internal static func logToConsoleIfExecutingOnMainThread() {
            if Thread.isMainThread {
                let _ = LogOnce.shouldNotBeMainThread
            }
        }
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
 
        static func privateKeyQuery(labeled: String, accessGroup: String?, prompt: String?, context: LAContext?) -> [String: Any] {
            var params: [String:Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: labeled,
                kSecReturnRef as String: true,
                ]
            if let accessGroup = accessGroup {
                params[kSecAttrAccessGroup as String] = accessGroup
            }
            if let prompt = prompt {
                params[kSecUseOperationPrompt as String] = prompt
            }
            if let context = context {
                params[kSecUseAuthenticationContext as String] = context
            }
            return params
        }
 
        static func generateKeyPairQuery(config: Config, token: Token, context: LAContext? = nil) throws -> [String:Any] {
 
            /* ========= private ========= */
            var privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.privateLabel,
                kSecAttrIsPermanent as String: true,
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
                ]
            if let privateKeyAccessGroup = config.privateKeyAccessGroup {
                privateKeyParams[kSecAttrAccessGroup as String] = privateKeyAccessGroup
            }
            if let context = context {
                privateKeyParams[kSecUseAuthenticationContext as String] = context
            }
 
            // On iOS 11 and lower: access control with empty flags doesn't work
            if !config.privateKeyAccessControl.flags.isEmpty {
                privateKeyParams[kSecAttrAccessControl as String] = try config.privateKeyAccessControl.underlying()
            } else {
                privateKeyParams[kSecAttrAccessible as String] = config.privateKeyAccessControl.protection
            }
 
            /* ========= public ========= */
            var publicKeyParams: [String: Any] = [
                kSecAttrLabel as String: config.publicLabel,
                ]
            if let publicKeyAccessGroup = config.publicKeyAccessGroup {
                publicKeyParams[kSecAttrAccessGroup as String] = publicKeyAccessGroup
            }
 
            // On iOS 11 and lower: access control with empty flags doesn't work
            if !config.publicKeyAccessControl.flags.isEmpty {
                publicKeyParams[kSecAttrAccessControl as String] = try config.publicKeyAccessControl.underlying()
            } else {
                publicKeyParams[kSecAttrAccessible as String] = config.publicKeyAccessControl.protection
            }
 
            /* ========= combined ========= */
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
 
        static func getPrivateKey(labeled: String, accessGroup: String?, prompt: String?, context: LAContext? = nil) throws -> PrivateKey {
            let query = privateKeyQuery(labeled: labeled, accessGroup: accessGroup, prompt: prompt, context: context)
            return PrivateKey(try getKey(query), context: context)
        }
 
        static func deletePublicKey(labeled: String, accessGroup: String?) throws {
            let query = publicKeyQuery(labeled: labeled, accessGroup: accessGroup) as CFDictionary
            logger?("SecItemDelete: \(query)")
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Error.osStatus(message: "Could not delete public key.", osStatus: status)
            }
        }
 
        static func deletePrivateKey(labeled: String, accessGroup: String?) throws {
            let query = privateKeyQuery(labeled: labeled, accessGroup: accessGroup, prompt: nil, context: nil) as CFDictionary
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
                /* |---> PublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // http://oid-info.com/get/1.2.840.10045.2.1 (ANSI X9.62 public key type)
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
            let noCompression: UInt8 = 0x04
            let keyRaw: Data
            if #available(iOS 10.0, *) {
                keyRaw = try export()
            } else {
                keyRaw = try exportWithOldApi()
            }
            guard keyRaw.first == noCompression else {
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
 
        internal init(_ underlying: SecKey, context: LAContext?) {
            super.init(underlying)
            self.context = context
        }
 
        public func isStoredOnSecureEnclave() throws -> Bool {
            let attribute = try self.attributes()[kSecAttrTokenID as String] as? String
            return attribute == (kSecAttrTokenIDSecureEnclave as String)
        }
    }
 

 
    public struct KeyConfig {
 
        // The label used to identify the key in keychain
        public var label: String
 
        // If the key requires user to authenticate this string is presented
        // the user when prompting for TouchID or device pass code (not FaceID)
        public var operationPrompt: String? = nil
 
        // The access control used to manage the access to the key
        public var accessControl: AccessControl
 
        // The access group e.g. "BBDV3R8HVV.no.agens.demo"
        // Useful for shared keychain items
        public var accessGroup: String? = nil
 
        // SecureEnclave only supports .secp256r1
        public var type: KeyType = .secp256r1
 
        // Should it be stored on .secureEnclave or in .keychain ?
        // Note: Public keys can not be stored on .secureEnclave
        public var token: Token
 
    }
 

 
        public enum Query {
            case create(label: String, accessGroup: String?, accessControl: SecAccessControl, keySizeInBits: Int, token: Token)
        }
 
        public struct Queries {
            // TODO: Remove
            public func create(label: String, accessGroup: String?, accessControl: SecAccessControl, keySizeInBits: Int, token: Token) -> [CFString:Any] {
                var params: [CFString:Any] = [:]
                params[kSecAttrLabel] = label
                params[kSecAttrAccessGroup] = accessGroup
                params[kSecAttrAccessControl] = accessControl
                params[kSecClass] = kSecClassKey
                params[kSecAttrKeyType] = Constants.attrKeyTypeEllipticCurve
                params[kSecAttrKeySizeInBits] = keySizeInBits
                params[kSecAttrIsPermanent] = true
                params[kSecUseAuthenticationUI] = true
                if token == .secureEnclave {
                    params[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
                }
                return params
            }
        }
 
    */




