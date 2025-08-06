//
//  SecureEnclaveActor.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation
import Security
import LocalAuthentication
import CryptoKit

/// Actor providing thread-safe Secure Enclave operations
actor SecureEnclaveActor {
    
    /// Generates a new key pair in the Secure Enclave
    /// - Parameter tag: Unique identifier for the key
    /// - Returns: SecureKey containing public key information
    public func generateKey(tag: String) throws -> SecureKey {
        // Remove any existing key with the same tag
        try? deleteKey(tag: tag)
        
        // Create access control for the private key
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        ) else {
            throw SecureEnclaveError.accessControlCreationFailed
        }
        
        // Define key attributes
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        // Generate the key pair
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SecureEnclaveError.keyGenerationFailed(error?.takeRetainedValue())
        }
        
        // Get the public key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.publicKeyExtractionFailed
        }
        
        // Export public key data
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw SecureEnclaveError.publicKeyExportFailed(error?.takeRetainedValue())
        }
        
        return SecureKey(
            tag: tag,
            publicKey: publicKeyData as Data,
            algorithm: .ecdsaSignatureMessageX962SHA256
        )
    }
    
    /// Deletes a key from the Secure Enclave
    /// - Parameter tag: The tag of the key to delete
    public func deleteKey(tag: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw SecureEnclaveError.keyDeletionFailed(status)
        }
    }
    
    /// Checks if a key exists in the Secure Enclave
    /// - Parameter tag: The tag of the key to check
    /// - Returns: true if the key exists, false otherwise
    public func keyExists(tag: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: false
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Retrieves a private key from the Secure Enclave
    private func getPrivateKey(tag: String) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess,
              let privateKey = item as! SecKey? else {
            throw SecureEnclaveError.keyNotFound(tag)
        }
        
        return privateKey
    }
    
    /// Encrypts data using a Secure Enclave key
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - tag: Tag of the key to use
    /// - Returns: Encrypted data
    public func encrypt(_ data: Data, using tag: String) throws -> Data {
        let privateKey = try getPrivateKey(tag: tag)
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.publicKeyExtractionFailed
        }
        
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, .eciesEncryptionCofactorX963SHA256AESGCM) else {
            throw SecureEnclaveError.algorithmNotSupported
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionCofactorX963SHA256AESGCM,
            data as CFData,
            &error
        ) else {
            throw SecureEnclaveError.encryptionFailed(error?.takeRetainedValue())
        }
        
        return encryptedData as Data
    }
    
    /// Decrypts data using a Secure Enclave key
    /// - Parameters:
    ///   - data: Data to decrypt
    ///   - tag: Tag of the key to use
    /// - Returns: Decrypted data
    public func decrypt(_ data: Data, using tag: String) throws -> Data {
        let privateKey = try getPrivateKey(tag: tag)
        
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, .eciesEncryptionCofactorX963SHA256AESGCM) else {
            throw SecureEnclaveError.algorithmNotSupported
        }
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(
            privateKey,
            .eciesEncryptionCofactorX963SHA256AESGCM,
            data as CFData,
            &error
        ) else {
            throw SecureEnclaveError.decryptionFailed(error?.takeRetainedValue())
        }
        
        return decryptedData as Data
    }
    
    /// Signs data using a Secure Enclave key
    /// - Parameters:
    ///   - data: Data to sign
    ///   - tag: Tag of the key to use
    /// - Returns: Signature data
    public func sign(_ data: Data, using tag: String) throws -> Data {
        let privateKey = try getPrivateKey(tag: tag)
        
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, .ecdsaSignatureMessageX962SHA256) else {
            throw SecureEnclaveError.algorithmNotSupported
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) else {
            throw SecureEnclaveError.signingFailed(error?.takeRetainedValue())
        }
        
        return signature as Data
    }
    
    /// Verifies a signature using a Secure Enclave key
    /// - Parameters:
    ///   - signature: Signature to verify
    ///   - data: Original data that was signed
    ///   - tag: Tag of the key to use
    /// - Returns: true if signature is valid, false otherwise
    public func verify(_ signature: Data, for data: Data, using tag: String) throws -> Bool {
        let privateKey = try getPrivateKey(tag: tag)
        
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.publicKeyExtractionFailed
        }
        
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, .ecdsaSignatureMessageX962SHA256) else {
            throw SecureEnclaveError.algorithmNotSupported
        }
        
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            signature as CFData,
            &error
        )
        
        if let error = error {
            throw SecureEnclaveError.verificationFailed(error.takeRetainedValue())
        }
        
        return result
    }
    
    /// Checks if Secure Enclave is available on this device
    public func isAvailable() -> Bool {
        // Check if we can create a test key with Secure Enclave
        let testTag = "com.sentinel.test.secure-enclave-check"
        
        // Try to create access control with Secure Enclave
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        ) else {
            return false
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: testTag.data(using: .utf8)!,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        if let _ = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            // Successfully created a key, Secure Enclave is available
            // Note: Key is not permanent, so it's automatically cleaned up
            return true
        }
        
        return false
    }
}