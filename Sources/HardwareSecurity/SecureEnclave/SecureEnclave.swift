//
//  SecureEnclave.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Dependencies
import DependenciesMacros
import Foundation
import Security
import LocalAuthentication
import CryptoKit

/**
 A dependency client for Secure Enclave operations.
 
 Provides hardware-backed cryptographic operations including key generation,
 encryption, decryption, and signing using the device's Secure Enclave.
 */
@DependencyClient
public struct SecureEnclave: Sendable {
    /// Generate a new hardware-backed key in the Secure Enclave
    public var generateKey: @Sendable (String) async throws -> SecureKey
    
    /// Delete a key from the Secure Enclave
    public var deleteKey: @Sendable (String) async throws -> Void
    
    /// Check if a key exists in the Secure Enclave
    public var keyExists: @Sendable (String) async -> Bool = { _ in
        unimplemented("SecureEnclave.keyExists", placeholder: false)
    }
    
    /// Encrypt data using a Secure Enclave key
    public var encrypt: @Sendable (Data, String) async throws -> Data
    
    /// Decrypt data using a Secure Enclave key
    public var decrypt: @Sendable (Data, String) async throws -> Data
    
    /// Sign data using a Secure Enclave key
    public var sign: @Sendable (Data, String) async throws -> Data
    
    /// Verify a signature using a Secure Enclave key
    public var verify: @Sendable (Data, Data, String) async throws -> Bool
    
    /// Check if Secure Enclave is available on this device
    public var isAvailable: @Sendable () async -> Bool = { 
        unimplemented("SecureEnclave.isAvailable", placeholder: false)
    }
}

// MARK: - Dependency Key

extension DependencyValues {
    /// Access the Secure Enclave dependency
    public var secureEnclave: SecureEnclave {
        get { self[SecureEnclave.self] }
        set { self[SecureEnclave.self] = newValue }
    }
}

extension SecureEnclave: DependencyKey {
    /// Live implementation using SecureEnclaveActor
    public static let liveValue: SecureEnclave = {
        let actor = SecureEnclaveActor()
        
        return Self(
            generateKey: { tag in
                try await actor.generateKey(tag: tag)
            },
            deleteKey: { tag in
                try await actor.deleteKey(tag: tag)
            },
            keyExists: { tag in
                await actor.keyExists(tag: tag)
            },
            encrypt: { data, tag in
                try await actor.encrypt(data, using: tag)
            },
            decrypt: { data, tag in
                try await actor.decrypt(data, using: tag)
            },
            sign: { data, tag in
                try await actor.sign(data, using: tag)
            },
            verify: { data, signature, tag in
                try await actor.verify(signature, for: data, using: tag)
            },
            isAvailable: {
                await actor.isAvailable()
            }
        )
    }()
    
    /// Test implementation with mock operations
    public static let testValue: SecureEnclave = {
        return SecureEnclave(
            generateKey: { tag in
                SecureKey(
                    tag: tag,
                    publicKey: Data(repeating: 0x01, count: 65),
                    algorithm: .ecdsaSignatureMessageX962SHA256
                )
            },
            deleteKey: { _ in },
            keyExists: { _ in false },
            encrypt: { data, _ in 
                // Simple XOR for testing
                Data(data.map { $0 ^ 0xFF })
            },
            decrypt: { data, _ in
                // Simple XOR for testing
                Data(data.map { $0 ^ 0xFF })
            },
            sign: { data, _ in
                // Mock signature
                Data(SHA256.hash(data: data))
            },
            verify: { data, signature, _ in
                // Mock verification
                Data(SHA256.hash(data: data)) == signature
            },
            isAvailable: { false }
        )
    }()
}

/**
 Represents a key stored in the Secure Enclave.
 */
public struct SecureKey: Equatable, Sendable {
    /// Unique tag identifying the key
    public let tag: String
    
    /// Public key data (can be exported)
    public let publicKey: Data
    
    /// Algorithm used for this key
    public let algorithm: SecKeyAlgorithm
    
    public init(tag: String, publicKey: Data, algorithm: SecKeyAlgorithm) {
        self.tag = tag
        self.publicKey = publicKey
        self.algorithm = algorithm
    }
}
