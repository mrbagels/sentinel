//
//  SecureEnclaveError.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation

/// Errors that can occur during Secure Enclave operations
public enum SecureEnclaveError: Error, LocalizedError, Equatable, Sendable {
    case notAvailable
    case keyGenerationFailed(CFError?)
    case keyNotFound(String)
    case keyDeletionFailed(OSStatus)
    case publicKeyExtractionFailed
    case publicKeyExportFailed(CFError?)
    case encryptionFailed(CFError?)
    case decryptionFailed(CFError?)
    case signingFailed(CFError?)
    case verificationFailed(CFError?)
    case algorithmNotSupported
    case accessControlCreationFailed
    case biometricAuthenticationFailed
    case invalidKeyData
    
    public var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Secure Enclave is not available on this device."
        case .keyGenerationFailed(let error):
            return "Failed to generate key in Secure Enclave: \(error?.localizedDescription ?? "Unknown error")"
        case .keyNotFound(let tag):
            return "Key with tag '\(tag)' not found in Secure Enclave."
        case .keyDeletionFailed(let status):
            return "Failed to delete key from Secure Enclave. Error code: \(status)"
        case .publicKeyExtractionFailed:
            return "Failed to extract public key from Secure Enclave key pair."
        case .publicKeyExportFailed(let error):
            return "Failed to export public key data: \(error?.localizedDescription ?? "Unknown error")"
        case .encryptionFailed(let error):
            return "Encryption failed: \(error?.localizedDescription ?? "Unknown error")"
        case .decryptionFailed(let error):
            return "Decryption failed: \(error?.localizedDescription ?? "Unknown error")"
        case .signingFailed(let error):
            return "Signing failed: \(error?.localizedDescription ?? "Unknown error")"
        case .verificationFailed(let error):
            return "Signature verification failed: \(error?.localizedDescription ?? "Unknown error")"
        case .algorithmNotSupported:
            return "The requested algorithm is not supported by this key."
        case .accessControlCreationFailed:
            return "Failed to create access control for Secure Enclave key."
        case .biometricAuthenticationFailed:
            return "Biometric authentication failed or was cancelled."
        case .invalidKeyData:
            return "The provided key data is invalid or corrupted."
        }
    }
    
    public static func == (lhs: SecureEnclaveError, rhs: SecureEnclaveError) -> Bool {
        switch (lhs, rhs) {
        case (.notAvailable, .notAvailable),
             (.publicKeyExtractionFailed, .publicKeyExtractionFailed),
             (.algorithmNotSupported, .algorithmNotSupported),
             (.accessControlCreationFailed, .accessControlCreationFailed),
             (.biometricAuthenticationFailed, .biometricAuthenticationFailed),
             (.invalidKeyData, .invalidKeyData):
            return true
        case let (.keyNotFound(lTag), .keyNotFound(rTag)):
            return lTag == rTag
        case let (.keyDeletionFailed(lStatus), .keyDeletionFailed(rStatus)):
            return lStatus == rStatus
        case let (.keyGenerationFailed(lError), .keyGenerationFailed(rError)),
             let (.publicKeyExportFailed(lError), .publicKeyExportFailed(rError)),
             let (.encryptionFailed(lError), .encryptionFailed(rError)),
             let (.decryptionFailed(lError), .decryptionFailed(rError)),
             let (.signingFailed(lError), .signingFailed(rError)),
             let (.verificationFailed(lError), .verificationFailed(rError)):
            // Compare CFError? - just check if both are nil or both are non-nil
            // CFError doesn't conform to Equatable, so we can't compare values directly
            switch (lError, rError) {
            case (nil, nil):
                return true
            case (_?, _?):
                // Both have errors, consider them equal for this enum case
                return true
            default:
                return false
            }
        default:
            return false
        }
    }
}
