//
//  KeychainError.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation
import Security

/// Errors that can occur during keychain operations
public enum KeychainError: Error, LocalizedError, Equatable, Sendable {
    case itemNotFound
    case duplicateItem
    case invalidData
    case accessControlCreationFailed
    case dataIntegrityCheckFailed
    case integrityKeyCreationFailed
    case authenticationFailed
    case interactionNotAllowed
    case decodeFailed
    case encodeFailed
    case unknown(OSStatus)
    
    /// Creates a KeychainError from an OSStatus code
    static func from(status: OSStatus, operation: KeychainOperation) -> KeychainError {
        switch status {
        case errSecItemNotFound:
            return .itemNotFound
        case errSecDuplicateItem:
            return .duplicateItem
        case errSecAuthFailed:
            return .authenticationFailed
        case errSecInteractionNotAllowed:
            return .interactionNotAllowed
        case errSecDecode:
            return .decodeFailed
        default:
            return .unknown(status)
        }
    }
    
    public var errorDescription: String? {
        switch self {
        case .itemNotFound:
            return "The requested keychain item was not found."
        case .duplicateItem:
            return "A keychain item with this identifier already exists."
        case .invalidData:
            return "The keychain data is invalid or corrupted."
        case .accessControlCreationFailed:
            return "Failed to create access control for biometric protection."
        case .dataIntegrityCheckFailed:
            return "Data integrity verification failed. The data may have been tampered with."
        case .integrityKeyCreationFailed:
            return "Failed to create or retrieve the integrity protection key."
        case .authenticationFailed:
            return "Authentication failed. Please verify your credentials."
        case .interactionNotAllowed:
            return "User interaction is not allowed for this operation."
        case .decodeFailed:
            return "Failed to decode the keychain data."
        case .encodeFailed:
            return "Failed to encode data for keychain storage."
        case .unknown(let status):
            return "Keychain operation failed with error code: \(status). \(errorMessage(for: status))"
        }
    }
    
    /// Provides detailed error message for OSStatus codes
    private func errorMessage(for status: OSStatus) -> String {
        if let message = SecCopyErrorMessageString(status, nil) as String? {
            return message
        }
        return "Unknown error"
    }
}

/// Types of keychain operations for error context
enum KeychainOperation: String, Sendable {
    case load = "load"
    case save = "save"
    case update = "update"
    case delete = "delete"
}