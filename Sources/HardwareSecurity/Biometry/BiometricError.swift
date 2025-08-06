//
//  BiometricError.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation
import LocalAuthentication

/// Biometric authentication errors
public enum BiometricError: Error, LocalizedError, Equatable, Sendable {
    case notAvailable
    case notEnrolled
    case passcodeNotSet
    case cancelled
    case failed
    case lockedOut
    case invalidContext
    case appInBackground
    case systemCancel
    case unknown(String)
    
    static func fromLAError(_ error: NSError) -> BiometricError {
        guard error.domain == LAErrorDomain else {
            return .unknown(error.localizedDescription)
        }
        
        switch error.code {
        case LAError.authenticationFailed.rawValue:
            return .failed
        case LAError.userCancel.rawValue:
            return .cancelled
        case LAError.systemCancel.rawValue:
            return .systemCancel
        case LAError.passcodeNotSet.rawValue:
            return .passcodeNotSet
        case LAError.biometryNotAvailable.rawValue:
            return .notAvailable
        case LAError.biometryNotEnrolled.rawValue:
            return .notEnrolled
        case LAError.biometryLockout.rawValue:
            return .lockedOut
        case LAError.appCancel.rawValue:
            return .appInBackground
        case LAError.invalidContext.rawValue:
            return .invalidContext
        default:
            return .unknown(error.localizedDescription)
        }
    }
    
    public var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Biometric authentication is not available on this device."
        case .notEnrolled:
            return "No biometric data is enrolled. Please set up Face ID or Touch ID in Settings."
        case .passcodeNotSet:
            return "Device passcode is not set. Please set up a passcode in Settings."
        case .cancelled:
            return "Authentication was cancelled by the user."
        case .failed:
            return "Biometric authentication failed. Please try again."
        case .lockedOut:
            return "Biometric authentication is locked due to too many failed attempts."
        case .invalidContext:
            return "The authentication context is invalid."
        case .appInBackground:
            return "Authentication was cancelled because the app moved to background."
        case .systemCancel:
            return "Authentication was cancelled by the system."
        case .unknown(let message):
            return "Authentication failed: \(message)"
        }
    }
}
