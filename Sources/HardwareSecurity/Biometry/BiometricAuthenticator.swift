//
//  BiometricAuthenticator.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Dependencies
import DependenciesMacros
import Foundation
import LocalAuthentication

/**
 A dependency client for biometric authentication.
 
 Provides Face ID/Touch ID authentication with fallback options and
 comprehensive error handling.
 */
@DependencyClient
public struct BiometricAuthenticator: Sendable {
    /// Authenticate using biometrics with a reason string
    public var authenticate: @Sendable (String) async throws -> Bool
    
    /// Authenticate with custom policy (biometrics, passcode, or both)
    public var authenticateWithPolicy: @Sendable (BiometricPolicy, String) async throws -> Bool
    
    /// Check if biometrics are available on this device
    public var canAuthenticate: @Sendable () async -> BiometricAvailability = {
        unimplemented("BiometricAuthenticator.canAuthenticate", placeholder: .notAvailable)
    }
    
    /// Check which biometric type is available
    public var biometricType: @Sendable () async -> BiometricType = {
        unimplemented("BiometricAuthenticator.biometricType", placeholder: .none)
    }
    
    /// Invalidate the current authentication context
    public var invalidate: @Sendable () async -> Void = {
        unimplemented("BiometricAuthenticator.invalidate", placeholder: ())
    }
}

/// Biometric authentication policies
public enum BiometricPolicy: Sendable {
    /// Biometric authentication only
    case biometryOnly
    /// Biometric or device passcode
    case biometryOrPasscode
    /// Biometric and device passcode (stronger security)
    case biometryAndPasscode
    
    var laPolicy: LAPolicy {
        switch self {
        case .biometryOnly:
            return .deviceOwnerAuthenticationWithBiometrics
        case .biometryOrPasscode, .biometryAndPasscode:
            return .deviceOwnerAuthentication
        }
    }
}

/// Biometric availability status
public enum BiometricAvailability: Equatable, Sendable {
    case available
    case notEnrolled
    case passcodeNotSet
    case notAvailable
    case lockedOut
    case unknown(String)
}

/// Type of biometric authentication available
public enum BiometricType: Equatable, Sendable {
    case none
    case touchID
    case faceID
    case opticID  // For Vision Pro
}

// MARK: - Dependency Key

extension DependencyValues {
    /// Access the biometric authenticator dependency
    public var biometricAuthenticator: BiometricAuthenticator {
        get { self[BiometricAuthenticator.self] }
        set { self[BiometricAuthenticator.self] = newValue }
    }
}

extension BiometricAuthenticator: DependencyKey {
    /// Live implementation using LAContext
    public static let liveValue: BiometricAuthenticator = {
        let actor = BiometricActor()
        
        return Self(
            authenticate: { reason in
                try await actor.authenticate(reason: reason)
            },
            authenticateWithPolicy: { policy, reason in
                try await actor.authenticate(policy: policy, reason: reason)
            },
            canAuthenticate: {
                await actor.canAuthenticate()
            },
            biometricType: {
                await actor.biometricType()
            },
            invalidate: {
                await actor.invalidate()
            }
        )
    }()
    
    /// Test implementation with configurable responses
    public static let testValue: BiometricAuthenticator = {
        return BiometricAuthenticator(
            authenticate: { _ in true },
            authenticateWithPolicy: { _, _ in true },
            canAuthenticate: { .available },
            biometricType: { .faceID },
            invalidate: { }
        )
    }()
}

/// Actor managing biometric authentication state
actor BiometricActor {
    private var currentContext: LAContext?
    
    /// Authenticate using biometrics
    func authenticate(reason: String) async throws -> Bool {
        try await authenticate(policy: .biometryOnly, reason: reason)
    }
    
    /// Authenticate with specified policy
    func authenticate(policy: BiometricPolicy, reason: String) async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        
        // Store context for potential invalidation
        currentContext = context
        defer { currentContext = nil }
        
        var error: NSError?
        guard context.canEvaluatePolicy(policy.laPolicy, error: &error) else {
            if let error = error {
                throw BiometricError.fromLAError(error)
            }
            throw BiometricError.notAvailable
        }
        
        do {
            return try await withCheckedThrowingContinuation { continuation in
                context.evaluatePolicy(
                    policy.laPolicy,
                    localizedReason: reason
                ) { success, error in
                    if success {
                        continuation.resume(returning: true)
                    } else if let error = error as NSError? {
                        continuation.resume(throwing: BiometricError.fromLAError(error))
                    } else {
                        continuation.resume(returning: false)
                    }
                }
            }
        } catch {
            throw error
        }
    }
    
    /// Check if biometric authentication is available
    func canAuthenticate() -> BiometricAvailability {
        let context = LAContext()
        var error: NSError?
        
        // First check biometrics only
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return .available
        }
        
        // Check the specific error
        if let error = error {
            switch error.code {
            case LAError.biometryNotEnrolled.rawValue:
                return .notEnrolled
            case LAError.passcodeNotSet.rawValue:
                return .passcodeNotSet
            case LAError.biometryNotAvailable.rawValue:
                return .notAvailable
            case LAError.biometryLockout.rawValue:
                return .lockedOut
            default:
                return .unknown(error.localizedDescription)
            }
        }
        
        return .notAvailable
    }
    
    /// Determine the type of biometric available
    func biometricType() -> BiometricType {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        
        switch context.biometryType {
        case .none:
            return .none
        case .touchID:
            return .touchID
        case .faceID:
            return .faceID
        case .opticID:
            return .opticID
        @unknown default:
            return .none
        }
    }
    
    /// Invalidate the current authentication context
    func invalidate() {
        currentContext?.invalidate()
        currentContext = nil
    }
}
