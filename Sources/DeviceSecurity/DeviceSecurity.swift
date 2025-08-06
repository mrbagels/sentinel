//
//  DeviceSecurity.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Dependencies
import DependenciesMacros
import Foundation

/**
 A dependency client for device security operations.
 
 Provides jailbreak detection, secure memory management,
 and runtime security checks for the application.
 */
@DependencyClient
public struct DeviceSecurity: Sendable {
    /// Check if the device is jailbroken
    public var isJailbroken: @Sendable () async -> Bool = {
        unimplemented("DeviceSecurity.isJailbroken", placeholder: false)
    }
    
    /// Get comprehensive security environment information
    public var securityEnvironment: @Sendable () async -> SecurityEnvironment = {
        unimplemented("DeviceSecurity.securityEnvironment", placeholder: SecurityEnvironment(
            isJailbroken: false,
            isDebuggerAttached: false,
            isSimulator: false,
            hasSecureEnclave: false,
            hasBiometrics: false,
            osVersion: "Unknown",
            deviceModel: "Unknown",
            integrityStatus: .unknown
        ))
    }
    
    /// Check if debugger is attached
    public var isDebuggerAttached: @Sendable () async -> Bool = {
        unimplemented("DeviceSecurity.isDebuggerAttached", placeholder: false)
    }
    
    /// Check if app is running in simulator
    public var isSimulator: @Sendable () async -> Bool = {
        unimplemented("DeviceSecurity.isSimulator", placeholder: false)
    }
    
    /// Check if app has been tampered with
    public var checkIntegrity: @Sendable () async -> IntegrityStatus = {
        unimplemented("DeviceSecurity.checkIntegrity", placeholder: .unknown)
    }
    
    /// Clear sensitive data from memory
    public var clearSensitiveMemory: @Sendable () async -> Void = {
        unimplemented("DeviceSecurity.clearSensitiveMemory", placeholder: ())
    }
    
    /// Get device security score (0-100)
    public var securityScore: @Sendable () async -> Int = {
        unimplemented("DeviceSecurity.securityScore", placeholder: 0)
    }
}

/// Comprehensive security environment information
public struct SecurityEnvironment: Equatable, Sendable {
    public let isJailbroken: Bool
    public let isDebuggerAttached: Bool
    public let isSimulator: Bool
    public let hasSecureEnclave: Bool
    public let hasBiometrics: Bool
    public let osVersion: String
    public let deviceModel: String
    public let integrityStatus: IntegrityStatus
    public let suspiciousFiles: [String]
    public let suspiciousLibraries: [String]
    
    public init(
        isJailbroken: Bool,
        isDebuggerAttached: Bool,
        isSimulator: Bool,
        hasSecureEnclave: Bool,
        hasBiometrics: Bool,
        osVersion: String,
        deviceModel: String,
        integrityStatus: IntegrityStatus,
        suspiciousFiles: [String] = [],
        suspiciousLibraries: [String] = []
    ) {
        self.isJailbroken = isJailbroken
        self.isDebuggerAttached = isDebuggerAttached
        self.isSimulator = isSimulator
        self.hasSecureEnclave = hasSecureEnclave
        self.hasBiometrics = hasBiometrics
        self.osVersion = osVersion
        self.deviceModel = deviceModel
        self.integrityStatus = integrityStatus
        self.suspiciousFiles = suspiciousFiles
        self.suspiciousLibraries = suspiciousLibraries
    }
    
    /// Calculate overall security level
    public var securityLevel: SecurityLevel {
        if isJailbroken || integrityStatus != .intact {
            return .compromised
        }
        if isDebuggerAttached {
            return .suspicious
        }
        if !hasSecureEnclave {
            return .basic
        }
        if hasBiometrics {
            return .high
        }
        return .medium
    }
}

/// Application integrity status
public enum IntegrityStatus: Equatable, Sendable {
    case intact
    case modified
    case unknown
    case checkFailed(String)
}

/// Device security levels
public enum SecurityLevel: Equatable, Sendable {
    case compromised
    case suspicious
    case basic
    case medium
    case high
    
    public var description: String {
        switch self {
        case .compromised:
            return "Device security is compromised"
        case .suspicious:
            return "Suspicious activity detected"
        case .basic:
            return "Basic security features available"
        case .medium:
            return "Standard security features active"
        case .high:
            return "Enhanced security features active"
        }
    }
    
    public var recommendedActions: [String] {
        switch self {
        case .compromised:
            return [
                "Do not store sensitive data on this device",
                "Consider using a non-jailbroken device",
                "Enable additional authentication"
            ]
        case .suspicious:
            return [
                "Verify app authenticity",
                "Check for unauthorized modifications",
                "Restart the application"
            ]
        case .basic:
            return [
                "Enable device passcode",
                "Consider upgrading to a newer device with Secure Enclave"
            ]
        case .medium:
            return [
                "Enable biometric authentication",
                "Keep your OS updated"
            ]
        case .high:
            return []
        }
    }
}

// MARK: - Dependency Key

extension DependencyValues {
    /// Access the device security dependency
    public var deviceSecurity: DeviceSecurity {
        get { self[DeviceSecurity.self] }
        set { self[DeviceSecurity.self] = newValue }
    }
}

extension DeviceSecurity: DependencyKey {
    /// Live implementation
    public static let liveValue: DeviceSecurity = {
        let detector = SecurityDetector()
        
        return Self(
            isJailbroken: {
                await detector.isJailbroken()
            },
            securityEnvironment: {
                await detector.getSecurityEnvironment()
            },
            isDebuggerAttached: {
                await detector.isDebuggerAttached()
            },
            isSimulator: {
                await detector.isSimulator()
            },
            checkIntegrity: {
                await detector.checkIntegrity()
            },
            clearSensitiveMemory: {
                await detector.clearSensitiveMemory()
            },
            securityScore: {
                await detector.calculateSecurityScore()
            }
        )
    }()
    
    /// Test implementation
    public static let testValue: DeviceSecurity = {
        return DeviceSecurity(
            isJailbroken: { false },
            securityEnvironment: {
                SecurityEnvironment(
                    isJailbroken: false,
                    isDebuggerAttached: false,
                    isSimulator: true,
                    hasSecureEnclave: false,
                    hasBiometrics: false,
                    osVersion: "17.0",
                    deviceModel: "Simulator",
                    integrityStatus: .intact
                )
            },
            isDebuggerAttached: { false },
            isSimulator: { true },
            checkIntegrity: { .intact },
            clearSensitiveMemory: { },
            securityScore: { 75 }
        )
    }()
}
