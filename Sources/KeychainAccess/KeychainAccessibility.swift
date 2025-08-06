//
//  KeychainAccessibility.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation
import Security

/// Security accessibility options for keychain items
public enum KeychainAccessibility: Sendable {
    /// Item is accessible when device is unlocked
    case whenUnlocked
    
    /// Item is accessible after first unlock until restart
    case afterFirstUnlock
    
    /// Item is accessible when device is unlocked, doesn't sync to iCloud
    case whenUnlockedThisDeviceOnly
    
    /// Item is accessible after first unlock, doesn't sync to iCloud
    case afterFirstUnlockThisDeviceOnly
    
    /// Item requires device passcode, doesn't sync to iCloud
    case whenPasscodeSetThisDeviceOnly
    
    /// Item requires biometric authentication and device unlock
    case whenUnlockedThisDeviceOnlyWithBiometrics
    
    /// Item requires biometric authentication after first unlock
    case afterFirstUnlockThisDeviceOnlyWithBiometrics
    
    /// The Core Foundation security constant
    var securityValue: CFString {
        switch self {
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .whenUnlockedThisDeviceOnlyWithBiometrics:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnlyWithBiometrics:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
    }
    
    /// Whether this accessibility level requires biometric authentication
    var requiresBiometric: Bool {
        switch self {
        case .whenUnlockedThisDeviceOnlyWithBiometrics,
             .afterFirstUnlockThisDeviceOnlyWithBiometrics:
            return true
        default:
            return false
        }
    }
    
    /// Whether this accessibility level prevents iCloud Keychain sync
    var isDeviceOnly: Bool {
        switch self {
        case .whenUnlockedThisDeviceOnly,
             .afterFirstUnlockThisDeviceOnly,
             .whenPasscodeSetThisDeviceOnly,
             .whenUnlockedThisDeviceOnlyWithBiometrics,
             .afterFirstUnlockThisDeviceOnlyWithBiometrics:
            return true
        default:
            return false
        }
    }
    
    /// Recommended default for most sensitive data
    public static let recommended: KeychainAccessibility = .whenUnlockedThisDeviceOnly
    
    /// Maximum security with biometric requirement
    public static let maximum: KeychainAccessibility = .whenUnlockedThisDeviceOnlyWithBiometrics
}