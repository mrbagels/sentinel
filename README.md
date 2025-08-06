# Sentinel

A comprehensive Swift security toolkit providing keychain access, hardware security, cryptography, and device security features for iOS applications.

[![Swift Version](https://img.shields.io/badge/Swift-6.1-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2017%2B-blue.svg)](https://developer.apple.com/ios/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

Sentinel is a modular security package designed for iOS applications that require robust security features. Built with Swift 6's strict concurrency in mind, it provides thread-safe, production-ready security components.

## Features

### 🔐 KeychainAccess
- Secure storage with hardware encryption
- Biometric authentication support
- Data integrity verification (HMAC)
- Integration with Point-Free's Dependencies and Sharing libraries
- Thread-safe actor-based implementation

### 🛡️ HardwareSecurity
- Secure Enclave operations
- Hardware-backed key generation
- Biometric authentication (Face ID/Touch ID)
- Cryptographic operations that never expose keys
- Support for signing and encryption

### 🔑 Cryptography
- TOTP generation (RFC 6238 compliant)
- Key derivation (PBKDF2, Argon2id ready)
- Entropy calculation and key strength analysis
- Secure random generation
- HMAC operations for data integrity

### 🔒 DeviceSecurity
- Comprehensive jailbreak detection (7+ methods)
- Debugger detection
- App integrity verification
- Secure memory management
- Runtime security environment analysis

## Installation

### Swift Package Manager

Add Sentinel to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/mrbagels/sentinel", from: "1.0.0")
]
```

Or in Xcode:
1. File → Add Package Dependencies
2. Enter the repository URL
3. Select the modules you need

## Usage

### KeychainAccess

```swift
import KeychainAccess
import Dependencies

// Using the Keychain dependency
@Dependency(\.keychain) var keychain

// Save data
try await keychain.save(userData, "user-key")

// Load data
let data = try await keychain.load("user-key")

// With Sharing library for reactive updates
@Shared(.keychainStorage("settings", defaultValue: Settings()))
var settings: Settings
```

### HardwareSecurity

```swift
import HardwareSecurity
import Dependencies

@Dependency(\.secureEnclave) var secureEnclave
@Dependency(\.biometricAuthenticator) var biometric

// Generate hardware-backed key
let key = try await secureEnclave.generateKey("my-key")

// Biometric authentication
let authenticated = try await biometric.authenticate("Authenticate to continue")

// Encrypt with Secure Enclave
let encrypted = try await secureEnclave.encrypt(data, "my-key")
```

### Cryptography

```swift
import Cryptography
import Dependencies

@Dependency(\.cryptography) var crypto

// Generate TOTP
let totpSecret = await crypto.generateTOTPSecret()
let code = await crypto.generateTOTP(totpSecret, nil)

// Key derivation
let salt = await crypto.generateSalt()
let key = await crypto.deriveKeyPBKDF2(password, salt, 120_000)

// Key strength analysis
let strength = await crypto.analyzeKeyStrength(password, .hardwareEnhanced)
```

### DeviceSecurity

```swift
import DeviceSecurity
import Dependencies

@Dependency(\.deviceSecurity) var security

// Check security environment
let environment = await security.securityEnvironment()
if environment.isJailbroken {
    // Handle jailbroken device
}

// Secure string for sensitive data
let securePassword = SecureString("sensitive-data")
// Memory is automatically wiped when SecureString is deallocated
```

## Requirements

- iOS 17.0+
- macOS 14.0+ (for macOS targets)
- Swift 6.1+
- Xcode 16.0+

## Dependencies

- [swift-dependencies](https://github.com/pointfreeco/swift-dependencies) - Dependency injection
- [swift-sharing](https://github.com/pointfreeco/swift-sharing) - State sharing and persistence

## Security Considerations

- **Jailbreak Detection**: Multiple detection methods are employed, but determined attackers may bypass them
- **Secure Enclave**: Only available on devices with A12 Bionic chip or later
- **Memory Protection**: Swift's ARC makes complete memory wiping challenging; use SecureString for sensitive data
- **Keychain**: Data is encrypted by iOS but may be accessible if device passcode is compromised

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Sentinel is available under the MIT license. See the [LICENSE](LICENSE) file for more info.

## Author

Kyle Begeman

## Acknowledgments

- [Point-Free](https://www.pointfree.co) for their excellent Dependencies and Sharing libraries
- The iOS security community for research and best practices
