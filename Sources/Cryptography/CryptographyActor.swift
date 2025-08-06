//
//  CryptographyActor.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation
import CryptoKit
import CommonCrypto

/// Actor providing thread-safe cryptographic operations
actor CryptographyActor {
    
    // MARK: - TOTP Operations
    
    /// Generate a TOTP code using RFC 6238 standard
    /// - Parameters:
    ///   - secret: The shared secret key
    ///   - time: The time to use (nil for current time)
    /// - Returns: 6-digit TOTP code
    func generateTOTP(secret: Data, time: Date? = nil) -> String {
        let timeInterval = (time ?? Date()).timeIntervalSince1970
        let counter = UInt64(timeInterval / 30) // 30-second time step
        
        // Convert counter to big-endian bytes
        var counterBigEndian = counter.bigEndian
        let counterData = withUnsafeBytes(of: &counterBigEndian) { Data($0) }
        
        // Generate HMAC-SHA1 (standard for TOTP)
        let key = SymmetricKey(data: secret)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key)
        let hmacData = Data(hmac)
        
        // Dynamic truncation
        let offset = Int(hmacData[hmacData.count - 1] & 0x0f)
        let truncated = hmacData[offset..<offset + 4]
        
        var code = truncated.withUnsafeBytes { bytes in
            bytes.load(as: UInt32.self).bigEndian
        }
        code &= 0x7FFFFFFF // Remove sign bit
        code %= 1_000_000  // 6-digit code
        
        return String(format: "%06d", code)
    }
    
    /// Generate a cryptographically secure TOTP secret
    func generateTOTPSecret() -> Data {
        // Generate 20 bytes (160 bits) for compatibility with most TOTP apps
        var bytes = [UInt8](repeating: 0, count: 20)
        _ = SecRandomCopyBytes(kSecRandomDefault, 20, &bytes)
        return Data(bytes)
    }
    
    // MARK: - Key Derivation
    
    /// Derive a key using Argon2id (requires external library in production)
    /// - Parameters:
    ///   - password: The password to derive from
    ///   - salt: Salt for the derivation
    /// - Returns: Derived symmetric key
    func deriveKeyArgon2(password: String, salt: Data) async throws -> SymmetricKey {
        // Note: Argon2id is not available in CryptoKit
        // In production, you'd use a library like CryptoSwift or Argon2Swift
        // For now, we'll use PBKDF2 as a fallback with high iterations
        
        // This is a placeholder - in production, use proper Argon2id
        return deriveKeyPBKDF2(
            password: password,
            salt: salt,
            iterations: 120_000 // High iteration count for better security
        )
    }
    
    /// Derive a key using PBKDF2
    /// - Parameters:
    ///   - password: The password to derive from
    ///   - salt: Salt for the derivation
    ///   - iterations: Number of iterations (recommend 120,000+)
    /// - Returns: Derived symmetric key
    func deriveKeyPBKDF2(password: String, salt: Data, iterations: Int) -> SymmetricKey {
        let passwordData = password.data(using: .utf8) ?? Data()
        
        var derivedKeyData = Data(count: 32) // 32 bytes for 256-bit key
        
        _ = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress!,
                        passwordData.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress!,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress!,
                        32
                    )
                }
            }
        }
        
        return SymmetricKey(data: derivedKeyData)
    }
    
    // MARK: - Entropy & Strength Analysis
    
    /// Calculate Shannon entropy of a string
    /// - Parameter key: The string to analyze
    /// - Returns: Entropy in bits
    func calculateEntropy(_ key: String) -> Double {
        guard !key.isEmpty else { return 0 }
        
        // Count character frequencies
        var frequencies: [Character: Int] = [:]
        for char in key {
            frequencies[char, default: 0] += 1
        }
        
        // Calculate Shannon entropy
        let length = Double(key.count)
        var entropy: Double = 0
        
        for count in frequencies.values {
            let probability = Double(count) / length
            entropy -= probability * log2(probability)
        }
        
        // Return total entropy (bits per character * length)
        return entropy * length
    }
    
    /// Analyze key strength with detailed feedback
    /// - Parameters:
    ///   - key: The key to analyze
    ///   - cipherType: The cipher type to evaluate against
    /// - Returns: Detailed key strength analysis
    func analyzeKeyStrength(_ key: String, for cipherType: CipherType) -> KeyStrength {
        let entropy = calculateEntropy(key)
        let patterns = detectPatterns(in: key)
        let score = calculateScore(entropy: entropy, patterns: patterns, keyLength: key.count)
        let suggestions = generateSuggestions(
            for: key,
            cipherType: cipherType,
            patterns: patterns,
            entropy: entropy
        )
        
        return KeyStrength(
            entropy: entropy,
            score: score,
            suggestions: suggestions,
            patterns: patterns
        )
    }
    
    /// Detect patterns in a key
    private func detectPatterns(in key: String) -> [PatternType] {
        var patterns: [PatternType] = []
        
        // Check for sequential characters
        if hasSequentialCharacters(key) {
            patterns.append(.sequential)
        }
        
        // Check for repeated sequences
        if hasRepeatedSequences(key) {
            patterns.append(.repeated)
        }
        
        // Check for keyboard walks
        if isKeyboardWalk(key) {
            patterns.append(.keyboardWalk)
        }
        
        // Check for common patterns
        if isCommonPattern(key) {
            patterns.append(.common)
        }
        
        // Check character types
        let hasNumbers = key.contains { $0.isNumber }
        let hasLetters = key.contains { $0.isLetter }
        
        if hasNumbers && !hasLetters {
            patterns.append(.numeric)
        } else if hasLetters && !hasNumbers {
            patterns.append(.alphabetic)
        }
        
        return patterns
    }
    
    private func hasSequentialCharacters(_ key: String) -> Bool {
        let chars = Array(key.lowercased())
        guard chars.count >= 3 else { return false }
        
        for i in 0..<(chars.count - 2) {
            if let first = chars[i].asciiValue,
               let second = chars[i + 1].asciiValue,
               let third = chars[i + 2].asciiValue {
                if second == first + 1 && third == second + 1 {
                    return true
                }
                if second == first - 1 && third == second - 1 {
                    return true
                }
            }
        }
        return false
    }
    
    private func hasRepeatedSequences(_ key: String) -> Bool {
        guard key.count >= 3 else { return false }
        
        // Check for repeated 2-3 character sequences
        for length in 2...min(3, key.count / 2) {
            var seen = Set<String>()
            for i in 0...(key.count - length) {
                let start = key.index(key.startIndex, offsetBy: i)
                let end = key.index(start, offsetBy: length)
                let substring = String(key[start..<end])
                
                if seen.contains(substring) {
                    return true
                }
                seen.insert(substring)
            }
        }
        return false
    }
    
    private func isKeyboardWalk(_ key: String) -> Bool {
        let walks = ["qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx", "qwertyuiop"]
        let lowercased = key.lowercased()
        return walks.contains { lowercased.contains($0) }
    }
    
    private func isCommonPattern(_ key: String) -> Bool {
        let common = ["password", "123456", "admin", "letmein", "welcome", "monkey"]
        let lowercased = key.lowercased()
        return common.contains { lowercased.contains($0) }
    }
    
    private func calculateScore(entropy: Double, patterns: [PatternType], keyLength: Int) -> KeyStrengthScore {
        // Base score from entropy
        var score = min(entropy * 10, 100) // Scale entropy to 0-100
        
        // Penalties for patterns
        score -= Double(patterns.count) * 15
        
        // Bonus for length
        if keyLength >= 12 {
            score += 10
        } else if keyLength >= 8 {
            score += 5
        }
        
        // Convert to score level
        switch score {
        case 80...:
            return .excellent
        case 60..<80:
            return .good
        case 40..<60:
            return .fair
        case 20..<40:
            return .weak
        default:
            return .veryWeak
        }
    }
    
    private func generateSuggestions(
        for key: String,
        cipherType: CipherType,
        patterns: [PatternType],
        entropy: Double
    ) -> [String] {
        var suggestions: [String] = []
        
        // Length suggestion
        if key.count < cipherType.minimumKeyLength {
            suggestions.append("Use at least \(cipherType.minimumKeyLength) characters")
        }
        
        // Pattern suggestions
        if patterns.contains(.sequential) {
            suggestions.append("Avoid sequential characters like 'abc' or '123'")
        }
        if patterns.contains(.repeated) {
            suggestions.append("Avoid repeated sequences")
        }
        if patterns.contains(.keyboardWalk) {
            suggestions.append("Avoid keyboard patterns like 'qwerty'")
        }
        if patterns.contains(.common) {
            suggestions.append("Avoid common words or phrases")
        }
        
        // Character type suggestions
        if patterns.contains(.numeric) {
            suggestions.append("Include letters for better security")
        }
        if patterns.contains(.alphabetic) {
            suggestions.append("Include numbers for better security")
        }
        
        let hasSpecial = key.contains { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }
        if !hasSpecial {
            suggestions.append("Add special characters like !@#$%")
        }
        
        // Entropy suggestion
        if entropy < 40 {
            suggestions.append("Consider using a longer, more random key")
        }
        
        return suggestions
    }
    
    // MARK: - Random Generation
    
    /// Generate cryptographically secure random data
    /// - Parameter byteCount: Number of bytes to generate
    /// - Returns: Random data
    func generateSecureRandom(byteCount: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return Data(bytes)
    }
    
    /// Generate a salt for key derivation (32 bytes)
    func generateSalt() -> Data {
        generateSecureRandom(byteCount: 32)
    }
    
    // MARK: - HMAC Operations
    
    /// Generate HMAC for data integrity
    /// - Parameters:
    ///   - data: Data to authenticate
    ///   - key: Symmetric key for HMAC
    /// - Returns: HMAC authentication code
    func generateHMAC(for data: Data, using key: SymmetricKey) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(for: data, using: key)
        return Data(hmac)
    }
    
    /// Verify HMAC for data integrity
    /// - Parameters:
    ///   - hmac: HMAC to verify
    ///   - data: Original data
    ///   - key: Symmetric key used for HMAC
    /// - Returns: true if HMAC is valid
    func verifyHMAC(_ hmac: Data, for data: Data, using key: SymmetricKey) -> Bool {
        let expectedHMAC = HMAC<SHA256>.authenticationCode(for: data, using: key)
        return Data(expectedHMAC) == hmac
    }
}
