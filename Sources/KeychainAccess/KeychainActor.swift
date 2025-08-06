//
//  KeychainActor.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation
import Security
import CryptoKit

/// An actor providing thread-safe access to keychain operations
public actor KeychainActor: Sendable {
    
    private let service: String
    private let accessGroup: String?
    
    /// Creates a new KeychainActor with the specified service identifier
    /// - Parameters:
    ///   - service: The service identifier for keychain items
    ///   - accessGroup: Optional access group for sharing between apps
    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }
    
    // MARK: - Public Methods
    
    /// Loads data from the keychain for the given key
    /// - Parameter key: The key to identify the keychain item
    /// - Returns: The data stored for the key
    /// - Throws: A KeychainError if the operation fails
    public func load(_ key: String) throws -> Data {
        let query = buildQuery(for: key, includeReturnData: true)
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.from(status: status, operation: .load)
        }
        
        // Verify data integrity if HMAC is present
        return try verifyAndExtractData(data)
    }
    
    /// Saves data to the keychain for the given key
    /// - Parameters:
    ///   - data: The data to store
    ///   - key: The key to identify the keychain item
    ///   - accessibility: Security accessibility constraint
    /// - Throws: A KeychainError if the operation fails
    public func save(_ data: Data, forKey key: String,
                     accessibility: KeychainAccessibility = .whenUnlockedThisDeviceOnly) throws {
        // Add integrity protection
        let protectedData = try addIntegrityProtection(to: data)
        
        var query = buildQuery(for: key)
        query[kSecValueData as String] = protectedData
        
        // Apply accessibility settings
        try applyAccessibility(accessibility, to: &query)
        
        // First try to delete any existing item (ignore errors)
        _ = SecItemDelete(query as CFDictionary)
        
        // Then add the new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.from(status: status, operation: .save)
        }
        
        try trackKey(key)
    }
    
    /// Updates existing data in the keychain
    /// - Parameters:
    ///   - data: The new data to store
    ///   - key: The key identifying the keychain item
    /// - Throws: A KeychainError if the operation fails or item doesn't exist
    public func update(_ data: Data, forKey key: String) throws {
        // Verify item exists first
        guard exists(key) else {
            throw KeychainError.itemNotFound
        }
        
        let protectedData = try addIntegrityProtection(to: data)
        
        let query = buildQuery(for: key)
        let attributes: [String: Any] = [
            kSecValueData as String: protectedData
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status == errSecSuccess else {
            throw KeychainError.from(status: status, operation: .update)
        }
    }
    
    /// Deletes a keychain item for the given key
    /// - Parameter key: The key identifying the keychain item
    /// - Throws: A KeychainError if the operation fails
    public func delete(_ key: String) throws {
        let query = buildQuery(for: key)
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.from(status: status, operation: .delete)
        }
        
        try untrackKey(key)
    }
    
    /// Checks if a key exists in the keychain
    /// - Parameter key: The key to check
    /// - Returns: true if the key exists, false otherwise
    public func exists(_ key: String) -> Bool {
        let query = buildQuery(for: key)
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Lists all tracked keys (without exposing their values)
    /// - Returns: Array of key names
    public func listKeys() throws -> [String] {
        try loadTrackedKeys()
    }
    
    /// Clears all keychain items tracked by this actor
    /// - Throws: A KeychainError if the operation fails
    public func clear() throws {
        let trackedKeys = try loadTrackedKeys()
        for key in trackedKeys {
            try delete(key)
        }
        try saveTrackedKeys([])
    }
    
    // MARK: - Private Helpers
    
    /// Builds the base query dictionary for keychain operations
    private func buildQuery(for key: String, includeReturnData: Bool = false) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: false  // Explicitly prevent iCloud sync
        ]
        
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        if includeReturnData {
            query[kSecReturnData as String] = true
        }
        
        return query
    }
    
    /// Applies accessibility settings to the query
    private func applyAccessibility(_ accessibility: KeychainAccessibility,
                                   to query: inout [String: Any]) throws {
        if accessibility.requiresBiometric {
            // Use access control for biometric protection
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                accessibility.securityValue,
                [.biometryCurrentSet, .privateKeyUsage],
                nil
            ) else {
                throw KeychainError.accessControlCreationFailed
            }
            query[kSecAttrAccessControl as String] = access
            // Do NOT set kSecAttrAccessible when using access control
        } else {
            // Use standard accessibility without access control
            query[kSecAttrAccessible as String] = accessibility.securityValue
        }
    }
    
    // MARK: - Data Integrity Protection
    
    /// Adds HMAC for data integrity verification
    private func addIntegrityProtection(to data: Data) throws -> Data {
        let key = try getOrCreateIntegrityKey()
        let hmac = HMAC<SHA256>.authenticationCode(for: data, using: key)
        
        // Combine HMAC + original data
        var protectedData = Data(hmac)
        protectedData.append(data)
        return protectedData
    }
    
    /// Verifies HMAC and extracts original data
    private func verifyAndExtractData(_ protectedData: Data) throws -> Data {
        guard protectedData.count > 32 else { // SHA256 HMAC is 32 bytes
            // Legacy data without HMAC, return as-is
            return protectedData
        }
        
        let hmacData = protectedData.prefix(32)
        let originalData = protectedData.suffix(from: 32)
        
        let key = try getOrCreateIntegrityKey()
        let expectedHMAC = HMAC<SHA256>.authenticationCode(for: originalData, using: key)
        
        guard hmacData == Data(expectedHMAC) else {
            throw KeychainError.dataIntegrityCheckFailed
        }
        
        return originalData
    }
    
    /// Gets or creates a symmetric key for HMAC operations
    private func getOrCreateIntegrityKey() throws -> SymmetricKey {
        let keyTag = "\(service).integrity-key"
        
        // Try to load existing key
        let loadQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let loadStatus = SecItemCopyMatching(loadQuery as CFDictionary, &result)
        
        if loadStatus == errSecSuccess, let keyData = result as? Data {
            return SymmetricKey(data: keyData)
        }
        
        // Generate new key
        let newKey = SymmetricKey(size: .bits256)
        let keyData = newKey.withUnsafeBytes { Data($0) }
        
        let saveQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let saveStatus = SecItemAdd(saveQuery as CFDictionary, nil)
        guard saveStatus == errSecSuccess || saveStatus == errSecDuplicateItem else {
            throw KeychainError.integrityKeyCreationFailed
        }
        
        return newKey
    }
    
    // MARK: - Key Tracking (Improved Security)
    
    private let keyTrackingKey = "__sentinel_tracked_keys__"
    
    private func trackKey(_ key: String) throws {
        var trackedKeys = try loadTrackedKeys()
        if !trackedKeys.contains(key) {
            trackedKeys.append(key)
            try saveTrackedKeys(trackedKeys)
        }
    }
    
    private func untrackKey(_ key: String) throws {
        var trackedKeys = try loadTrackedKeys()
        trackedKeys.removeAll { $0 == key }
        try saveTrackedKeys(trackedKeys)
    }
    
    private func loadTrackedKeys() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyTrackingKey,
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let data = result as? Data else {
            // No tracking data yet
            return []
        }
        
        do {
            return try JSONDecoder().decode([String].self, from: data)
        } catch {
            // Corrupted tracking data, start fresh
            return []
        }
    }
    
    private func saveTrackedKeys(_ keys: [String]) throws {
        let data = try JSONEncoder().encode(keys)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyTrackingKey,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        
        // Delete existing tracking data
        _ = SecItemDelete(query as CFDictionary)
        
        // Save new tracking data
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            // Non-fatal: tracking failure shouldn't break operations
            return
        }
    }
}
