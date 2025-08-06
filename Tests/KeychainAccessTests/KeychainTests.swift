//
//  KeychainTests.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Testing
import Dependencies
@testable import KeychainAccess

@Suite("Keychain Tests")
struct KeychainTests {
    
    @Test("Save and load data")
    func testSaveAndLoad() async throws {
        try await withDependencies {
            $0.keychain = .testValue
        } operation: {
            @Dependency(\.keychain) var keychain
            
            let testData = "test-data".data(using: .utf8)!
            let key = "test-key"
            
            // Save data
            try await keychain.save(testData, key)
            
            // Load data
            let loadedData = try await keychain.load(key)
            #expect(loadedData == testData)
        }
    }
    
    @Test("Load non-existent key throws error")
    func testLoadNonExistent() async throws {
        await withDependencies {
            $0.keychain = .testValue
        } operation: {
            @Dependency(\.keychain) var keychain
            
            await #expect(throws: KeychainError.itemNotFound) {
                _ = try await keychain.load("non-existent-key")
            }
        }
    }
    
    @Test("Update existing item")
    func testUpdate() async throws {
        try await withDependencies {
            $0.keychain = .testValue
        } operation: {
            @Dependency(\.keychain) var keychain
            
            let key = "update-key"
            let originalData = "original".data(using: .utf8)!
            let updatedData = "updated".data(using: .utf8)!
            
            // Save original
            try await keychain.save(originalData, key)
            
            // Update
            try await keychain.update(updatedData, key)
            
            // Verify update
            let loadedData = try await keychain.load(key)
            #expect(loadedData == updatedData)
        }
    }
    
    @Test("Update non-existent item throws error")
    func testUpdateNonExistent() async throws {
        await withDependencies {
            $0.keychain = .testValue
        } operation: {
            @Dependency(\.keychain) var keychain
            
            let data = "data".data(using: .utf8)!
            
            await #expect(throws: KeychainError.itemNotFound) {
                try await keychain.update(data, "non-existent")
            }
        }
    }
    
    @Test("Delete item")
    func testDelete() async throws {
        try await withDependencies {
            $0.keychain = .testValue
        } operation: {
            @Dependency(\.keychain) var keychain
            
            let key = "delete-key"
            let data = "data".data(using: .utf8)!
            
            // Save data
            try await keychain.save(data, key)
            
            // Verify it exists
            #expect(await keychain.exists(key))
            
            // Delete
            try await keychain.delete(key)
            
            // Verify deleted
            #expect(await !keychain.exists(key))
        }
    }
    
//    @Test("Clear all items")
//    func testClear() async throws {
//        try await withDependencies {
//            $0.keychain = .testValue
//        } operation: {
//            @Dependency(\.keychain) var keychain
//            
//            // Clear any existing items first
//            try await keychain.clear()
//            
//            // Save multiple items
//            try await keychain.save("data1".data(using: .utf8)!, "key1")
//            try await keychain.save("data2".data(using: .utf8)!, "key2")
//            try await keychain.save("data3".data(using: .utf8)!, "key3")
//            
//            // Verify they exist
//            let keys = try await keychain.listKeys()
//            #expect(keys.count == 3)
//            
//            // Clear all
//            try await keychain.clear()
//            
//            // Verify cleared
//            let remainingKeys = try await keychain.listKeys()
//            #expect(remainingKeys.isEmpty)
//        }
//    }
//
//    @Test("List keys returns all tracked keys")
//    func testListKeys() async throws {
//        try await withDependencies {
//            $0.keychain = .testValue
//        } operation: {
//            @Dependency(\.keychain) var keychain
//            
//            // Start clean - clear any existing keys
//            try await keychain.clear()
//            
//            // Save items
//            let keys = ["alpha", "beta", "gamma"]
//            for key in keys {
//                try await keychain.save("data".data(using: .utf8)!, key)
//            }
//            
//            // List keys
//            let listedKeys = try await keychain.listKeys()
//            #expect(Set(listedKeys) == Set(keys))
//            
//            // Clean up after test
//            try await keychain.clear()
//        }
//    }
}

@Suite("KeychainAccessibility Tests")
struct KeychainAccessibilityTests {
    
    @Test("Recommended accessibility is device only")
    func testRecommendedAccessibility() {
        #expect(KeychainAccessibility.recommended == .whenUnlockedThisDeviceOnly)
        #expect(KeychainAccessibility.recommended.isDeviceOnly)
        #expect(!KeychainAccessibility.recommended.requiresBiometric)
    }
    
    @Test("Maximum security requires biometric")
    func testMaximumAccessibility() {
        #expect(KeychainAccessibility.maximum == .whenUnlockedThisDeviceOnlyWithBiometrics)
        #expect(KeychainAccessibility.maximum.isDeviceOnly)
        #expect(KeychainAccessibility.maximum.requiresBiometric)
    }
    
    @Test("Device only flags are correct")
    func testDeviceOnlyFlags() {
        #expect(KeychainAccessibility.whenUnlocked.isDeviceOnly == false)
        #expect(KeychainAccessibility.afterFirstUnlock.isDeviceOnly == false)
        #expect(KeychainAccessibility.whenUnlockedThisDeviceOnly.isDeviceOnly == true)
        #expect(KeychainAccessibility.afterFirstUnlockThisDeviceOnly.isDeviceOnly == true)
        #expect(KeychainAccessibility.whenPasscodeSetThisDeviceOnly.isDeviceOnly == true)
    }
}
