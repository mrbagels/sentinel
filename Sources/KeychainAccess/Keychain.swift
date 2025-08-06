//
//  Keychain.swift
//  sentinel
//
//  KeychainAccess module - Secure keychain storage with Dependencies integration
//


import Dependencies
import DependenciesMacros
import Foundation

/**
 A dependency client for secure keychain storage.
 
 This interface provides access to keychain operations through an actor-based implementation,
 ensuring thread safety and proper error handling.
 */
@DependencyClient
public struct Keychain: Sendable {
    /// Unique identifier for Equatable/Hashable conformance
    private let id = UUID()
    
    /// The default service name used for keychain items
    public static let defaultService = "com.sentinel.keychain-service"
    
    /// Loads data from the keychain for the given key
    public var load: @Sendable (String) async throws -> Data
    
    /// Saves data to the keychain for the given key
    public var save: @Sendable (Data, String) async throws -> Void
    
    /// Updates existing data in the keychain for the given key
    public var update: @Sendable (Data, String) async throws -> Void
    
    /// Deletes a keychain item for the given key
    public var delete: @Sendable (String) async throws -> Void
    
    /// Clears all keychain items tracked by this dependency
    public var clear: @Sendable () async throws -> Void
    
    /// Checks if a key exists in the keychain
    public var exists: @Sendable (String) async -> Bool = { _ in
        return unimplemented("Keychain.exists", placeholder: false)
    }
    
    /// Lists all tracked keys (without exposing their values)
    public var listKeys: @Sendable () async throws -> [String]
}

// MARK: - Equatable and Hashable

extension Keychain: Equatable, Hashable {
    public static func == (lhs: Keychain, rhs: Keychain) -> Bool {
        lhs.id == rhs.id
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

// MARK: - Dependency Key

extension DependencyValues {
    /// Access the keychain dependency
    public var keychain: Keychain {
        get { self[Keychain.self] }
        set { self[Keychain.self] = newValue }
    }
}

extension Keychain: DependencyKey {
    /// Live implementation using KeychainActor
    public static let liveValue: Keychain = {
        let actor = KeychainActor(service: defaultService)
        
        return Self(
            load: { key in
                try await actor.load(key)
            },
            save: { data, key in
                try await actor.save(data, forKey: key)
            },
            update: { data, key in
                try await actor.update(data, forKey: key)
            },
            delete: { key in
                try await actor.delete(key)
            },
            clear: {
                try await actor.clear()
            },
            exists: { key in
                await actor.exists(key)
            },
            listKeys: {
                try await actor.listKeys()
            }
        )
    }()
    
    /// Test implementation with in-memory storage
    public static let testValue: Keychain = {
        final class TestStorage: @unchecked Sendable {
            private var storage: [String: Data] = [:]
            private var trackedKeys: Set<String> = []
            private let queue = DispatchQueue(label: "test.keychain")
            
            func load(_ key: String) throws -> Data {
                var result: Data?
                var loadError: KeychainError?
                queue.sync {
                    if let data = storage[key] {
                        result = data
                    } else {
                        loadError = .itemNotFound
                    }
                }
                if let error = loadError {
                    throw error
                }
                return result!
            }
            
            func save(_ data: Data, key: String) {
                queue.sync {
                    storage[key] = data
                    trackedKeys.insert(key)
                }
            }
            
            func update(_ data: Data, key: String) throws {
                var updateError: KeychainError?
                queue.sync {
                    guard storage[key] != nil else {
                        updateError = .itemNotFound
                        return
                    }
                    storage[key] = data
                }
                if let error = updateError {
                    throw error
                }
            }
            
            func delete(_ key: String) {
                queue.sync {
                    storage.removeValue(forKey: key)
                    trackedKeys.remove(key)
                }
            }
            
            func clear() {
                queue.sync {
                    storage.removeAll()
                    trackedKeys.removeAll()
                }
            }
            
            func exists(_ key: String) -> Bool {
                queue.sync {
                    storage[key] != nil
                }
            }
            
            func listKeys() -> [String] {
                queue.sync {
                    Array(trackedKeys)
                }
            }
        }
        
        let storage = TestStorage()
        
        return Keychain(
            load: { key in try storage.load(key) },
            save: { data, key in storage.save(data, key: key) },
            update: { data, key in try storage.update(data, key: key) },
            delete: { key in storage.delete(key) },
            clear: { storage.clear() },
            exists: { key in storage.exists(key) },
            listKeys: { storage.listKeys() }
        )
    }()
}
