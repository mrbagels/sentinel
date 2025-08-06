//
//  KeychainStorage.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Dependencies
import Foundation
import Sharing

/**
 A SharedKey implementation backed by Keychain storage with native observation support.
 
 This implementation provides secure persistence through the iOS Keychain with
 proper support for the Sharing library's persistence protocols.
 */
public struct KeychainStorage<Value: Codable & Sendable>: SharedKey {
    
    @Dependency(\.keychain) var keychain
    
    /// The key used for saving and retrieving from the keychain service
    public let key: String
    
    /// A default value to return when no stored value is available
    public let defaultValue: Value
    
    /// Optional accessibility level for keychain storage
    public let accessibility: KeychainAccessibility
    
    /// An identifier computed from the key
    public var id: String { 
        "keychain-\(key)" 
    }
    
    /**
     Creates a KeychainStorage instance.
     
     - Parameters:
       - key: The key to use for storing in the keychain
       - defaultValue: The value to return when no stored value exists
       - accessibility: The security accessibility level (defaults to recommended)
     */
    public init(
        key: String, 
        defaultValue: Value,
        accessibility: KeychainAccessibility = .recommended
    ) {
        self.key = key
        self.defaultValue = defaultValue
        self.accessibility = accessibility
    }
    
    // MARK: - SharedKey Protocol
    
    /**
     Saves a value to the Keychain.
     
     - Parameters:
       - value: The value to be saved
       - context: A context indicating if save is user-initiated
       - continuation: A continuation to resume once the save is complete
     */
    public func save(
        _ value: Value, 
        context: SaveContext, 
        continuation: SaveContinuation
    ) {
        Task {
            do {
                let encoder = JSONEncoder()
                let data = try encoder.encode(value)
                try await keychain.save(data, key)
                
                // Notify subscribers of the change
                await notifier.notify(value)
                
                continuation.resume()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
    
    /**
     Loads a value from the Keychain.
     
     - Parameters:
       - context: A context provided by the Sharing framework
       - continuation: A continuation to resume with the loaded value
     */
    public func load(
        context: LoadContext<Value>, 
        continuation: LoadContinuation<Value>
    ) {
        Task {
            do {
                let data = try await keychain.load(key)
                let decoder = JSONDecoder()
                let loadedValue = try decoder.decode(Value.self, from: data)
                continuation.resume(returning: loadedValue)
            } catch KeychainError.itemNotFound {
                // Return default value if not found
                continuation.resume(returning: defaultValue)
            } catch {
                // For other errors, use the default value or throw
                continuation.resume(returning: defaultValue)
            }
        }
    }
    
    /**
     Subscribes to changes for this key.
     
     This implementation provides change notifications using AsyncStream
     for proper integration with the Sharing library.
     
     - Parameters:
       - context: A context provided by the Sharing framework
       - subscriber: A subscriber to receive value updates
     - Returns: A subscription that can be cancelled
     */
    public func subscribe(
        context: LoadContext<Value>, 
        subscriber: SharedSubscriber<Value>
    ) -> SharedSubscription {
        // Create a task to handle the subscription
        let task = Task {
            // First load the current value
            do {
                let data = try await keychain.load(key)
                let decoder = JSONDecoder()
                let loadedValue = try decoder.decode(Value.self, from: data)
                subscriber.yield(loadedValue)
            } catch KeychainError.itemNotFound {
                subscriber.yield(defaultValue)
            } catch {
                // On error, yield the default value
                subscriber.yield(defaultValue)
            }
            
            // Then subscribe to future changes
            let stream = await notifier.subscribe()
            for await value in stream {
                subscriber.yield(value)
            }
        }
        
        // Return a subscription that cancels the task when done
        return SharedSubscription {
            task.cancel()
        }
    }
    
    // MARK: - Change Notification
    
    /// Actor for managing subscribers to value changes
    private let notifier = ChangeNotifier<Value>()
}

/// Actor for managing change notifications in a thread-safe manner
private actor ChangeNotifier<Value: Sendable> {
    /// Type representing a single subscription
    private struct Subscription {
        let id: UUID
        let continuation: AsyncStream<Value>.Continuation
    }
    
    /// Active subscriptions
    private var subscriptions: [UUID: Subscription] = [:]
    
    /// Creates a new subscription
    func subscribe() -> AsyncStream<Value> {
        AsyncStream { continuation in
            let id = UUID()
            let subscription = Subscription(id: id, continuation: continuation)
            subscriptions[id] = subscription
            
            continuation.onTermination = { [weak self] _ in
                Task { await self?.unsubscribe(id: id) }
            }
        }
    }
    
    /// Removes a subscription
    func unsubscribe(id: UUID) {
        subscriptions.removeValue(forKey: id)
    }
    
    /// Notifies all subscribers of a value change
    func notify(_ value: Value) {
        for subscription in subscriptions.values {
            subscription.continuation.yield(value)
        }
    }
}

// MARK: - Convenience Factory

extension SharedKey {
    /**
     Creates a keychain storage for the specified key and default value.
     
     - Parameters:
       - key: The key to use for storage
       - defaultValue: The default value to return when no value is stored
       - accessibility: The security accessibility level
     - Returns: A KeychainStorage instance
     */
    public static func keychainStorage<Value>(
        _ key: String, 
        defaultValue: Value,
        accessibility: KeychainAccessibility = .recommended
    ) -> Self where Self == KeychainStorage<Value> {
        return Self(key: key, defaultValue: defaultValue, accessibility: accessibility)
    }
}

// MARK: - Type-Safe Keys

extension SharedKey where Self == KeychainStorage<Bool> {
    /// Example type-safe key for biometric authentication preference
    public static var biometricEnabled: Self {
        keychainStorage("biometric-enabled", defaultValue: false, accessibility: .maximum)
    }
}

extension SharedKey where Self == KeychainStorage<Data> {
    /// Example type-safe key for secure token storage
    public static func secureToken(_ identifier: String) -> Self {
        keychainStorage("token-\(identifier)", defaultValue: Data(), accessibility: .whenUnlockedThisDeviceOnly)
    }
}