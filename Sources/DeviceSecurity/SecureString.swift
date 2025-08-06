//
//  SecureString.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation

/**
 A secure wrapper for sensitive string data that automatically clears memory.
 
 This class ensures sensitive data is properly wiped from memory when no longer needed,
 reducing the risk of memory inspection attacks.
 */
public final class SecureString: @unchecked Sendable {
    private var data: NSMutableData
    private let lock = NSLock()
    
    /// The length of the secure string
    public var count: Int {
        lock.withLock { data.length }
    }
    
    /// Initialize with a string value
    public init(_ string: String) {
        let bytes = Array(string.utf8)
        self.data = NSMutableData(bytes: bytes, length: bytes.count)
    }
    
    /// Initialize with data
    public init(data: Data) {
        self.data = NSMutableData(data: data)
    }
    
    /// Initialize empty with capacity
    public init(capacity: Int = 0) {
        self.data = NSMutableData(capacity: capacity) ?? NSMutableData()
    }
    
    /// Get the string value (use carefully - creates a copy in memory)
    public func reveal() -> String {
        lock.withLock {
            String(data: data as Data, encoding: .utf8) ?? ""
        }
    }
    
    /// Get the raw data (use carefully - creates a copy in memory)
    public func revealData() -> Data {
        lock.withLock {
            Data(data as Data)
        }
    }
    
    /// Append a string to this secure string
    public func append(_ string: String) {
        lock.withLock {
            let bytes = Array(string.utf8)
            data.append(bytes, length: bytes.count)
        }
    }
    
    /// Append data to this secure string
    public func appendData(_ newData: Data) {
        lock.withLock {
            data.append(newData)
        }
    }
    
    /// Clear the secure string from memory
    public func clear() {
        lock.withLock {
            // Overwrite with zeros
            data.resetBytes(in: NSRange(location: 0, length: data.length))
            data.length = 0
        }
    }
    
    /// Compare with another secure string in constant time
    public func isEqual(to other: SecureString) -> Bool {
        lock.withLock {
            other.lock.withLock {
                constantTimeCompare(data as Data, other.data as Data)
            }
        }
    }
    
    /// Compare with a regular string in constant time
    public func isEqual(to string: String) -> Bool {
        lock.withLock {
            let stringData = string.data(using: .utf8) ?? Data()
            return constantTimeCompare(data as Data, stringData)
        }
    }
    
    /// Constant-time comparison to prevent timing attacks
    private func constantTimeCompare(_ data1: Data, _ data2: Data) -> Bool {
        guard data1.count == data2.count else {
            return false
        }
        
        var result: UInt8 = 0
        for (byte1, byte2) in zip(data1, data2) {
            result |= byte1 ^ byte2
        }
        
        return result == 0
    }
    
    deinit {
        clear()
    }
}

/**
 A property wrapper that automatically secures string values.
 
 Usage:
 ```swift
 @SecureStringWrapper var password: String = ""
 */
@propertyWrapper
public struct SecureStringWrapper: Sendable {
    private let storage: SecureString
    
    public var wrappedValue: String {
        get { storage.reveal() }
        set {
            storage.clear()
            storage.append(newValue)
        }
    }

    public init(wrappedValue: String) {
        self.storage = SecureString(wrappedValue)
    }

    /// Access the underlying SecureString
    public var projectedValue: SecureString {
        storage
    }
}

/**
A secure data wrapper that automatically clears memory.
*/
public final class SecureData: @unchecked Sendable {
    
    private var data: NSMutableData
    private let lock = NSLock()
    
    /// The length of the secure data
    public var count: Int {
        lock.withLock { data.length }
    }
    
    /// Initialize with data
    public init(_ data: Data) {
        self.data = NSMutableData(data: data)
    }
    
    /// Initialize empty with capacity
    public init(capacity: Int = 0) {
        self.data = NSMutableData(capacity: capacity) ?? NSMutableData()
    }
    
    /// Get the data (use carefully - creates a copy in memory)
    public func reveal() -> Data {
        lock.withLock {
            Data(data as Data)
        }
    }
    
    /// Append data
    public func append(_ newData: Data) {
        lock.withLock {
            data.append(newData)
        }
    }
    
    /// Clear the data from memory
    public func clear() {
        lock.withLock {
            // Overwrite with random data first, then zeros
            let length = data.length
            if length > 0 {
                var randomBytes = [UInt8](repeating: 0, count: length)
                _ = SecRandomCopyBytes(kSecRandomDefault, length, &randomBytes)
                data.replaceBytes(in: NSRange(location: 0, length: length), withBytes: randomBytes)
                
                // Then overwrite with zeros
                data.resetBytes(in: NSRange(location: 0, length: length))
            }
            data.length = 0
        }
    }
    
    deinit {
        clear()
    }
}
