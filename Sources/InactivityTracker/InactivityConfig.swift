//
//  InactivityConfig.swift
//  sentinel
//
//  Created by Kyle on 6/3/25.
//

import Foundation

/**
 Configuration for inactivity tracking behavior
 */
public struct InactivityConfig: Equatable, Sendable {
    /// Duration before timeout
    public let timeout: Duration
    
    /// Optional warning threshold before timeout (e.g., 2 minutes before timeout)
    public let warningThreshold: Duration?
    
    /// Minimum time between touch detections (throttling)
    public let touchThrottleInterval: TimeInterval
    
    public init(
        timeout: Duration = .seconds(30 * 60),
        warningThreshold: Duration? = nil,
        touchThrottleInterval: TimeInterval = 1.0
    ) {
        self.timeout = timeout
        self.warningThreshold = warningThreshold
        self.touchThrottleInterval = touchThrottleInterval
    }
}

/**
 Callback configuration for inactivity events.
 These are stored separately from InactivityConfig to maintain Equatable conformance.
 */
public struct InactivityCallbacks: Sendable {
    /// Called when warning threshold is reached (parameter is seconds until timeout)
    public var onWarning: (@Sendable (Int) -> Void)?
    
    /// Called when any activity is detected
    public var onActivityDetected: (@Sendable () -> Void)?
    
    /// Called when timeout is reached
    public var onTimeout: @Sendable () -> Void
    
    public init(
        onWarning: (@Sendable (Int) -> Void)? = nil,
        onActivityDetected: (@Sendable () -> Void)? = nil,
        onTimeout: @escaping @Sendable () -> Void
    ) {
        self.onWarning = onWarning
        self.onActivityDetected = onActivityDetected
        self.onTimeout = onTimeout
    }
}
