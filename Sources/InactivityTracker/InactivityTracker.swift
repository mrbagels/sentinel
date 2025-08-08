//
//  InactivityTracker.swift
//  sentinel
//
//  Created by Kyle on 8/8/25.
//


import ComposableArchitecture
import Foundation

/**
 Tracks user inactivity and triggers logout after a specified duration.
 
 This reducer monitors user activity across the application and automatically
 logs out users after a period of inactivity to ensure security.
 */
@Reducer
public struct InactivityTracker {
    
    // MARK: - State
    
    @ObservableState
    public struct State: Equatable {
        /// The duration of inactivity before logout
        var inactivityDuration: Duration
        
        /// Whether inactivity tracking is enabled
        var isTrackingEnabled: Bool
        
        /// The last recorded activity timestamp (nil until timer starts)
        var lastActivityDate: Date?
        
        /// Whether the inactivity timer is currently running
        var isTimerActive: Bool
        
        /// Seconds since last activity (for display)
        var secondsSinceLastActivity: Int
        
        /// When the app was backgrounded
        var backgroundedAt: Date?
        
        /// Configuration for the tracker
        var config: InactivityConfig
        
        /// Warning threshold from config (for convenience)
        var warningThreshold: Duration? {
            config.warningThreshold
        }
        
        /// Track if warning has been issued (for new warning feature)
        var hasIssuedWarning: Bool = false
        
        public init(
            config: InactivityConfig,
            isTrackingEnabled: Bool = true,
            lastActivityDate: Date? = nil,
            isTimerActive: Bool = false,
            secondsSinceLastActivity: Int = 0,
            backgroundedAt: Date? = nil
        ) {
            self.config = config
            self.inactivityDuration = config.timeout
            self.isTrackingEnabled = isTrackingEnabled
            self.lastActivityDate = lastActivityDate
            self.isTimerActive = isTimerActive
            self.secondsSinceLastActivity = secondsSinceLastActivity
            self.backgroundedAt = backgroundedAt
        }
    }
    
    // MARK: - Actions
    
    public enum Action: Equatable, Sendable {
        /// Records user activity
        case recordActivity
        
        /// Starts the inactivity timer
        case startTimer
        
        /// Resumes the timer without resetting the last activity date
        case resume
        
        /// Stops the inactivity timer
        case stopTimer
        
        /// Timer tick to check for inactivity
        case timerTick
        
        /// Schedule next timer tick with dynamic interval
        case scheduleNextTick
        
        /// Inactivity timeout reached
        case inactivityTimeout
        
        /// App lifecycle events
        case pauseForBackground
        
        /// Enable or disable tracking
        case setTrackingEnabled(Bool)
        
        /// Update configuration
        case updateConfig(InactivityConfig)
        
        /// Warning threshold reached (new)
        case warningReached
    }
    
    // MARK: - Dependencies
    
    @Dependency(\.date) var date
    @Dependency(\.continuousClock) var clock
    
    private enum CancelID { case timer }
    
    public init() {}
    
    // MARK: - Reducer
    
    public var body: some ReducerOf<Self> {
        Reduce { state, action in
            switch action {
            // Activity recording
            case .recordActivity:
                return handleActivityRecording(&state)
                
            // Timer management
            case .startTimer, .resume, .stopTimer, .timerTick, .scheduleNextTick:
                return handleTimerManagement(&state, action: action)
                
            // Lifecycle
            case .pauseForBackground:
                return handleLifecycle(&state, action: action)
                
            // Configuration
            case .setTrackingEnabled, .updateConfig:
                return handleConfiguration(&state, action: action)
                
            // Timeout
            case .inactivityTimeout:
                return handleTimeout(&state)
                
            // Warning (new)
            case .warningReached:
                state.hasIssuedWarning = true
                return .none
            }
        }
    }
    
    // MARK: - Activity Recording
    
    private func handleActivityRecording(_ state: inout State) -> Effect<Action> {
        guard state.isTrackingEnabled else { return .none }
        
        state.lastActivityDate = date()
        state.secondsSinceLastActivity = 0
        state.hasIssuedWarning = false // Reset warning on new activity
        
        // Restart the timer if it's not already running
        if !state.isTimerActive {
            return .send(.startTimer)
        }
        return .none
    }
    
    // MARK: - Timer Management
    
    private func handleTimerManagement(_ state: inout State, action: Action) -> Effect<Action> {
        switch action {
        case .startTimer:
            guard state.isTrackingEnabled else { return .none }
            
            state.isTimerActive = true
            state.lastActivityDate = date()
            state.secondsSinceLastActivity = 0
            state.hasIssuedWarning = false
            
            return .send(.scheduleNextTick)
            
        case .resume:
            guard state.isTrackingEnabled else { return .none }
            
            /**
            Check if we're resuming from background
            */
            if let backgroundedAt = state.backgroundedAt {
                let backgroundDuration = date().timeIntervalSince(backgroundedAt)
                state.backgroundedAt = nil
                
                /**
                Add background time to our tracking
                */
                if let lastActivity = state.lastActivityDate {
                    state.lastActivityDate = lastActivity.addingTimeInterval(-backgroundDuration)
                    
                    /**
                    Check if we've already exceeded the timeout while backgrounded
                    */
                    let timeSinceActivity = date().timeIntervalSince(state.lastActivityDate!)
                    if timeSinceActivity >= Double(state.inactivityDuration.components.seconds) {
                        return .send(.inactivityTimeout)
                    }
                    
                    /**
                    Check if we should trigger warning (new)
                    */
                    if let warningThreshold = state.warningThreshold,
                       !state.hasIssuedWarning {
                        let warningTime = Double(state.inactivityDuration.components.seconds) - Double(warningThreshold.components.seconds)
                        if timeSinceActivity >= warningTime {
                            state.hasIssuedWarning = true
                            return .merge(
                                .send(.warningReached),
                                .send(.scheduleNextTick)
                            )
                        }
                    }
                }
            }
            
            /**
            Resume the timer
            */
            state.isTimerActive = true
            return .send(.scheduleNextTick)
            
        case .stopTimer:
            guard state.isTimerActive else { return .none }
            
            state.isTimerActive = false
            return .cancel(id: CancelID.timer)
            
        case .timerTick:
            guard state.isTrackingEnabled else {
                return .send(.stopTimer)
            }
            
            guard let lastActivityDate = state.lastActivityDate else {
                return .send(.startTimer)
            }
            
            let now = date()
            let timeSinceLastActivity = now.timeIntervalSince(lastActivityDate)
            state.secondsSinceLastActivity = Int(timeSinceLastActivity)
            
            if timeSinceLastActivity >= Double(state.inactivityDuration.components.seconds) {
                return .send(.inactivityTimeout)
            }
            
            /**
            Check for warning threshold (new)
            */
            if let warningThreshold = state.warningThreshold,
               !state.hasIssuedWarning {
                let warningTime = Double(state.inactivityDuration.components.seconds) - Double(warningThreshold.components.seconds)
                if timeSinceLastActivity >= warningTime {
                    state.hasIssuedWarning = true
                    return .merge(
                        .send(.warningReached),
                        .send(.scheduleNextTick)
                    )
                }
            }
            
            return .send(.scheduleNextTick)
            
        case .scheduleNextTick:
            return scheduleNextTimerTick(state)
            
        default:
            return .none
        }
    }
    
    // MARK: - Lifecycle Management
    
    private func handleLifecycle(_ state: inout State, action: Action) -> Effect<Action> {
        switch action {
        case .pauseForBackground:
            guard state.isTrackingEnabled else { return .none }
            
            state.backgroundedAt = date()
            return .send(.stopTimer)
            
        default:
            return .none
        }
    }
    
    // MARK: - Configuration Management
    
    private func handleConfiguration(_ state: inout State, action: Action) -> Effect<Action> {
        switch action {
        case .setTrackingEnabled(let enabled):
            state.isTrackingEnabled = enabled
            
            if enabled && !state.isTimerActive {
                return .send(.startTimer)
            } else if !enabled && state.isTimerActive {
                return .send(.stopTimer)
            }
            
            return .none
            
        case .updateConfig(let config):
            state.config = config
            state.inactivityDuration = config.timeout
            state.hasIssuedWarning = false
            return .none
            
        default:
            return .none
        }
    }
    
    // MARK: - Timeout Handling
    
    private func handleTimeout(_ state: inout State) -> Effect<Action> {
        // Reset our own state before notifying parent
        state.isTimerActive = false
        state.lastActivityDate = date()
        state.secondsSinceLastActivity = 0
        
        return .cancel(id: CancelID.timer)
    }
    
    // MARK: - Timer Scheduling
    
    private func scheduleNextTimerTick(_ state: State) -> Effect<Action> {
        guard state.isTimerActive,
              let lastActivityDate = state.lastActivityDate else {
            return .none
        }
        
        let timeSinceLastActivity = date().timeIntervalSince(lastActivityDate)
        let timeRemaining = state.inactivityDuration.components.seconds - Int64(timeSinceLastActivity)
        
        // Dynamic interval based on time remaining
        let nextInterval: Duration = switch timeRemaining {
        case ...10:           .seconds(1)    // Last 10 seconds: check every second
        case ...60:           .seconds(5)    // Last minute: check every 5 seconds
        case ...300:          .seconds(30)   // Last 5 minutes: check every 30 seconds
        case ...600:          .seconds(60)   // Last 10 minutes: check every minute
        default:              .seconds(300)  // Otherwise: check every 5 minutes
        }
        
        return .run { [clock] send in
            try await clock.sleep(for: nextInterval)
            await send(.timerTick)
        }
        .cancellable(id: CancelID.timer)
    }
}

// MARK: - Async/Await Extensions

public extension InactivityTracker {
    
    /**
     Waits for a timeout to occur
     */
    static func waitForTimeout(store: Store<State, Action>) async -> TimeoutReason {
        await withCheckedContinuation { continuation in
            let task = Task { @MainActor in
                var hasResumed = false
                
                while !hasResumed {
                    let state = store.withState { $0 }
                    if state.secondsSinceLastActivity >= Int(state.inactivityDuration.components.seconds) {
                        if !hasResumed {
                            hasResumed = true
                            continuation.resume(returning: .inactivityTimeout)
                        }
                        break
                    }
                    try? await Task.sleep(nanoseconds: 1_000_000_000) // Check every second
                }
            }
            
            Task {
                await withTaskCancellationHandler {
                    task.cancel()
                    continuation.resume(returning: .cancelled)
                } onCancel: {
                    task.cancel()
                }
            }
        }
    }
    
    /**
     Stream of activity events
     */
    static func activityStream(store: Store<State, Action>) -> AsyncStream<ActivityEvent> {
        AsyncStream { continuation in
            let task = Task { @MainActor in
                var lastState: State? = nil
                var isActive = true
                
                while isActive {
                    let state = store.withState { $0 }
                    
                    defer { lastState = state }
                    
                    // Detect started
                    if state.isTimerActive && lastState?.isTimerActive != true {
                        continuation.yield(.started)
                    }
                    
                    // Detect activity
                    if state.secondsSinceLastActivity == 0 && (lastState?.secondsSinceLastActivity ?? 0) > 0 {
                        continuation.yield(.activityDetected)
                    }
                    
                    // Detect warning
                    if state.hasIssuedWarning && lastState?.hasIssuedWarning != true {
                        let remaining = Int(state.inactivityDuration.components.seconds) - state.secondsSinceLastActivity
                        continuation.yield(.warning(secondsRemaining: remaining))
                    }
                    
                    // Detect timeout
                    if state.secondsSinceLastActivity >= Int(state.inactivityDuration.components.seconds) {
                        continuation.yield(.timeout)
                        continuation.finish()
                        isActive = false
                        break
                    }
                    
                    try? await Task.sleep(nanoseconds: 1_000_000_000) // Check every second
                }
            }
            
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }
}

/**
 Reason for timeout
 */
public enum TimeoutReason: Equatable, Sendable {
    case inactivityTimeout
    case cancelled
}

/**
 Activity events that can be observed
 */
public enum ActivityEvent: Equatable, Sendable {
    case started
    case activityDetected
    case warning(secondsRemaining: Int)
    case timeout
}
