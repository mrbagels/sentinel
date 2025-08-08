//
//  AppFeature.swift
//  sentinel
//
//  Created by Kyle on 8/8/25.
//


import ComposableArchitecture
import SwiftUI

@Reducer
struct AppFeature {
    @ObservableState
    struct State: Equatable {
        var isAuthenticated = true
        var userName = "John Doe"
        var inactivity = InactivityTracker.State(
            config: InactivityConfig(
                timeout: .seconds(10),
                warningThreshold: .seconds(5),
                touchThrottleInterval: 1.0
            )
        )
        var showingWarningAlert = false
        var warningSecondsRemaining = 0
    }
    
    enum Action: BindableAction {
        case binding(BindingAction<State>)
        case inactivity(InactivityTracker.Action)
        case loginButtonTapped
        case logoutButtonTapped
        case dismissWarningAlert
        case extendSessionButtonTapped
    }
    
    var body: some ReducerOf<Self> {
        Scope(state: \.inactivity, action: \.inactivity, child: InactivityTracker.init)
        
        BindingReducer()
        Reduce { state, action in
            switch action {
            case .inactivity(.warningReached):
                /**
                Handle the warning - show an alert to the user
                */
                state.showingWarningAlert = true
                if let warningThreshold = state.inactivity.config.warningThreshold {
                    let warningSeconds = Int(warningThreshold.components.seconds)
                    state.warningSecondsRemaining = warningSeconds
                }
                return .none
                
            case .inactivity(.inactivityTimeout):
                /**
                Handle the timeout - log the user out
                */
                state.isAuthenticated = false
                state.showingWarningAlert = false
                return .none
                
            case .inactivity:
                /**
                Let the child reducer handle other actions
                */
                return .none
                
            case .loginButtonTapped:
                state.isAuthenticated = true
                return .send(.inactivity(.startTimer))
                
            case .logoutButtonTapped:
                state.isAuthenticated = false
                return .send(.inactivity(.stopTimer))
                
            case .dismissWarningAlert:
                state.showingWarningAlert = false
                return .none
                
            case .extendSessionButtonTapped:
                state.showingWarningAlert = false
                /**
                Record activity to reset the timer
                */
                return .send(.inactivity(.recordActivity))
                
            case .binding:
                return .none
            }
        }
    }
}

struct AppView: View {
    @Bindable var store: StoreOf<AppFeature>
    
    var body: some View {
        NavigationStack {
            if store.isAuthenticated {
                AuthenticatedView(store: store)
            } else {
                LoginView(store: store)
            }
        }
    }
}

struct AuthenticatedView: View {
    @Bindable var store: StoreOf<AppFeature>
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Welcome, \(store.userName)!")
                .font(.title)
            
            Text("You've been active for \(store.inactivity.secondsSinceLastActivity) seconds")
                .foregroundColor(.secondary)
            
            Text("Timeout in: \(remainingSeconds) seconds")
                .font(.caption)
                .foregroundColor(.red)
            
            Button("Logout") {
                store.send(.logoutButtonTapped)
            }
            .buttonStyle(.borderedProminent)
            
            Spacer()
            
            Text("Tap anywhere to reset the timer")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .navigationTitle("Dashboard")
        /**
        Apply the inactivity tracking modifier
        */
        .trackInactivity(
            store: store,
            isActive: store.inactivity.isTrackingEnabled,
            throttleInterval: store.inactivity.config.touchThrottleInterval
        ) { store in
            store.send(.inactivity(.recordActivity))
        }
        .alert("Inactivity Warning", isPresented: $store.showingWarningAlert) {
            Button("Extend Session") {
                store.send(.extendSessionButtonTapped)
            }
            Button("Logout", role: .cancel) {
                store.send(.logoutButtonTapped)
            }
        } message: {
            Text("You will be logged out in \(store.warningSecondsRemaining) seconds due to inactivity.")
        }
        .onAppear {
            store.send(.inactivity(.startTimer))
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification)) { _ in
            store.send(.inactivity(.pauseForBackground))
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.willEnterForegroundNotification)) { _ in
            store.send(.inactivity(.resume))
        }
    }
    
    private var remainingSeconds: Int {
        let total = Int(store.inactivity.config.timeout.components.seconds)
        return max(0, total - store.inactivity.secondsSinceLastActivity)
    }
}

struct LoginView: View {
    let store: StoreOf<AppFeature>
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Session Expired")
                .font(.title)
            
            Text("Please log in again")
                .foregroundColor(.secondary)
            
            Button("Login") {
                store.send(.loginButtonTapped)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .navigationTitle("Login")
    }
}

/**
 Example of using the async/await features
 */
struct AsyncExampleView: View {
    let store: StoreOf<AppFeature>
    @State private var monitoringTask: Task<Void, Never>?
    
    var body: some View {
        Text("Monitoring Session")
            .onAppear {
                /**
                Start monitoring for timeout using async/await
                */
                monitoringTask = Task {
                    let reason = await InactivityTracker.waitForTimeout(
                        store: store.scope(state: \.inactivity, action: \.inactivity)
                    )
                    
                    switch reason {
                    case .inactivityTimeout:
                        print("User timed out due to inactivity")
                    case .cancelled:
                        print("Monitoring was cancelled")
                    }
                }
            }
            .onDisappear {
                monitoringTask?.cancel()
            }
            .task {
                /**
                Alternative: Use the activity stream
                */
                let activityStream = InactivityTracker.activityStream(
                    store: store.scope(state: \.inactivity, action: \.inactivity)
                )
                
                for await event in activityStream {
                    switch event {
                    case .started:
                        print("Inactivity tracking started")
                    case .activityDetected:
                        print("User activity detected")
                    case .warning(let secondsRemaining):
                        print("Warning: \(secondsRemaining) seconds until timeout")
                    case .timeout:
                        print("Session timed out")
                    }
                }
            }
    }
}

/**
 Preview with callbacks example
 */
#Preview {
    AppView(
        store: Store(initialState: AppFeature.State()) {
            AppFeature()
        }
    )
}
