//
//  InactivityModifier.swift
//  sentinel
//
//  Created by Kyle on 8/8/25.
//


import ComposableArchitecture
import SwiftUI

/**
 A generic view modifier that adds inactivity tracking to any view.
 Works with any action closure, not tied to a specific store type.
 */
struct InactivityModifier<Store>: ViewModifier {
    let store: Store
    let isActive: Bool
    let throttleInterval: TimeInterval
    let onTouch: (Store) -> Void
    
    func body(content: Content) -> some View {
        content
            .overlay(
                Group {
                    if isActive {
                        InteractionDetector(
                            throttleInterval: throttleInterval,
                            onTouch: { onTouch(store) }
                        )
                        .ignoresSafeArea()
                    }
                }
            )
    }
}

// MARK: - View Extensions

public extension View {
    /**
     Adds generic inactivity tracking to the view
     - Parameters:
       - store: Any store type
       - isActive: Whether tracking should be active
       - throttleInterval: Minimum time between touch detections
       - onTouch: Closure called when touch is detected
     */
    func trackInactivity<Store>(
        store: Store,
        isActive: Bool,
        throttleInterval: TimeInterval = 1.0,
        onTouch: @escaping (Store) -> Void
    ) -> some View {
        modifier(InactivityModifier(
            store: store,
            isActive: isActive,
            throttleInterval: throttleInterval,
            onTouch: onTouch
        ))
    }
    
    /**
     Simplified inactivity tracking without a store
     - Parameters:
       - isActive: Whether tracking should be active
       - throttleInterval: Minimum time between touch detections
       - onTouch: Closure called when touch is detected
     */
    func trackInactivity(
        isActive: Bool,
        throttleInterval: TimeInterval = 1.0,
        onTouch: @escaping () -> Void
    ) -> some View {
        overlay(
            Group {
                if isActive {
                    InteractionDetector(
                        throttleInterval: throttleInterval,
                        onTouch: onTouch
                    )
                    .ignoresSafeArea()
                }
            }
        )
    }
}
