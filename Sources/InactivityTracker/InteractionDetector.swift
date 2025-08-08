//
//  InteractionDetector.swift
//  sentinel
//
//  Created by Kyle on 8/8/25.
//


import SwiftUI

/**
 A completely generic view that detects user interactions without blocking SwiftUI touch handling.
 Uses hitTest to intercept touches and pass them through.
 */
struct InteractionDetector: UIViewRepresentable {
    let onTouch: () -> Void
    let throttleInterval: TimeInterval
    
    init(
        throttleInterval: TimeInterval = 1.0,
        onTouch: @escaping () -> Void
    ) {
        self.throttleInterval = throttleInterval
        self.onTouch = onTouch
    }
    
    func makeUIView(context: Context) -> TouchDetectingView {
        let view = TouchDetectingView()
        view.onTouch = onTouch
        view.throttleInterval = throttleInterval
        return view
    }
    
    func updateUIView(_ uiView: TouchDetectingView, context: Context) {
        uiView.onTouch = onTouch
        uiView.throttleInterval = throttleInterval
    }
}

class TouchDetectingView: UIView {
    var onTouch: (() -> Void)?
    var throttleInterval: TimeInterval = 1.0
    private var lastInteractionTime: Date = Date()
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        backgroundColor = .clear
        isUserInteractionEnabled = true
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? {
        // Detect the touch
        if event?.type == .touches {
            let now = Date()
            if now.timeIntervalSince(lastInteractionTime) > throttleInterval {
                lastInteractionTime = now
                onTouch?()
            }
        }
        
        // Return nil to pass the touch through to SwiftUI
        return nil
    }
}