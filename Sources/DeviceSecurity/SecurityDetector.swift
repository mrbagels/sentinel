//
//  SecurityDetector.swift
//  sentinel
//
//  Created by Kyle on 8/6/25.
//


import Foundation
import UIKit
import Darwin
import MachO

/// Actor providing device security detection and monitoring
actor SecurityDetector {
    
    // MARK: - Jailbreak Detection
    
    /// Comprehensive jailbreak detection using multiple methods
    func isJailbroken() -> Bool {
        // Method 1: Check for suspicious files
        if checkSuspiciousFiles() {
            return true
        }
        
        // Method 2: Check for suspicious URL schemes
        if checkSuspiciousURLSchemes() {
            return true
        }
        
        // Method 3: Check file permissions
        if checkFilePermissions() {
            return true
        }
        
        // Method 4: Check for suspicious libraries
        if checkDynamicLibraries() {
            return true
        }
        
        // Method 5: Fork detection (sandbox check)
        if checkFork() {
            return true
        }
        
        // Method 6: Check symbolic links
        if checkSymbolicLinks() {
            return true
        }
        
        // Method 7: Check system calls
        if checkSystemCalls() {
            return true
        }
        
        return false
    }
    
    /// Check for suspicious files that indicate jailbreak
    private func checkSuspiciousFiles() -> Bool {
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/RocketBootstrap.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/SBSettings.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries",
            "/Library/PreferenceBundles/LibertyPref.bundle",
            "/Library/PreferenceBundles/RocketBootstrapPref.bundle",
            "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/etc/apt",
            "/etc/ssh/sshd_config",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/bin/bash",
            "/bin/sh",
            "/usr/sbin/frida-server",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib"
        ]
        
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
            
            // Also check if we can read the path (shouldn't be able to in sandbox)
            if let _ = try? FileManager.default.contentsOfDirectory(atPath: path) {
                return true
            }
        }
        
        return false
    }
    
    /// Check for suspicious URL schemes
    private func checkSuspiciousURLSchemes() -> Bool {
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://", "activator://"]
        
        // UIApplication.shared is MainActor-isolated, so we need to check from MainActor
        return MainActor.assumeIsolated {
            for scheme in schemes {
                if let url = URL(string: scheme),
                   UIApplication.shared.canOpenURL(url) {
                    return true
                }
            }
            return false
        }
    }
    
    /// Check file permissions (can we write outside sandbox?)
    private func checkFilePermissions() -> Bool {
        let testString = "jailbreak_test"
        let paths = [
            "/private/jailbreak_test.txt",
            "/root/jailbreak_test.txt"
        ]
        
        for path in paths {
            do {
                try testString.write(toFile: path, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: path)
                return true  // If we can write outside sandbox, device is jailbroken
            } catch {
                // Expected behavior - should not be able to write
            }
        }
        
        return false
    }
    
    /// Check for suspicious dynamic libraries
    private func checkDynamicLibraries() -> Bool {
        let suspiciousLibraries = [
            "SubstrateLoader.dylib",
            "SSLKillSwitch2.dylib",
            "SSLKillSwitch.dylib",
            "MobileSubstrate.dylib",
            "TweakInject.dylib",
            "CydiaSubstrate.dylib",
            "cynject",
            "libcycript",
            "frida",
            "libhooker"
        ]
        
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                for suspicious in suspiciousLibraries {
                    if name.contains(suspicious) {
                        return true
                    }
                }
            }
        }
        
        return false
    }
    
    /// Check if we can execute commands (simplified check)
    private func checkFork() -> Bool {
        // fork() is not available on iOS
        // Instead, check if we can access certain system functions
        // that shouldn't be accessible in a sandboxed environment
        
        // Try to access /bin/bash directly
        return FileManager.default.isExecutableFile(atPath: "/bin/bash")
    }
    
    /// Check for symbolic links that shouldn't exist
    private func checkSymbolicLinks() -> Bool {
        let paths = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]
        
        for path in paths {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
                if let fileType = attributes[.type] as? FileAttributeType,
                   fileType == .typeSymbolicLink {
                    return true
                }
            } catch {
                // Ignore errors
            }
        }
        
        return false
    }
    
    /// Check system calls that shouldn't work
    private func checkSystemCalls() -> Bool {
        // system() is not available on iOS
        // Instead check if we can access shell binaries
        let shells = ["/bin/bash", "/bin/sh"]
        for shell in shells {
            if FileManager.default.isExecutableFile(atPath: shell) {
                return true
            }
        }
        return false
    }
    
    // MARK: - Debugger Detection
    
    /// Check if a debugger is attached
    func isDebuggerAttached() -> Bool {
        // Method 1: Check P_TRACED flag
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result == 0 {
            return (info.kp_proc.p_flag & P_TRACED) != 0
        }
        
        // Method 2: Check ptrace
        return checkPtrace()
    }
    
    private func checkPtrace() -> Bool {
        // ptrace(PT_DENY_ATTACH, 0, 0, 0) would prevent debugging
        // But we just check if it's already attached
        return false  // Simplified - implement actual ptrace check if needed
    }
    
    // MARK: - Environment Checks
    
    /// Check if running in simulator
    func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    /// Get comprehensive security environment
    func getSecurityEnvironment() async -> SecurityEnvironment {
        let jailbroken = isJailbroken()
        let debuggerAttached = isDebuggerAttached()
        let simulator = isSimulator()
        let hasSecureEnclave = checkSecureEnclave()
        let hasBiometrics = checkBiometrics()
        
        // Get MainActor-isolated values
        let (osVersion, deviceModel) = await MainActor.run {
            (UIDevice.current.systemVersion, getDeviceModel())
        }
        
        let integrityStatus = checkIntegrity()
        let suspiciousFiles = getSuspiciousFiles()
        let suspiciousLibraries = getSuspiciousLibraries()
        
        return SecurityEnvironment(
            isJailbroken: jailbroken,
            isDebuggerAttached: debuggerAttached,
            isSimulator: simulator,
            hasSecureEnclave: hasSecureEnclave,
            hasBiometrics: hasBiometrics,
            osVersion: osVersion,
            deviceModel: deviceModel,
            integrityStatus: integrityStatus,
            suspiciousFiles: suspiciousFiles,
            suspiciousLibraries: suspiciousLibraries
        )
    }
    
    private func checkSecureEnclave() -> Bool {
        // Check if device supports Secure Enclave
        // A12 Bionic and later have Secure Enclave
        let deviceModel = getDeviceModel()
        
        // This is a simplified check - in production, use proper detection
        let secureEnclaveDevices = [
            "iPhone10,", // iPhone 8/X and later
            "iPhone11,", "iPhone12,", "iPhone13,", "iPhone14,", "iPhone15,",
            "iPad8,",    // iPad Pro 3rd gen and later
            "iPad11,", "iPad12,", "iPad13,", "iPad14,"
        ]
        
        return secureEnclaveDevices.contains { deviceModel.hasPrefix($0) }
    }
    
    private func checkBiometrics() -> Bool {
        // Import LocalAuthentication would be needed for full check
        // Simplified version
        return checkSecureEnclave()  // If has Secure Enclave, likely has biometrics
    }
    
    private nonisolated func getDeviceModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let modelCode = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(validatingCString: $0)
            }
        }
        return modelCode ?? "Unknown"
    }
    
    private func getSuspiciousFiles() -> [String] {
        var found: [String] = []
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/sbin/sshd",
            "/etc/apt"
        ]
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                found.append(path)
            }
        }
        
        return found
    }
    
    private func getSuspiciousLibraries() -> [String] {
        var found: [String] = []
        let suspiciousLibraries = ["MobileSubstrate", "cynject", "frida"]
        
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                for suspicious in suspiciousLibraries {
                    if name.contains(suspicious) && !found.contains(name) {
                        found.append(name)
                    }
                }
            }
        }
        
        return found
    }
    
    // MARK: - Integrity Check
    
    /// Check application integrity
    func checkIntegrity() -> IntegrityStatus {
        // Check if app binary has been modified
        if checkBinaryIntegrity() {
            return .modified
        }
        
        // Check for code injection
        if checkCodeInjection() {
            return .modified
        }
        
        return .intact
    }
    
    private func checkBinaryIntegrity() -> Bool {
        // Check if __RESTRICT section exists (indicates unmodified binary)
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                if name.contains(Bundle.main.bundleIdentifier ?? "") {
                    // Check for __RESTRICT,__restrict section
                    // let header = _dyld_get_image_header(i)
                    // Simplified check - implement full Mach-O parsing for production
                    return false
                }
            }
        }
        return false
    }
    
    private func checkCodeInjection() -> Bool {
        // Check for injected dylibs
        let mainExecutablePath = Bundle.main.executablePath ?? ""
        for i in 0..<_dyld_image_count() {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                // Check if any loaded library is not from system or app bundle
                if !name.hasPrefix("/System/") &&
                   !name.hasPrefix("/usr/lib/") &&
                   !name.hasPrefix(mainExecutablePath) &&
                   !name.contains(Bundle.main.bundlePath) {
                    return true
                }
            }
        }
        return false
    }
    
    // MARK: - Security Operations
    
    /// Clear sensitive data from memory
    func clearSensitiveMemory() {
        // This is a placeholder - actual implementation would:
        // 1. Overwrite sensitive memory regions
        // 2. Clear any cached credentials
        // 3. Force garbage collection if possible
        
        // Clear URLCache
        URLCache.shared.removeAllCachedResponses()
        
        // Clear image cache if using one
        // Clear any in-memory caches
        
        // Note: Swift's ARC makes explicit memory clearing challenging
        // Consider using SecureString wrapper for sensitive data
    }
    
    /// Calculate overall security score
    func calculateSecurityScore() -> Int {
        var score = 100
        
        if isJailbroken() {
            score -= 50
        }
        
        if isDebuggerAttached() {
            score -= 30
        }
        
        if isSimulator() {
            score -= 10
        }
        
        if !checkSecureEnclave() {
            score -= 10
        }
        
        if !checkBiometrics() {
            score -= 5
        }
        
        if checkIntegrity() != .intact {
            score -= 20
        }
        
        return max(0, score)
    }
}
