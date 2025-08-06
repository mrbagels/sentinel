// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "sentinel",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .tvOS(.v17),
        .watchOS(.v10)
    ],
    products: [
        // Main product that exports all libraries
        .library(
            name: "Sentinel",
            targets: ["KeychainAccess", "HardwareSecurity", "Cryptography", "DeviceSecurity"]
        ),
        // Individual products for selective import
        .library(
            name: "KeychainAccess",
            targets: ["KeychainAccess"]
        ),
        .library(
            name: "HardwareSecurity",
            targets: ["HardwareSecurity"]
        ),
        .library(
            name: "Cryptography",
            targets: ["Cryptography"]
        ),
        .library(
            name: "DeviceSecurity",
            targets: ["DeviceSecurity"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/pointfreeco/swift-dependencies", from: "1.9.3"),
        .package(url: "https://github.com/pointfreeco/swift-sharing", from: "2.6.0"),
    ],
    targets: [
        // KeychainAccess - Enhanced keychain operations
        .target(
            name: "KeychainAccess",
            dependencies: [
                .product(name: "Dependencies", package: "swift-dependencies"),
                .product(name: "DependenciesMacros", package: "swift-dependencies"),
                .product(name: "Sharing", package: "swift-sharing"),
            ],
            swiftSettings: swiftSettings
        ),
        
        // HardwareSecurity - Secure Enclave & Biometrics
        .target(
            name: "HardwareSecurity",
            dependencies: [
                .product(name: "Dependencies", package: "swift-dependencies"),
                .product(name: "DependenciesMacros", package: "swift-dependencies"),
            ],
            swiftSettings: swiftSettings
        ),
        
        // Cryptography - TOTP, key derivation, crypto utilities
        .target(
            name: "Cryptography",
            dependencies: [
                .product(name: "Dependencies", package: "swift-dependencies"),
                .product(name: "DependenciesMacros", package: "swift-dependencies"),
            ],
            swiftSettings: swiftSettings
        ),
        
        // DeviceSecurity - Jailbreak detection, secure memory
        .target(
            name: "DeviceSecurity",
            dependencies: [
                .product(name: "Dependencies", package: "swift-dependencies"),
                .product(name: "DependenciesMacros", package: "swift-dependencies"),
            ],
            swiftSettings: swiftSettings
        ),
        
        // Test targets
        .testTarget(
            name: "KeychainAccessTests",
            dependencies: ["KeychainAccess"],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "HardwareSecurityTests",
            dependencies: ["HardwareSecurity"],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CryptographyTests",
            dependencies: ["Cryptography"],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "DeviceSecurityTests",
            dependencies: ["DeviceSecurity"],
            swiftSettings: swiftSettings
        ),
    ]
)

/// Shared Swift settings for all targets
var swiftSettings: [SwiftSetting] {
    [
        .swiftLanguageMode(.v6),
        .enableExperimentalFeature("StrictConcurrency"),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("GlobalConcurrency"),
        .enableUpcomingFeature("IsolatedDefaultValues"),
        .define("DEBUG", .when(configuration: .debug)),
    ]
}
