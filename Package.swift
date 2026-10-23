// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "YeboID",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [.library(name: "YeboID", targets: ["YeboID"])],
    targets: [.target(name: "YeboID"), .testTarget(name: "YeboIDTests", dependencies: ["YeboID"])]
)
