# YeboID for Swift

Native iOS 13+ and macOS 10.15+ sign-in through `ASWebAuthenticationSession`, S256 PKCE, exact callback/state validation and Keychain token storage. No third-party dependencies or native client secrets. Read [AGENTS.md](AGENTS.md).

## Swift Package Manager

In Xcode, add `https://github.com/omegathesecond/yeboid-swift` with version `0.1.0`. Add the `YeboID` library to your app target. Or in Package.swift:

```swift
.package(url: "https://github.com/omegathesecond/yeboid-swift", from: "0.1.0")
// target dependencies: .product(name: "YeboID", package: "yeboid-swift")
```

Register `com.yourcompany.yourapp://oauth/callback` exactly in [Developer Apps](https://yeboid.com/developer/apps), then add `com.yourcompany.yourapp` in the app's URL Types (`CFBundleURLSchemes`). This SDK supports custom-scheme callbacks; it intentionally rejects HTTP/HTTPS callbacks. It does not implement tvOS device authorization or watchOS login.

## Sign in

```swift
import YeboID
import AuthenticationServices

@MainActor final class LoginCoordinator: NSObject, ASWebAuthenticationPresentationContextProviding {
    let identity: YeboID
    private let window: ASPresentationAnchor

    init(window: ASPresentationAnchor) throws {
        self.window = window
        identity = try YeboID(clientID: "YOUR_PUBLIC_CLIENT_ID",
            redirectURI: URL(string: "com.yourcompany.yourapp://oauth/callback")!)
    }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { window }
    func signIn() async throws -> String {
        _ = try await identity.signIn(presentationContext: self)
        let user = try await identity.userInfo()
        guard let sub = user["sub"] as? String else { throw YeboIDError("invalid_userinfo") }
        return sub
    }
}
```

Keep the coordinator and client alive for the app session. Show thrown errors through the app's error UI, including user cancellation, Keychain errors and offline requests. Do not replace failed login with an invented user. Discovery supplies the correct hosted login and API endpoints; do not build the login endpoint by appending to the issuer.

Defaults request `openid profile offline_access`. Add a scope only after registering it for your client and obtaining fresh user consent. `tokens.grantedScopes` reflects the token response. Fetch identity from `userInfo()`; only persist `sub` as `yeboid_user_id` in product DBs. Never authorize an API using `idToken`.

## Restore, refresh, sign out

```swift
if let tokens = try coordinator.identity.tokens() {
    // Use tokens.accessToken as the Bearer token on your product API.
    // If expiresAt is reached, explicitly refresh before the next request.
}
let rotated = try await coordinator.identity.refresh()
try await coordinator.identity.signOut()
```

Keychain saves the rotated token before refresh returns. Mutating operations are exclusive; overlapping operations throw `operation_in_progress` so callers cannot reuse one refresh token concurrently. Keep one instance per issuer/client; do not share the store with an extension or another process without external coordination. Refresh is never retried automatically. If rotation succeeded but transport/storage failed, require fresh sign-in instead of replaying an uncertain refresh token.

`signOut()` revokes the app's refresh token before clearing Keychain. An error preserves local state and must be shown. This does not clear the system browser's SSO cookie or blacklist access JWTs already issued. Protect your API with server-side audience/purpose/scope checks and introspection when current revocation matters.

For app-specific storage policies, implement `YeboIDTokenStore`; all persistence methods must throw on failure. The default Keychain account includes issuer/client, and access is limited to the unlocked device. Never substitute UserDefaults or plaintext storage.

```sh
swift test
```

Automated tests cover PKCE, callback validation, rotation, outage and storage errors. They do not certify real device login or app approval.
