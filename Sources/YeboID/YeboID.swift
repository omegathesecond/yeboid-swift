import Foundation
import AuthenticationServices
import CryptoKit
import Security

public struct YeboIDError: Error, LocalizedError {
    public let code: String
    public let status: Int?
    public var errorDescription: String? { "YeboID: \(code)" }
    public init(_ code: String, status: Int? = nil) { self.code = code; self.status = status }
}

public struct YeboIDTokens: Codable {
    public let accessToken: String
    public let refreshToken: String?
    /// Identity is read from userinfo. Never use this ID token as an API credential.
    public let idToken: String?
    public let scope: String
    public let expiresAt: Date
    public var grantedScopes: Set<String> { Set(scope.split(separator: " ").map(String.init)) }
}

@MainActor public protocol YeboIDTokenStore {
    func load() throws -> YeboIDTokens?
    func save(_ tokens: YeboIDTokens) throws
    func clear() throws
}

/// Use a different account per issuer/client. Keychain failures always throw.
@MainActor public final class YeboIDKeychainStore: YeboIDTokenStore {
    private let account: String
    public init(account: String) { self.account = account }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.yeboid.tokens", kSecAttrAccount as String: account]
    }
    public func load() throws -> YeboIDTokens? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw YeboIDError("keychain_read", status: Int(status)) }
        return try JSONDecoder().decode(YeboIDTokens.self, from: data)
    }
    public func save(_ tokens: YeboIDTokens) throws {
        let value = try JSONEncoder().encode(tokens)
        let attributes: [String: Any] = [kSecValueData as String: value, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw YeboIDError("keychain_write", status: Int(status)) }
    }
    public func clear() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw YeboIDError("keychain_delete", status: Int(status)) }
    }
}

private final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private struct Discovery: Decodable {
    let issuer: String
    let authorization_endpoint: URL
    let token_endpoint: URL
    let userinfo_endpoint: URL
    let revocation_endpoint: URL
    let scopes_supported: [String]
    let code_challenge_methods_supported: [String]
}

@MainActor public final class YeboID {
    nonisolated public static let defaultScopes = ["openid", "profile", "offline_access"]
    public typealias Transport = (URLRequest) async throws -> (Data, HTTPURLResponse)
    private let clientID: String
    private let redirectURI: URL
    private let issuer: URL
    private let scopes: [String]
    private let store: YeboIDTokenStore
    private let transport: Transport
    private var metadata: Discovery?
    private var webSession: ASWebAuthenticationSession?
    private var busy = false

    /// Custom-scheme callback must be registered exactly. No client secret is accepted by this native SDK.
    public init(clientID: String, redirectURI: URL, issuer: URL = URL(string: "https://api.yeboid.com")!,
                scopes: [String] = YeboID.defaultScopes, store: YeboIDTokenStore? = nil, transport: Transport? = nil) throws {
        guard !clientID.isEmpty, Self.secure(issuer), issuer.query == nil, issuer.path.isEmpty || issuer.path == "/" else { throw YeboIDError("invalid_issuer") }
        guard let scheme = redirectURI.scheme, !["http", "https"].contains(scheme.lowercased()),
              redirectURI.query == nil, redirectURI.fragment == nil, redirectURI.user == nil, redirectURI.password == nil else { throw YeboIDError("invalid_native_callback") }
        guard scopes.contains("openid"), scopes.allSatisfy({ !$0.isEmpty && $0.rangeOfCharacter(from: .whitespacesAndNewlines) == nil }) else { throw YeboIDError("invalid_scope") }
        self.clientID = clientID; self.redirectURI = redirectURI; self.issuer = issuer; self.scopes = scopes
        self.store = store ?? YeboIDKeychainStore(account: issuer.absoluteString + "|" + clientID)
        if let transport = transport { self.transport = transport }
        else {
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 10
            config.timeoutIntervalForResource = 20
            let session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
            self.transport = { request in
                // Completion API keeps iOS 13/macOS 10.15 support.
                try await withCheckedThrowingContinuation { continuation in
                    session.dataTask(with: request) { data, response, error in
                        if let error = error { continuation.resume(throwing: error); return }
                        guard let data = data, let response = response as? HTTPURLResponse else {
                            continuation.resume(throwing: YeboIDError("invalid_response")); return
                        }
                        continuation.resume(returning: (data, response))
                    }.resume()
                }
            }
        }
    }

    nonisolated private static func secure(_ url: URL) -> Bool {
        url.scheme == "https" && url.host != nil && url.user == nil && url.password == nil && url.fragment == nil
    }
    private func request(_ url: URL, form: [String: String]? = nil, token: String? = nil) async throws -> Data {
        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let form = form {
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            request.httpBody = Self.form(form).data(using: .utf8)
        }
        if let token = token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await transport(request)
        guard (200..<300).contains(response.statusCode) else { throw YeboIDError("http_\(response.statusCode)", status: response.statusCode) }
        return data
    }
    nonisolated static func form(_ values: [String: String]) -> String {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return values.sorted { $0.key < $1.key }.map { key, value in
            key.addingPercentEncoding(withAllowedCharacters: allowed)! + "=" + value.addingPercentEncoding(withAllowedCharacters: allowed)!
        }.joined(separator: "&")
    }
    private func discovery() async throws -> Discovery {
        if let metadata = metadata { return metadata }
        let data = try await request(issuer.appendingPathComponent(".well-known/openid-configuration"))
        let d = try JSONDecoder().decode(Discovery.self, from: data)
        guard d.issuer.trimmingCharacters(in: CharacterSet(charactersIn: "/")) == issuer.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")),
              [d.authorization_endpoint, d.token_endpoint, d.userinfo_endpoint, d.revocation_endpoint].allSatisfy(Self.secure),
              d.code_challenge_methods_supported.contains("S256") else { throw YeboIDError("invalid_discovery") }
        guard Set(scopes).isSubset(of: Set(d.scopes_supported)) else { throw YeboIDError("invalid_scope") }
        metadata = d
        return d
    }
    public func checkRegistration() async throws {
        var path = URLComponents(url: issuer, resolvingAgainstBaseURL: false)!
        let encoded = clientID.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        path.percentEncodedPath = "/oauth/clients/\(encoded)/configuration"
        let data = try await request(path.url!)
        struct Configuration: Decodable { let client_id: String; let redirect_uris: [String]; let scopes: [String] }
        let config = try JSONDecoder().decode(Configuration.self, from: data)
        guard config.client_id == clientID, config.redirect_uris.contains(redirectURI.absoluteString) else { throw YeboIDError("invalid_registration") }
        guard Set(scopes).isSubset(of: Set(config.scopes)) else { throw YeboIDError("invalid_scope") }
    }
    nonisolated static func random() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw YeboIDError("random_failed") }
        return base64URL(Data(bytes))
    }
    nonisolated static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    nonisolated static func challenge(_ verifier: String) -> String { base64URL(Data(SHA256.hash(data: Data(verifier.utf8)))) }
    nonisolated static func callbackCode(_ url: URL, redirect: URL, state: String) throws -> String {
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false), parts.fragment == nil else { throw YeboIDError("invalid_callback") }
        let items = parts.queryItems ?? []
        parts.query = nil
        guard parts.url == redirect, items.filter({ $0.name == "state" }).count == 1,
              items.first(where: { $0.name == "state" })?.value == state else { throw YeboIDError("state_mismatch") }
        if items.contains(where: { $0.name == "error" }) { throw YeboIDError("authorization_denied") }
        guard items.filter({ $0.name == "code" }).count == 1, let code = items.first(where: { $0.name == "code" })?.value, !code.isEmpty else { throw YeboIDError("missing_code") }
        return code
    }

    public func signIn(presentationContext: ASWebAuthenticationPresentationContextProviding) async throws -> YeboIDTokens {
        guard !busy else { throw YeboIDError("operation_in_progress") }
        busy = true
        defer { busy = false; webSession = nil }
        try await checkRegistration()
        let d = try await discovery()
        let verifier = try Self.random(), state = try Self.random()
        var url = URLComponents(url: d.authorization_endpoint, resolvingAgainstBaseURL: false)!
        url.queryItems = (url.queryItems ?? []) + ["response_type": "code", "client_id": clientID, "redirect_uri": redirectURI.absoluteString,
            "scope": scopes.joined(separator: " "), "state": state, "code_challenge": Self.challenge(verifier), "code_challenge_method": "S256"].map { URLQueryItem(name: $0.key, value: $0.value) }
        let callback: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(url: url.url!, callbackURLScheme: redirectURI.scheme) { callback, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let callback = callback { continuation.resume(returning: callback) }
                else { continuation.resume(throwing: YeboIDError("missing_callback")) }
            }
            session.presentationContextProvider = presentationContext
            webSession = session
            if !session.start() { continuation.resume(throwing: YeboIDError("browser_start_failed")) }
        }
        let code = try Self.callbackCode(callback, redirect: redirectURI, state: state)
        return try await exchange(["grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI.absoluteString, "code_verifier": verifier], endpoint: d.token_endpoint)
    }

    private struct TokenResponse: Decodable {
        let access_token: String; let refresh_token: String?; let id_token: String?
        let token_type: String; let expires_in: Double; let scope: String
    }
    private func exchange(_ form: [String: String], endpoint: URL) async throws -> YeboIDTokens {
        let data = try await request(endpoint, form: form.merging(["client_id": clientID]) { _, new in new })
        let response = try JSONDecoder().decode(TokenResponse.self, from: data)
        guard !response.access_token.isEmpty, response.token_type.lowercased() == "bearer", response.expires_in.isFinite, response.expires_in > 0,
              form["grant_type"] != "refresh_token" || !(response.refresh_token ?? "").isEmpty else { throw YeboIDError("invalid_token_response") }
        let tokens = YeboIDTokens(accessToken: response.access_token, refreshToken: response.refresh_token, idToken: response.id_token,
                                  scope: response.scope, expiresAt: Date().addingTimeInterval(response.expires_in))
        try store.save(tokens)
        return tokens
    }
    public func tokens() throws -> YeboIDTokens? { try store.load() }
    public func refresh() async throws -> YeboIDTokens {
        guard !busy else { throw YeboIDError("operation_in_progress") }
        busy = true; defer { busy = false }
        guard let token = try store.load()?.refreshToken, !token.isEmpty else { throw YeboIDError("login_required") }
        let d = try await discovery()
        return try await exchange(["grant_type": "refresh_token", "refresh_token": token], endpoint: d.token_endpoint)
    }
    public func userInfo() async throws -> [String: Any] {
        guard let tokens = try store.load(), tokens.expiresAt > Date() else { throw YeboIDError("login_required") }
        let d = try await discovery()
        let data = try await request(d.userinfo_endpoint, token: tokens.accessToken)
        guard let user = try JSONSerialization.jsonObject(with: data) as? [String: Any], let sub = user["sub"] as? String, !sub.isEmpty else { throw YeboIDError("invalid_userinfo") }
        return user
    }
    /// Revokes this app's refresh token. The shared browser SSO session remains.
    public func signOut() async throws {
        guard !busy else { throw YeboIDError("operation_in_progress") }
        busy = true; defer { busy = false }
        if let token = try store.load()?.refreshToken {
            let d = try await discovery()
            _ = try await request(d.revocation_endpoint, form: ["client_id": clientID, "token": token, "token_type_hint": "refresh_token"])
        }
        try store.clear()
    }
}
