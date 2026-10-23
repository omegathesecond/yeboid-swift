import XCTest
@testable import YeboID

@MainActor final class MemoryStore: YeboIDTokenStore {
    var value: YeboIDTokens?
    var failSave = false
    func load() -> YeboIDTokens? { value }
    func save(_ tokens: YeboIDTokens) throws {
        if failSave { throw YeboIDError("storage_failed") }
        value = tokens
    }
    func clear() { value = nil }
}

final class YeboIDTests: XCTestCase {
    func testPKCEVector() {
        XCTAssertEqual(YeboID.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }
    func testCallbackValidation() throws {
        let redirect = URL(string: "com.example.app://oauth/callback")!
        XCTAssertEqual(try YeboID.callbackCode(URL(string: "com.example.app://oauth/callback?code=ok&state=expected")!, redirect: redirect, state: "expected"), "ok")
        for value in ["com.other://oauth/callback?code=x&state=expected", "com.example.app://oauth/callback?code=x&state=wrong",
                      "com.example.app://oauth/callback?code=x&code=y&state=expected", "com.example.app://oauth/callback?error=access_denied&state=expected"] {
            XCTAssertThrowsError(try YeboID.callbackCode(URL(string: value)!, redirect: redirect, state: "expected"))
        }
    }
    @MainActor func testRefreshRotationAndFailure() async throws {
        let store = MemoryStore()
        store.value = YeboIDTokens(accessToken: "old-access", refreshToken: "old-refresh", idToken: nil, scope: "openid", expiresAt: Date())
        var failure = false
        var forms: [String] = []
        let client = try YeboID(clientID: "app", redirectURI: URL(string: "com.example://callback")!, store: store) { request in
            let url = request.url!
            var payload: String
            if url.path.contains("openid-configuration") {
                payload = """
                {"issuer":"https://api.yeboid.com","authorization_endpoint":"https://yeboid.com/oauth/authorize","token_endpoint":"https://api.yeboid.com/oauth/token","userinfo_endpoint":"https://api.yeboid.com/oauth/userinfo","revocation_endpoint":"https://api.yeboid.com/oauth/revoke","scopes_supported":["openid","profile","offline_access"],"code_challenge_methods_supported":["S256"]}
                """
            } else {
                forms.append(String(data: request.httpBody!, encoding: .utf8)!)
                payload = """
                {"access_token":"new-access","refresh_token":"new-refresh","expires_in":900,"token_type":"Bearer","scope":"openid"}
                """
            }
            return (Data(payload.utf8), HTTPURLResponse(url: url, statusCode: failure ? 503 : 200, httpVersion: nil, headerFields: nil)!)
        }
        let refreshed = try await client.refresh()
        XCTAssertEqual(refreshed.refreshToken, "new-refresh")
        XCTAssertEqual(store.value?.scope, "openid")
        XCTAssertTrue(forms[0].contains("refresh_token=old-refresh"))
        XCTAssertFalse(forms[0].contains("scope="))
        failure = true
        do { try await client.signOut(); XCTFail("outage must throw") } catch {}
        XCTAssertNotNil(store.value)
        failure = false
        store.failSave = true
        do { _ = try await client.refresh(); XCTFail("storage failure must throw") } catch {}
    }
}
