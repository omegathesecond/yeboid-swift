# YeboID integration instructions for coding agents

Read README.md, https://docs.yeboid.com/platforms and https://docs.yeboid.com/ai-agents first.
Use the implementation for the existing stack. Do not generate React/Node for a native or Python app.
Register the exact callback and explicitly choose scopes in https://yeboid.com/developer/apps.
Use OIDC discovery at https://api.yeboid.com/.well-known/openid-configuration; the hosted authorization endpoint uses a different origin.
The SDK checks exact callbacks and requested scopes through /oauth/clients/{clientId}/configuration before sign-in. All preflight errors are visible; never bypass or silently replace them.
Defaults: openid profile offline_access. Permissions must be registered, requested, consented and enforced. Refresh cannot add permissions.
Humans perform identity verification and account consent. Never automate bypasses or invent a successful login.
Never embed a client secret in native/browser code. Never authorize APIs with an ID token or unverified JWT claims.
Use the actual granted scopes, then enforce resource ownership server-side. Store only sub as yeboid_user_id in product databases; fetch PII from userinfo.
Do not log tokens, authorization codes, PKCE verifiers, secrets or PII. Dependency/storage errors must reach the app's normal error channel.
Refresh tokens rotate: serialize per session and persist the new refresh token before another call. Never automatically retry a consumed token after a transport/storage failure; require fresh login if its state is uncertain.
App-session revocation does not clear the system-browser SSO cookie. Test and report those separately.
Verify cancellation/denial, wrong state/callback, missing scopes, rotation, outages, storage failures and logout. Report local checks, public artifacts, deployment and actual device login separately.

## Swift / iOS and macOS

Use ASWebAuthenticationSession and Keychain. Keep a single @MainActor YeboID instance and a presentation-context provider alive. Register a reverse-domain custom URL scheme; this SDK rejects HTTPS callbacks. Concurrent mutations throw operation_in_progress. UserInfo supplies identity; this SDK does not validate ID tokens for application use.

Validation: `swift test`.
