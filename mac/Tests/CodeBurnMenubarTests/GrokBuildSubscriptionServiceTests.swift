import Foundation
import Testing
@testable import CodeBurnMenubar

@Suite("Grok Build subscription service")
@MainActor
struct GrokBuildSubscriptionServiceTests {
    @Test("Grok Build credential discovery prefers the current OIDC login")
    func prefersOIDCCredential() throws {
        let data = Data(#"""
        {
          "https://accounts.x.ai/sign-in": {
            "key": "synthetic-legacy-token",
            "expires_at": "2026-09-08T10:00:00Z"
          },
          "https://auth.x.ai::synthetic-principal": {
            "key": "synthetic-oidc-token",
            "refresh_token": "synthetic-refresh-token",
            "auth_mode": "oidc",
            "expires_at": "2026-09-09T10:00:00Z",
            "oidc_issuer": "https://auth.x.ai",
            "oidc_client_id": "synthetic-client"
          }
        }
        """#.utf8)

        let credential = try GrokBuildCredentialStore.decode(data)

        #expect(credential.accessToken == "synthetic-oidc-token")
        #expect(credential.refreshToken == "synthetic-refresh-token")
        #expect(credential.authMode == "oidc")
        #expect(credential.oidcIssuer == "https://auth.x.ai")
        #expect(credential.oidcClientId == "synthetic-client")
        #expect(credential.scope == "https://auth.x.ai::synthetic-principal")
        #expect(credential.expiresAt == ISO8601DateFormatter().date(from: "2026-09-09T10:00:00Z"))
        #expect(credential.canRefresh)
    }

    @Test("one refresh reuses Grok Build login for quota and plan")
    func refreshesWithExistingLogin() async throws {
        let requests = RequestCapture()
        let credential = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-oidc-token",
            refreshToken: "synthetic-refresh-token",
            authMode: "oidc",
            expiresAt: ISO8601DateFormatter().date(from: "2026-09-09T10:00:00Z"),
            oidcIssuer: "https://auth.x.ai",
            oidcClientId: "synthetic-client",
            scope: "https://auth.x.ai::synthetic-principal"
        )
        let deps = GrokBuildSubscriptionService.Deps(
            loadCredential: { credential },
            fetch: { request in
                await requests.record(request)
                let body: String
                switch request.url?.path {
                case "/v1/billing":
                    body = #"""
                    {"config":{"creditUsagePercent":2,"currentPeriod":{"end":"2026-09-06T17:52:03Z"}}}
                    """#
                case "/v1/settings":
                    body = #"{"subscription_tier_display":"SuperGrok Heavy"}"#
                default:
                    Issue.record("Unexpected Grok endpoint")
                    body = "{}"
                }
                return (
                    Data(body.utf8),
                    HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                )
            }
        )

        let result = try await GrokBuildSubscriptionService.refresh(
            deps: deps,
            now: ISO8601DateFormatter().date(from: "2026-09-01T10:00:00Z")!
        )
        let captured = await requests.values

        #expect(result.connection == .connected)
        #expect(result.primary?.label == "Weekly")
        #expect(result.primary?.percent == 0.02)
        #expect(result.primary?.resetsAt == ISO8601DateFormatter().date(from: "2026-09-06T17:52:03Z"))
        #expect(result.planLabel == "SuperGrok Heavy")
        #expect(result.footerLines == ["Source: Grok Build"])
        #expect(captured.map(\.url?.path) == ["/v1/billing", "/v1/settings"])
        #expect(captured.allSatisfy {
            $0.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-oidc-token"
                && $0.value(forHTTPHeaderField: "x-xai-token-auth") == "xai-grok-cli"
        })
    }

    @Test("missing and expired Grok Build logins never reach the network")
    func rejectsUnavailableLoginBeforeFetching() async throws {
        let requests = RequestCapture()
        let fetch: @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse) = { request in
            await requests.record(request)
            return (
                Data("{}".utf8),
                HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            )
        }
        let now = ISO8601DateFormatter().date(from: "2026-09-01T10:00:00Z")!

        do {
            _ = try await GrokBuildSubscriptionService.refresh(
                deps: .init(loadCredential: { nil }, fetch: fetch),
                now: now
            )
            Issue.record("Expected a missing-login failure")
        } catch let error as GrokBuildSubscriptionService.FetchError {
            #expect(error == .noCredentials)
        }

        let expired = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-expired-token",
            authMode: "oidc",
            expiresAt: now.addingTimeInterval(-1)
        )
        do {
            _ = try await GrokBuildSubscriptionService.refresh(
                deps: .init(loadCredential: { expired }, fetch: fetch),
                now: now
            )
            Issue.record("Expected an expired-login failure")
        } catch let error as GrokBuildSubscriptionService.FetchError {
            #expect(error == .expiredSession)
        }

        #expect(await requests.values.isEmpty)
    }

    @Test("an expired OIDC login refreshes silently and then fetches quota")
    func refreshesExpiredOIDCLoginBeforeBilling() async throws {
        let requests = RequestCapture()
        let persisted = PersistCapture()
        let now = ISO8601DateFormatter().date(from: "2026-09-05T17:00:00Z")!
        let expired = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-expired-token",
            refreshToken: "synthetic-refresh-token",
            authMode: "oidc",
            expiresAt: now.addingTimeInterval(-60),
            oidcIssuer: "https://auth.x.ai",
            oidcClientId: "synthetic-client",
            scope: "https://auth.x.ai::synthetic-principal"
        )
        let deps = GrokBuildSubscriptionService.Deps(
            loadCredential: { expired },
            fetch: { request in
                await requests.record(request)
                let body: String
                switch (request.httpMethod, request.url?.path) {
                case ("GET", "/.well-known/openid-configuration"):
                    body = #"{"token_endpoint":"https://auth.x.ai/oauth2/token"}"#
                case ("POST", "/oauth2/token"):
                    #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
                    let posted = String(data: request.httpBody ?? Data(), encoding: .utf8) ?? ""
                    #expect(posted.contains("grant_type=refresh_token"))
                    #expect(posted.contains("refresh_token=synthetic-refresh-token"))
                    #expect(posted.contains("client_id=synthetic-client"))
                    body = #"{"access_token":"synthetic-fresh-token","refresh_token":"synthetic-rotated-refresh","expires_in":21600}"#
                case ("GET", "/v1/billing"):
                    #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-fresh-token")
                    body = #"{"config":{"creditUsagePercent":1,"currentPeriod":{"end":"2026-09-09T19:53:44Z"}}}"#
                case ("GET", "/v1/settings"):
                    body = #"{"subscription_tier_display":"SuperGrok Heavy"}"#
                default:
                    Issue.record("Unexpected Grok endpoint \(request.httpMethod ?? "") \(request.url?.absoluteString ?? "")")
                    body = "{}"
                }
                return (
                    Data(body.utf8),
                    HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                )
            },
            persistRefreshed: { tokens in
                persisted.record(tokens)
            }
        )

        let result = try await GrokBuildSubscriptionService.refresh(deps: deps, now: now)
        let captured = await requests.values
        let stored = persisted.values

        #expect(result.connection == .connected)
        #expect(result.primary?.percent == 0.01)
        #expect(result.planLabel == "SuperGrok Heavy")
        #expect(captured.map(\.url?.path) == [
            "/.well-known/openid-configuration",
            "/oauth2/token",
            "/v1/billing",
            "/v1/settings",
        ])
        #expect(stored.count == 1)
        #expect(stored.first?.accessToken == "synthetic-fresh-token")
        #expect(stored.first?.refreshToken == "synthetic-rotated-refresh")
        #expect(stored.first?.scope == "https://auth.x.ai::synthetic-principal")
    }

    @Test("a rejected refresh token stays a terminal login failure")
    func rejectedRefreshDoesNotFetchBilling() async throws {
        let requests = RequestCapture()
        let now = ISO8601DateFormatter().date(from: "2026-09-05T17:00:00Z")!
        let expired = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-expired-token",
            refreshToken: "synthetic-refresh-token",
            authMode: "oidc",
            expiresAt: now.addingTimeInterval(-60),
            oidcIssuer: "https://auth.x.ai",
            oidcClientId: "synthetic-client",
            scope: "https://auth.x.ai::synthetic-principal"
        )
        do {
            _ = try await GrokBuildSubscriptionService.refresh(
                deps: .init(
                    loadCredential: { expired },
                    fetch: { request in
                        await requests.record(request)
                        let status = request.url?.path == "/oauth2/token" ? 400 : 200
                        let body = request.url?.path == "/.well-known/openid-configuration"
                            ? #"{"token_endpoint":"https://auth.x.ai/oauth2/token"}"#
                            : #"{"error":"invalid_grant"}"#
                        return (
                            Data(body.utf8),
                            HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
                        )
                    }
                ),
                now: now
            )
            Issue.record("Expected an expired-login failure")
        } catch let error as GrokBuildSubscriptionService.FetchError {
            #expect(error == .expiredSession)
        }
        let paths = await requests.values.map(\.url?.path)
        #expect(paths.contains("/oauth2/token"))
        #expect(!paths.contains("/v1/billing"))
    }

    @Test("OIDC refresh writes the rotated grant back into Grok auth.json")
    func persistRefreshedPreservesOtherFields() throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("codeburn-grok-refresh-\(UUID().uuidString)", isDirectory: true)
        let grokHome = home.appendingPathComponent(".grok", isDirectory: true)
        try FileManager.default.createDirectory(at: grokHome, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }

        let original = Data(#"""
        {
          "https://auth.x.ai::synthetic-principal": {
            "auth_mode": "oidc",
            "email": "user@example.com",
            "expires_at": "2026-09-05T00:00:00Z",
            "key": "synthetic-expired-token",
            "oidc_client_id": "synthetic-client",
            "oidc_issuer": "https://auth.x.ai",
            "refresh_token": "synthetic-refresh-token",
            "team_id": "keep-me"
          }
        }
        """#.utf8)
        try original.write(to: grokHome.appendingPathComponent("auth.json"))

        let expires = ISO8601DateFormatter().date(from: "2026-09-05T23:00:00Z")!
        try GrokBuildCredentialStore.persistRefreshed(
            .init(
                scope: "https://auth.x.ai::synthetic-principal",
                accessToken: "synthetic-fresh-token",
                refreshToken: "synthetic-rotated-refresh",
                expiresAt: expires
            ),
            environment: ["GROK_HOME": grokHome.path],
            home: home
        )

        let reloaded = try GrokBuildCredentialStore.load(
            environment: ["GROK_HOME": grokHome.path],
            home: home
        )
        #expect(reloaded?.accessToken == "synthetic-fresh-token")
        #expect(reloaded?.refreshToken == "synthetic-rotated-refresh")
        #expect(abs((reloaded?.expiresAt?.timeIntervalSince(expires) ?? 999)) < 1)
        #expect(reloaded?.oidcClientId == "synthetic-client")

        let raw = try JSONSerialization.jsonObject(
            with: Data(contentsOf: grokHome.appendingPathComponent("auth.json"))
        ) as? [String: Any]
        let entry = raw?["https://auth.x.ai::synthetic-principal"] as? [String: Any]
        #expect(entry?["email"] as? String == "user@example.com")
        #expect(entry?["team_id"] as? String == "keep-me")
    }

    @Test("a still-valid token near expiry is refreshed before billing")
    func refreshesNearExpiryBeforeBilling() async throws {
        let requests = RequestCapture()
        let now = ISO8601DateFormatter().date(from: "2026-09-05T17:00:00Z")!
        let soon = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-aging-token",
            refreshToken: "synthetic-refresh-token",
            authMode: "oidc",
            expiresAt: now.addingTimeInterval(4 * 60),
            oidcIssuer: "https://auth.x.ai",
            oidcClientId: "synthetic-client",
            scope: "https://auth.x.ai::synthetic-principal"
        )
        let result = try await GrokBuildSubscriptionService.refresh(
            deps: .init(
                loadCredential: { soon },
                fetch: { request in
                    await requests.record(request)
                    let body: String
                    switch request.url?.path {
                    case "/.well-known/openid-configuration":
                        body = #"{"token_endpoint":"https://auth.x.ai/oauth2/token"}"#
                    case "/oauth2/token":
                        body = #"{"access_token":"synthetic-fresh-token","expires_in":21600}"#
                    case "/v1/billing":
                        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-fresh-token")
                        body = #"{"config":{"creditUsagePercent":3,"currentPeriod":{"end":"2026-09-09T19:53:44Z"}}}"#
                    case "/v1/settings":
                        body = #"{"subscription_tier_display":"SuperGrok Heavy"}"#
                    default:
                        Issue.record("Unexpected Grok endpoint")
                        body = "{}"
                    }
                    return (
                        Data(body.utf8),
                        HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                    )
                }
            ),
            now: now
        )
        let paths = await requests.values.map(\.url?.path)
        #expect(result.primary?.percent == 0.03)
        #expect(paths.contains("/oauth2/token"))
        #expect(paths.contains("/v1/billing"))
    }

    @Test("a persist failure still uses the in-memory refreshed token")
    func persistFailureDoesNotDropRefreshedSession() async throws {
        let now = ISO8601DateFormatter().date(from: "2026-09-05T17:00:00Z")!
        let expired = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-expired-token",
            refreshToken: "synthetic-refresh-token",
            authMode: "oidc",
            expiresAt: now.addingTimeInterval(-60),
            oidcIssuer: "https://auth.x.ai",
            oidcClientId: "synthetic-client",
            scope: "https://auth.x.ai::synthetic-principal"
        )
        let result = try await GrokBuildSubscriptionService.refresh(
            deps: .init(
                loadCredential: { expired },
                fetch: { request in
                    let body: String
                    switch request.url?.path {
                    case "/.well-known/openid-configuration":
                        body = #"{"token_endpoint":"https://auth.x.ai/oauth2/token"}"#
                    case "/oauth2/token":
                        body = #"{"access_token":"synthetic-fresh-token","expires_in":21600}"#
                    case "/v1/billing":
                        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-fresh-token")
                        body = #"{"config":{"creditUsagePercent":4,"currentPeriod":{"end":"2026-09-09T19:53:44Z"}}}"#
                    case "/v1/settings":
                        body = "{}"
                    default:
                        Issue.record("Unexpected Grok endpoint")
                        body = "{}"
                    }
                    return (
                        Data(body.utf8),
                        HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                    )
                },
                persistRefreshed: { _ in
                    throw GrokBuildCredentialStore.ReadError.persistFailed
                }
            ),
            now: now
        )
        #expect(result.connection == .connected)
        #expect(result.primary?.percent == 0.04)
    }

    @Test("a 401 on billing retries once after a silent refresh")
    func retriesBillingAfterUnauthorizedThenRefresh() async throws {
        let requests = RequestCapture()
        let billingHits = HitCounter()
        let now = ISO8601DateFormatter().date(from: "2026-09-05T17:00:00Z")!
        let live = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-stale-token",
            refreshToken: "synthetic-refresh-token",
            authMode: "oidc",
            expiresAt: now.addingTimeInterval(3600),
            oidcIssuer: "https://auth.x.ai",
            oidcClientId: "synthetic-client",
            scope: "https://auth.x.ai::synthetic-principal"
        )
        let result = try await GrokBuildSubscriptionService.refresh(
            deps: .init(
                loadCredential: { live },
                fetch: { request in
                    await requests.record(request)
                    let path = request.url?.path
                    if path == "/v1/billing" {
                        let hit = await billingHits.next()
                        if hit == 1 {
                            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-stale-token")
                            return (
                                Data("{}".utf8),
                                HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!
                            )
                        }
                        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer synthetic-fresh-token")
                    }
                    let body: String
                    switch path {
                    case "/.well-known/openid-configuration":
                        body = #"{"token_endpoint":"https://auth.x.ai/oauth2/token"}"#
                    case "/oauth2/token":
                        body = #"{"access_token":"synthetic-fresh-token","expires_in":21600}"#
                    case "/v1/billing":
                        body = #"{"config":{"creditUsagePercent":5,"currentPeriod":{"end":"2026-09-09T19:53:44Z"}}}"#
                    case "/v1/settings":
                        body = #"{"subscription_tier_display":"SuperGrok Heavy"}"#
                    default:
                        Issue.record("Unexpected Grok endpoint")
                        body = "{}"
                    }
                    return (
                        Data(body.utf8),
                        HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                    )
                }
            ),
            now: now
        )
        let paths = await requests.values.map(\.url?.path)
        #expect(result.primary?.percent == 0.05)
        #expect(paths == [
            "/v1/billing",
            "/.well-known/openid-configuration",
            "/oauth2/token",
            "/v1/billing",
            "/v1/settings",
        ])
    }

    @Test("Grok billing failures retain actionable classifications")
    func classifiesBillingFailures() async throws {
        let credential = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-oidc-token",
            authMode: "oidc",
            expiresAt: nil
        )
        let cases: [(Int, GrokBuildSubscriptionService.FetchError)] = [
            (401, .authenticationRejected),
            (403, .authenticationRejected),
            (429, .rateLimited),
            (503, .providerUnavailable),
            (418, .parseFailure),
        ]

        for (status, expected) in cases {
            let deps = GrokBuildSubscriptionService.Deps(
                loadCredential: { credential },
                fetch: { request in
                    (
                        Data("{}".utf8),
                        HTTPURLResponse(
                            url: request.url!,
                            statusCode: status,
                            httpVersion: nil,
                            headerFields: nil
                        )!
                    )
                }
            )
            do {
                _ = try await GrokBuildSubscriptionService.refresh(deps: deps)
                Issue.record("Expected HTTP \(status) to fail")
            } catch let error as GrokBuildSubscriptionService.FetchError {
                #expect(error == expected)
            }
        }
    }

    @Test("on-demand billing is a safe fallback when percent is absent")
    func usesOnDemandFallback() async throws {
        let credential = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-oidc-token",
            authMode: "oidc",
            expiresAt: nil
        )
        let deps = GrokBuildSubscriptionService.Deps(
            loadCredential: { credential },
            fetch: { request in
                let body: String
                let status: Int
                if request.url?.path == "/v1/billing" {
                    body = #"{"config":{"onDemandUsed":{"val":25},"onDemandCap":{"val":100},"billingPeriodEnd":"2026-10-01T10:00:00Z","subscriptionTier":"supergrok"}}"#
                    status = 200
                } else {
                    body = "{}"
                    status = 503
                }
                return (
                    Data(body.utf8),
                    HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
                )
            }
        )

        let result = try await GrokBuildSubscriptionService.refresh(
            deps: deps,
            now: ISO8601DateFormatter().date(from: "2026-09-01T10:00:00Z")!
        )

        #expect(result.primary?.percent == 0.25)
        #expect(result.primary?.label == "Monthly")
        #expect(result.planLabel == "SuperGrok")
    }

    @Test("an active unified-billing window with no percent field is 0% used")
    func treatsOmittedPercentInActivePeriodAsZero() async throws {
        let credential = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-oidc-token",
            authMode: "oidc",
            expiresAt: nil
        )
        let deps = GrokBuildSubscriptionService.Deps(
            loadCredential: { credential },
            fetch: { request in
                let body: String
                switch request.url?.path {
                case "/v1/billing":
                    body = #"""
                    {"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"2026-09-02T19:53:44.968223+00:00","end":"2026-09-09T19:53:44.968223+00:00"},"onDemandCap":{"val":0},"onDemandUsed":{"val":0},"isUnifiedBillingUser":true,"prepaidBalance":{"val":0},"billingPeriodEnd":"2026-09-09T19:53:44.968223+00:00"}}
                    """#
                case "/v1/settings":
                    body = #"{"subscription_tier_display":"SuperGrok Heavy"}"#
                default:
                    Issue.record("Unexpected Grok endpoint")
                    body = "{}"
                }
                return (
                    Data(body.utf8),
                    HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                )
            }
        )

        let result = try await GrokBuildSubscriptionService.refresh(
            deps: deps,
            now: ISO8601DateFormatter().date(from: "2026-09-02T21:00:00Z")!
        )

        #expect(result.connection == .connected)
        #expect(result.primary?.percent == 0)
        #expect(result.primary?.label == "Weekly")
        #expect(result.primary?.resetsAt != nil)
        #expect(result.details.count == 1)
        #expect(result.planLabel == "SuperGrok Heavy")
        #expect(result.footerLines == ["Source: Grok Build"])
    }

    @Test("an expired unified-billing window without a percent is not invented as 0%")
    func doesNotInventZeroOutsideActivePeriod() async throws {
        let credential = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-oidc-token",
            authMode: "oidc",
            expiresAt: nil
        )
        let deps = GrokBuildSubscriptionService.Deps(
            loadCredential: { credential },
            fetch: { request in
                let body: String
                switch request.url?.path {
                case "/v1/billing":
                    body = #"""
                    {"config":{"currentPeriod":{"type":"USAGE_PERIOD_TYPE_WEEKLY","start":"2026-08-26T19:53:44.968223+00:00","end":"2026-09-02T19:53:44.968223+00:00"},"onDemandCap":{"val":0},"onDemandUsed":{"val":0},"isUnifiedBillingUser":true}}
                    """#
                case "/v1/settings":
                    body = #"{"subscription_tier_display":"SuperGrok Heavy"}"#
                default:
                    Issue.record("Unexpected Grok endpoint")
                    body = "{}"
                }
                return (
                    Data(body.utf8),
                    HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                )
            }
        )

        let result = try await GrokBuildSubscriptionService.refresh(
            deps: deps,
            now: ISO8601DateFormatter().date(from: "2026-09-02T21:00:00Z")!
        )

        #expect(result.connection == .connected)
        #expect(result.primary == nil)
        #expect(result.planLabel == "SuperGrok Heavy")
    }

    @Test("cancellation during the optional plan request cancels the refresh")
    func cancellationWinsDuringPlanFetch() async throws {
        let credential = GrokBuildCredentialStore.Credential(
            accessToken: "synthetic-oidc-token",
            authMode: "oidc",
            expiresAt: nil
        )
        let deps = GrokBuildSubscriptionService.Deps(
            loadCredential: { credential },
            fetch: { request in
                if request.url?.path == "/v1/settings" {
                    throw CancellationError()
                }
                return (
                    Data(#"{"config":{"creditUsagePercent":2}}"#.utf8),
                    HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                )
            }
        )

        await #expect(throws: CancellationError.self) {
            try await GrokBuildSubscriptionService.refresh(deps: deps)
        }
    }

    private actor RequestCapture {
        private(set) var values: [URLRequest] = []
        func record(_ request: URLRequest) { values.append(request) }
    }

    private final class PersistCapture: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: [GrokBuildCredentialStore.RefreshedTokens] = []

        func record(_ tokens: GrokBuildCredentialStore.RefreshedTokens) {
            lock.lock()
            stored.append(tokens)
            lock.unlock()
        }

        var values: [GrokBuildCredentialStore.RefreshedTokens] {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }
    }

    private actor HitCounter {
        private var count = 0
        func next() -> Int {
            count += 1
            return count
        }
    }
}
