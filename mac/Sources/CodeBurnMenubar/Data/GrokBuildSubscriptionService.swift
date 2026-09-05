import Foundation

/// Access to the login that Grok Build owns in `$GROK_HOME/auth.json`.
/// CodeBurn never copies the bearer into Keychain, UserDefaults, logs, or its
/// support directory. A successful OIDC refresh writes the rotated grant back
/// into that same Grok-owned file so the CLI and the dock stay on one session.
enum GrokBuildCredentialStore {
    static let refreshSkew: TimeInterval = 5 * 60

    struct Credential: Equatable, Sendable {
        let accessToken: String
        let refreshToken: String?
        let authMode: String?
        let expiresAt: Date?
        let oidcIssuer: String?
        let oidcClientId: String?
        let scope: String

        init(
            accessToken: String,
            refreshToken: String? = nil,
            authMode: String?,
            expiresAt: Date?,
            oidcIssuer: String? = nil,
            oidcClientId: String? = nil,
            scope: String = ""
        ) {
            self.accessToken = accessToken
            self.refreshToken = refreshToken
            self.authMode = authMode
            self.expiresAt = expiresAt
            self.oidcIssuer = oidcIssuer
            self.oidcClientId = oidcClientId
            self.scope = scope
        }

        func isExpired(at date: Date) -> Bool {
            guard let expiresAt else { return false }
            return expiresAt <= date
        }

        func needsRefresh(at date: Date, skew: TimeInterval = refreshSkew) -> Bool {
            guard let expiresAt else { return false }
            return expiresAt.addingTimeInterval(-skew) <= date
        }

        var canRefresh: Bool {
            GrokBuildCredentialStore.cleaned(refreshToken) != nil
                && GrokBuildCredentialStore.httpsURL(from: oidcIssuer) != nil
                && GrokBuildCredentialStore.cleaned(oidcClientId) != nil
        }
    }

    struct RefreshedTokens: Equatable, Sendable {
        let scope: String
        let accessToken: String
        let refreshToken: String?
        let expiresAt: Date
    }

    enum ReadError: Error, Equatable {
        case malformed
        case missingToken
        case persistFailed
    }

    private struct Entry: Decodable {
        let key: String?
        let refreshToken: String?
        let authMode: String?
        let expiresAt: String?
        let oidcIssuer: String?
        let oidcClientId: String?

        enum CodingKeys: String, CodingKey {
            case key
            case refreshToken = "refresh_token"
            case authMode = "auth_mode"
            case expiresAt = "expires_at"
            case oidcIssuer = "oidc_issuer"
            case oidcClientId = "oidc_client_id"
        }
    }

    static func load(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) throws -> Credential? {
        let authURL = authURL(environment: environment, home: home)
        guard FileManager.default.fileExists(atPath: authURL.path) else { return nil }
        return try decode(SafeFile.read(from: authURL.path, maxBytes: 128 * 1024))
    }

    static func decode(_ data: Data) throws -> Credential {
        let entries: [String: Entry]
        do {
            entries = try JSONDecoder().decode([String: Entry].self, from: data)
        } catch {
            throw ReadError.malformed
        }

        let usable = entries.compactMap { scope, entry -> (scope: String, entry: Entry, token: String)? in
            guard let token = cleaned(entry.key) else { return nil }
            return (scope, entry, token)
        }
        let selected = usable.sorted { lhs, rhs in
            let lhsRank = credentialRank(scope: lhs.scope)
            let rhsRank = credentialRank(scope: rhs.scope)
            return lhsRank == rhsRank ? lhs.scope < rhs.scope : lhsRank < rhsRank
        }.first
        guard let selected else { throw ReadError.missingToken }

        return Credential(
            accessToken: selected.token,
            refreshToken: cleaned(selected.entry.refreshToken),
            authMode: cleaned(selected.entry.authMode),
            expiresAt: parseDate(selected.entry.expiresAt),
            oidcIssuer: cleaned(selected.entry.oidcIssuer),
            oidcClientId: cleaned(selected.entry.oidcClientId),
            scope: selected.scope
        )
    }

    /// Atomic read-modify-write of Grok's `auth.json`. Preserves every other
    /// scope and every field on the selected entry; only `key`, `expires_at`,
    /// and a rotated `refresh_token` are rewritten.
    static func persistRefreshed(
        _ tokens: RefreshedTokens,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) throws {
        let authURL = authURL(environment: environment, home: home)
        let lockURL = authURL.deletingLastPathComponent().appendingPathComponent("auth.json.lock")
        try SafeFile.withExclusiveLock(at: lockURL.path) {
            let data = try SafeFile.read(from: authURL.path, maxBytes: 128 * 1024)
            guard var root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  var entry = root[tokens.scope] as? [String: Any]
            else {
                throw ReadError.persistFailed
            }
            entry["key"] = tokens.accessToken
            entry["expires_at"] = iso8601String(tokens.expiresAt)
            if let refresh = cleaned(tokens.refreshToken) {
                entry["refresh_token"] = refresh
            }
            root[tokens.scope] = entry
            guard let out = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]) else {
                throw ReadError.persistFailed
            }
            try SafeFile.write(out, to: authURL.path, mode: 0o600)
        }
    }

    private static func authURL(environment: [String: String], home: URL) -> URL {
        let grokHome: URL
        if let configured = cleaned(environment["GROK_HOME"]) {
            grokHome = URL(
                fileURLWithPath: (configured as NSString).expandingTildeInPath,
                isDirectory: true
            )
        } else {
            grokHome = home.appendingPathComponent(".grok", isDirectory: true)
        }
        return grokHome.appendingPathComponent("auth.json", isDirectory: false)
    }

    private static func credentialRank(scope: String) -> Int {
        if scope.hasPrefix("https://auth.x.ai::") { return 0 }
        if scope.contains("/sign-in") { return 1 }
        return 2
    }

    fileprivate static func cleaned(_ raw: String?) -> String? {
        guard let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else { return nil }
        return value
    }

    fileprivate static func httpsURL(from raw: String?) -> URL? {
        guard let value = cleaned(raw),
              let url = URL(string: value),
              url.scheme?.lowercased() == "https",
              url.host != nil,
              url.user == nil,
              url.password == nil
        else { return nil }
        return url
    }

    private static func parseDate(_ raw: String?) -> Date? {
        guard let raw = cleaned(raw) else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: raw) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: raw)
    }

    fileprivate static func iso8601String(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}

/// Live Grok Build subscription usage obtained with the OAuth login already
/// managed by the Grok CLI. Requests use an ephemeral, cookie-free session and
/// the bearer is released after each refresh.
enum GrokBuildSubscriptionService {
    static let billingURL = URL(string: "https://cli-chat-proxy.grok.com/v1/billing?format=credits")!
    static let settingsURL = URL(string: "https://cli-chat-proxy.grok.com/v1/settings")!
    private static let timeoutSeconds: TimeInterval = 15

    enum FetchError: Error, Equatable, LocalizedError, Sendable {
        case noCredentials
        case expiredSession
        case credentialDataUnreadable
        case authenticationRejected
        case rateLimited
        case providerUnavailable
        case parseFailure
        case network

        enum Classification: Equatable, Sendable {
            case terminalAuth
            case transient
            case parseFailure
        }

        var classification: Classification {
            switch self {
            case .noCredentials, .expiredSession, .credentialDataUnreadable, .authenticationRejected:
                .terminalAuth
            case .rateLimited, .providerUnavailable, .network:
                .transient
            case .parseFailure:
                .parseFailure
            }
        }

        var errorDescription: String? {
            switch self {
            case .noCredentials:
                "Run `grok login`, then click Retry."
            case .expiredSession:
                "The Grok Build login has expired. Run `grok login`, then click Retry."
            case .credentialDataUnreadable:
                "Could not read Grok Build's local login. Run `grok login` again, then click Retry."
            case .authenticationRejected:
                "Grok rejected the current Grok Build login. Run `grok login`, then click Retry."
            case .rateLimited:
                "Grok rate-limited the quota request."
            case .providerUnavailable:
                "Grok quota is temporarily unavailable."
            case .parseFailure:
                "Grok returned an unrecognized quota response."
            case .network:
                "Network error fetching Grok quota."
            }
        }
    }

    struct Deps: Sendable {
        var loadCredential: @Sendable () throws -> GrokBuildCredentialStore.Credential?
        var fetch: @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)
        var persistRefreshed: @Sendable (GrokBuildCredentialStore.RefreshedTokens) throws -> Void = { _ in }

        static let live = Deps(
            loadCredential: { try GrokBuildCredentialStore.load() },
            fetch: { request in
                let configuration = URLSessionConfiguration.ephemeral
                configuration.httpCookieStorage = nil
                configuration.httpShouldSetCookies = false
                configuration.urlCache = nil
                configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
                let session = URLSession(configuration: configuration)
                defer { session.invalidateAndCancel() }
                let (data, response) = try await session.data(for: request)
                guard let http = response as? HTTPURLResponse else { throw FetchError.network }
                return (data, http)
            },
            persistRefreshed: { try GrokBuildCredentialStore.persistRefreshed($0) }
        )
    }

    @MainActor
    static func refresh(deps: Deps = .live, now: Date = Date()) async throws -> QuotaSummary {
        let loadCredential = deps.loadCredential
        let loaded: GrokBuildCredentialStore.Credential
        do {
            guard let value = try await Task.detached(operation: loadCredential).value else {
                throw FetchError.noCredentials
            }
            loaded = value
        } catch let error as FetchError {
            throw error
        } catch let error as GrokBuildCredentialStore.ReadError {
            switch error {
            case .missingToken: throw FetchError.noCredentials
            case .malformed, .persistFailed: throw FetchError.credentialDataUnreadable
            }
        } catch {
            throw FetchError.credentialDataUnreadable
        }

        var credential = loaded
        var refreshedThisCycle = false
        if credential.needsRefresh(at: now) {
            credential = try await rotateSession(credential, deps: deps, now: now)
            refreshedThisCycle = credential.accessToken != loaded.accessToken
        }
        guard !credential.isExpired(at: now) else { throw FetchError.expiredSession }

        let billingData: Data
        do {
            billingData = try await fetchRequired(
                url: billingURL,
                credential: credential,
                deps: deps
            )
        } catch FetchError.authenticationRejected where !refreshedThisCycle && credential.canRefresh {
            credential = try await rotateSession(credential, deps: deps, now: now)
            guard !credential.isExpired(at: now) else { throw FetchError.expiredSession }
            billingData = try await fetchRequired(
                url: billingURL,
                credential: credential,
                deps: deps
            )
        }
        let billing = try decodeBilling(billingData, now: now)
        let settingsPlan = try await fetchPlan(credential: credential, deps: deps)
        let plan = normalizedPlan(settingsPlan) ?? normalizedPlan(billing.subscriptionTier)
        let window = billing.usedPercent.map { percent in
            QuotaSummary.Window(
                label: windowLabel(resetsAt: billing.resetsAt, now: now),
                percent: percent,
                resetsAt: billing.resetsAt
            )
        }
        return QuotaSummary(
            providerFilter: .grok,
            connection: .connected,
            primary: window,
            details: window.map { [$0] } ?? [],
            planLabel: plan,
            footerLines: ["Source: Grok Build"]
        )
    }

    private struct BillingSnapshot {
        let usedPercent: Double?
        let resetsAt: Date?
        let subscriptionTier: String?
    }

    private struct BillingEnvelope: Decodable {
        let config: BillingConfig?
        let subscriptionTier: String?
    }

    private struct BillingConfig: Decodable {
        let creditUsagePercent: Double?
        let currentPeriod: CurrentPeriod?
        let billingPeriodEnd: String?
        let onDemandCap: Amount?
        let onDemandUsed: Amount?
        let used: Amount?
        let monthlyLimit: Amount?
        let subscriptionTier: String?
        let isUnifiedBillingUser: Bool?
    }

    private struct CurrentPeriod: Decodable {
        let start: String?
        let end: String?
    }
    private struct Amount: Decodable { let val: Double? }
    private struct SettingsEnvelope: Decodable {
        let subscriptionTierDisplay: String?

        enum CodingKeys: String, CodingKey {
            case subscriptionTierDisplay = "subscription_tier_display"
        }
    }

    private static func decodeBilling(_ data: Data, now: Date) throws -> BillingSnapshot {
        let envelope: BillingEnvelope
        do {
            envelope = try JSONDecoder().decode(BillingEnvelope.self, from: data)
        } catch {
            throw FetchError.parseFailure
        }
        guard let config = envelope.config else { throw FetchError.parseFailure }

        let rawPercent: Double?
        if let percent = config.creditUsagePercent, percent.isFinite {
            rawPercent = percent
        } else if let used = config.onDemandUsed?.val,
                  let cap = config.onDemandCap?.val,
                  used.isFinite, cap.isFinite, used >= 0, cap > 0 {
            rawPercent = used / cap * 100
        } else if let used = config.used?.val,
                  let cap = config.monthlyLimit?.val,
                  used.isFinite, cap.isFinite, used >= 0, cap > 0 {
            rawPercent = used / cap * 100
        } else if config.isUnifiedBillingUser == true,
                  isActiveBillingPeriod(config.currentPeriod, now: now) {
            // Grok's web client and proto3 both treat an omitted
            // creditUsagePercent as 0 during an active window. After a weekly
            // reset the field is simply absent — that is 0% used, not unknown.
            // Only unified-billing accounts carry that contract; for anyone
            // else an omitted field stays unknown rather than a fabricated 0%.
            rawPercent = 0
        } else {
            rawPercent = nil
        }

        let reset = parseDate(config.currentPeriod?.end ?? config.billingPeriodEnd)
        if rawPercent == nil, reset == nil, config.isUnifiedBillingUser != true {
            throw FetchError.parseFailure
        }

        return BillingSnapshot(
            usedPercent: rawPercent.map { min(1, max(0, $0 / 100)) },
            resetsAt: reset,
            subscriptionTier: config.subscriptionTier ?? envelope.subscriptionTier
        )
    }

    private static func isActiveBillingPeriod(_ period: CurrentPeriod?, now: Date) -> Bool {
        guard let end = parseDate(period?.end), end > now else { return false }
        if let start = parseDate(period?.start) {
            return start <= now
        }
        return true
    }

    private struct TokenResponse: Decodable {
        let accessToken: String
        let refreshToken: String?
        let expiresIn: Double?

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
            case expiresIn = "expires_in"
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            accessToken = try container.decode(String.self, forKey: .accessToken)
            refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
            if let seconds = try? container.decode(Double.self, forKey: .expiresIn) {
                expiresIn = seconds
            } else if let seconds = try? container.decode(Int.self, forKey: .expiresIn) {
                expiresIn = Double(seconds)
            } else {
                expiresIn = nil
            }
        }
    }

    private struct DiscoveryDocument: Decodable {
        let tokenEndpoint: String?

        enum CodingKeys: String, CodingKey {
            case tokenEndpoint = "token_endpoint"
        }
    }

    /// Grok CLI refreshes ~5 minutes before expiry via the stored refresh
    /// token. Mirror that here so Capacity Dock does not drop to a terminal
    /// disconnect every time the short-lived access token ages out.
    private static func rotateSession(
        _ credential: GrokBuildCredentialStore.Credential,
        deps: Deps,
        now: Date
    ) async throws -> GrokBuildCredentialStore.Credential {
        guard credential.canRefresh else {
            if credential.isExpired(at: now) { throw FetchError.expiredSession }
            return credential
        }
        if let sibling = try? await Task.detached(operation: deps.loadCredential).value,
           sibling.accessToken != credential.accessToken,
           !sibling.isExpired(at: now)
        {
            return sibling
        }

        do {
            let tokens = try await requestRefreshedTokens(credential, deps: deps, now: now)
            let persist = deps.persistRefreshed
            try? await Task.detached { try persist(tokens) }.value
            return GrokBuildCredentialStore.Credential(
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken ?? credential.refreshToken,
                authMode: credential.authMode,
                expiresAt: tokens.expiresAt,
                oidcIssuer: credential.oidcIssuer,
                oidcClientId: credential.oidcClientId,
                scope: tokens.scope
            )
        } catch let error as FetchError {
            if case .expiredSession = error,
               let sibling = try? await Task.detached(operation: deps.loadCredential).value,
               sibling.accessToken != credential.accessToken,
               !sibling.isExpired(at: now)
            {
                return sibling
            }
            if !credential.isExpired(at: now), error.classification == .transient {
                return credential
            }
            throw error
        }
    }

    private static func requestRefreshedTokens(
        _ credential: GrokBuildCredentialStore.Credential,
        deps: Deps,
        now: Date
    ) async throws -> GrokBuildCredentialStore.RefreshedTokens {
        guard let refreshToken = GrokBuildCredentialStore.cleaned(credential.refreshToken),
              let clientId = GrokBuildCredentialStore.cleaned(credential.oidcClientId)
        else {
            throw FetchError.expiredSession
        }
        let endpoint = try await tokenEndpoint(for: credential, deps: deps)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = timeoutSeconds
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CodeBurn", forHTTPHeaderField: "User-Agent")
        request.httpBody = formURLEncoded([
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", clientId),
        ]).data(using: .utf8)

        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await deps.fetch(request)
        } catch let error as FetchError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw FetchError.network
        }

        switch response.statusCode {
        case 200:
            break
        case 401, 403, 400:
            throw FetchError.expiredSession
        case 429:
            throw FetchError.rateLimited
        case 500...599:
            throw FetchError.providerUnavailable
        default:
            throw FetchError.expiredSession
        }

        let decoded: TokenResponse
        do {
            decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw FetchError.parseFailure
        }
        let access = GrokBuildCredentialStore.cleaned(decoded.accessToken)
        guard let access else { throw FetchError.parseFailure }
        let lifetime = decoded.expiresIn.flatMap { $0.isFinite && $0 > 0 ? $0 : nil } ?? 3600
        return GrokBuildCredentialStore.RefreshedTokens(
            scope: credential.scope,
            accessToken: access,
            refreshToken: GrokBuildCredentialStore.cleaned(decoded.refreshToken),
            expiresAt: now.addingTimeInterval(lifetime)
        )
    }

    private static func tokenEndpoint(
        for credential: GrokBuildCredentialStore.Credential,
        deps: Deps
    ) async throws -> URL {
        guard let issuer = GrokBuildCredentialStore.httpsURL(from: credential.oidcIssuer) else {
            throw FetchError.expiredSession
        }
        let discovery = issuer
            .appendingPathComponent(".well-known")
            .appendingPathComponent("openid-configuration")
        var request = URLRequest(url: discovery)
        request.httpMethod = "GET"
        request.timeoutInterval = timeoutSeconds
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CodeBurn", forHTTPHeaderField: "User-Agent")
        if let (data, response) = try? await deps.fetch(request),
           response.statusCode == 200,
           let document = try? JSONDecoder().decode(DiscoveryDocument.self, from: data),
           let endpoint = GrokBuildCredentialStore.httpsURL(from: document.tokenEndpoint)
        {
            return endpoint
        }
        if issuer.host?.lowercased() == "auth.x.ai",
           let fallback = URL(string: "https://auth.x.ai/oauth2/token")
        {
            return fallback
        }
        throw FetchError.network
    }

    private static func formURLEncoded(_ pairs: [(String, String)]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return pairs.map { key, value in
            let encodedKey = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
            let encodedValue = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
            return "\(encodedKey)=\(encodedValue)"
        }.joined(separator: "&")
    }

    private static func fetchRequired(
        url: URL,
        credential: GrokBuildCredentialStore.Credential,
        deps: Deps
    ) async throws -> Data {
        let request = authorizedRequest(url: url, credential: credential)
        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await deps.fetch(request)
        } catch let error as FetchError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw FetchError.network
        }
        switch response.statusCode {
        case 200: return data
        case 401, 403: throw FetchError.authenticationRejected
        case 429: throw FetchError.rateLimited
        case 500...599: throw FetchError.providerUnavailable
        default: throw FetchError.parseFailure
        }
    }

    private static func fetchPlan(
        credential: GrokBuildCredentialStore.Credential,
        deps: Deps
    ) async throws -> String? {
        let request = authorizedRequest(url: settingsURL, credential: credential)
        let data: Data
        let response: HTTPURLResponse
        do {
            (data, response) = try await deps.fetch(request)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return nil
        }
        guard response.statusCode == 200,
              let settings = try? JSONDecoder().decode(SettingsEnvelope.self, from: data) else { return nil }
        return settings.subscriptionTierDisplay
    }

    private static func authorizedRequest(
        url: URL,
        credential: GrokBuildCredentialStore.Credential
    ) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = timeoutSeconds
        request.setValue("Bearer \(credential.accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("xai-grok-cli", forHTTPHeaderField: "x-xai-token-auth")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CodeBurn", forHTTPHeaderField: "User-Agent")
        return request
    }

    private static func parseDate(_ raw: String?) -> Date? {
        guard let raw, !raw.isEmpty else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: raw) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: raw)
    }

    private static func normalizedPlan(_ raw: String?) -> String? {
        guard let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty else { return nil }
        switch value.lowercased().filter(\.isLetter) {
        case "supergrokheavy", "heavy": return "SuperGrok Heavy"
        case "supergrok": return "SuperGrok"
        default: return value
        }
    }

    private static func windowLabel(resetsAt: Date?, now: Date) -> String {
        guard let resetsAt else { return "Credits" }
        let days = Int((resetsAt.timeIntervalSince(now) / 86_400).rounded())
        if (4...12).contains(days) { return "Weekly" }
        if (20...45).contains(days) { return "Monthly" }
        return "Credits"
    }
}
