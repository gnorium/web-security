import Foundation

/// Provider for generating OAuth/OIDC authorization URLs.
/// Brand-neutral and compatible with Google, Apple, and AWS Cognito.
public struct OIDCProvider: Sendable {
    public enum Provider: String, Sendable {
        case google
        case apple
        case cognito
    }

    private let provider: Provider
    private let clientId: String
    private let redirectUri: String
    private let userPoolId: String?
    private let region: String?

    public init(
        provider: Provider, 
        clientId: String, 
        redirectUri: String, 
        userPoolId: String? = nil, 
        region: String? = nil
    ) {
        self.provider = provider
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.userPoolId = userPoolId
        self.region = region
    }

    /// Generate the authorization URL for the provider.
    public func authorizationURL(state: String) -> String {
        let endpoint = authorizationEndpoint()
        let scope = defaultScope()

        var components = URLComponents(string: endpoint)!
        var queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: scope),
            URLQueryItem(name: "state", value: state)
        ]

        if provider == .apple {
            queryItems.append(URLQueryItem(name: "response_mode", value: "form_post"))
        }
        
        components.queryItems = queryItems
        return components.url?.absoluteString ?? endpoint
    }

    // MARK: - Private Helpers

    private func authorizationEndpoint() -> String {
        switch provider {
        case .google:
            return "https://accounts.google.com/o/oauth2/v2/auth"
        case .apple:
            return "https://appleid.apple.com/auth/authorize"
        case .cognito:
            guard let userPoolId = userPoolId, let region = region else { return "" }
            return "https://\(userPoolId).auth.\(region).amazoncognito.com/oauth2/authorize"
        }
    }

    private func defaultScope() -> String {
        switch provider {
        case .google: return "openid email profile"
        case .apple: return "openid email name"
        case .cognito: return "openid email profile"
        }
    }
}
