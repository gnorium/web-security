import Foundation

/// Provider for generating OAuth/OIDC authorization URLs.
/// Brand-neutral and compatible with Google and Apple.
public struct OIDCProvider: Sendable {
  public enum Provider: String, Sendable {
    case google
    case apple
  }

  private let provider: Provider
  private let clientID: String
  private let redirectUri: String

  public init(
    provider: Provider,
    clientID: String,
    redirectUri: String
  ) {
    self.provider = provider
    self.clientID = clientID
    self.redirectUri = redirectUri
  }

  /// Generate the authorization URL for the provider.
  public func authorizationURL(state: String) -> String {
    let endpoint = authorizationEndpoint()
    let scope = defaultScope()

    var components = URLComponents(string: endpoint)!
    var queryItems = [
      URLQueryItem(name: "client_id", value: clientID),
      URLQueryItem(name: "redirect_uri", value: redirectUri),
      URLQueryItem(name: "response_type", value: "code"),
      URLQueryItem(name: "scope", value: scope),
      URLQueryItem(name: "state", value: state),
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
    }
  }

  private func defaultScope() -> String {
    switch provider {
    case .google: return "openid email profile"
    case .apple: return "openid email name"
    }
  }
}
