import Foundation
import JWTKit

/// A standard JWT payload for user authentication.
public struct AuthenticationPayload: JWTPayload, Codable, Sendable {
    public let sub: SubjectClaim
    public let exp: ExpirationClaim
    public let mfaVerified: Bool
    
    public init(subject: String, mfaVerified: Bool, expiration: Date) {
        self.sub = SubjectClaim(value: subject)
        self.mfaVerified = mfaVerified
        self.exp = ExpirationClaim(value: expiration)
    }

    public func verify(using signer: some JWTAlgorithm) async throws {
        try self.exp.verifyNotExpired()
    }
}

/// Authenticator for signing and verifying JWTs.
public struct JWTAuthenticator: Sendable {
    private let keys: JWTKeyCollection

    public init(keys: JWTKeyCollection) {
        self.keys = keys
    }
    
    public init(secret: String) async {
        self.keys = JWTKeyCollection()
        await self.keys.add(hmac: HMACKey(stringLiteral: secret), digestAlgorithm: .sha256)
    }

    /// Sign a payload for a given subject.
    public func sign(
        subject: String, 
        mfaVerified: Bool = true, 
        expirationInterval: TimeInterval = 60 * 60 * 24 * 7 // 7 days
    ) async throws -> String {
        let payload = AuthenticationPayload(
            subject: subject,
            mfaVerified: mfaVerified,
            expiration: Date().addingTimeInterval(expirationInterval)
        )
        return try await keys.sign(payload)
    }
    
    public func sign<Payload: JWTPayload>(_ payload: Payload) async throws -> String {
        try await keys.sign(payload)
    }

    /// Verify a token and return the payload.
    public func verify(_ token: String) async throws -> AuthenticationPayload {
        return try await keys.verify(token, as: AuthenticationPayload.self)
    }
    
    public func verify<Payload: JWTPayload>(_ token: String, as type: Payload.Type) async throws -> Payload {
        try await keys.verify(token, as: type)
    }
}
