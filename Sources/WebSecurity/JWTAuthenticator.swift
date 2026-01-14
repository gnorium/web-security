import Foundation
import JWTKit

/// A standard JWT payload for user authentication.
public struct AuthenticationPayload: JWTPayload, Codable, Sendable {
    public let subject: SubjectClaim
    public let expiration: ExpirationClaim
    public let mfaVerified: Bool
    
    public init(subject: String, mfaVerified: Bool, expiration: Date) {
        self.subject = SubjectClaim(value: subject)
        self.mfaVerified = mfaVerified
        self.expiration = ExpirationClaim(value: expiration)
    }

    public func verify(using signer: JWTSigner) throws {
        try self.expiration.verifyNotExpired()
    }
}

/// Authenticator for signing and verifying JWTs.
public struct JWTAuthenticator: Sendable {
    private let signers: JWTSigners

    public init(signers: JWTSigners) {
        self.signers = signers
    }

    /// Sign a payload for a given subject.
    public func sign(
        subject: String, 
        mfaVerified: Bool = true, 
        expirationInterval: TimeInterval = 60 * 60 * 24 * 7 // 7 days
    ) throws -> String {
        let payload = AuthenticationPayload(
            subject: subject,
            mfaVerified: mfaVerified,
            expiration: Date().addingTimeInterval(expirationInterval)
        )
        return try signers.sign(payload)
    }

    /// Verify a token and return the payload.
    public func verify(_ token: String) throws -> AuthenticationPayload {
        return try signers.verify(token, as: AuthenticationPayload.self)
    }
}

// MARK: - Claims

public struct SubjectClaim: Codable, Sendable {
    public let value: String
    public init(value: String) { self.value = value }
}

public struct ExpirationClaim: Codable, Sendable {
    public let value: Date
    public init(value: Date) { self.value = value }
    
    public func verifyNotExpired() throws {
        if self.value < Date() {
            throw JWTError.claimVerificationFailure(name: "exp", reason: "Token has expired")
        }
    }
}
