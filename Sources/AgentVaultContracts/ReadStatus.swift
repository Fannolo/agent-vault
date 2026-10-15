import Foundation

/// Every non-error status an agent can receive. Broker, wire codec and MCP bridge derive from this.
public enum ReadOutcomeStatus: String, CaseIterable, Codable, Sendable {
    case completed, ready, cancelled
    case approvalRequired = "approval_required"
    case humanStepRequired = "human_step_required"
}

/// Every failure status an agent can receive. Lowercase tokens only; precise browser host
/// codes stay in the broker audit and are never placed on the agent wire.
public enum ReadFailureStatus: String, CaseIterable, Codable, Sendable, Error {
    case invalidInput = "invalid_input"
    case accessDenied = "access_denied"
    case stateUnavailable = "state_unavailable"
    case secretUnavailable = "secret_unavailable"
    case upstreamUnavailable = "upstream_unavailable"
    case invalidResponse = "invalid_response"
    case busy
    case operationFailed = "operation_failed"
    case loginRejected = "login_rejected"
    /// The page, origin or profile contract of a fixed web workflow no longer matched.
    case pageChanged = "page_changed"
    /// A human step cannot be shown, for example because it needs an unreviewed origin.
    case challengeUnavailable = "challenge_unavailable"
    case humanStepExpired = "human_step_expired"
    case humanCancelled = "human_cancelled"
    /// The browser session ended with its host before the run concluded.
    case sessionLost = "session_lost"
}

public enum ReadStatus: Equatable, Sendable {
    case outcome(ReadOutcomeStatus)
    case failure(ReadFailureStatus)

    public init?(wire: String) {
        if let outcome = ReadOutcomeStatus(rawValue: wire) { self = .outcome(outcome) }
        else if let failure = ReadFailureStatus(rawValue: wire) { self = .failure(failure) }
        else { return nil }
    }

    public var wire: String {
        switch self {
        case .outcome(let outcome): outcome.rawValue
        case .failure(let failure): failure.rawValue
        }
    }
}

/// The only profile shape any action returns. Both fields are required.
public struct AccountProfile: Codable, Equatable, Sendable {
    public let login: String
    public let userID: Int

    public init?(login: String, userID: Int) {
        guard Self.isValidLogin(login), userID > 0 else { return nil }
        self.login = login; self.userID = userID
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let value = Self(login: try container.decode(String.self, forKey: .login),
                               userID: try container.decode(Int.self, forKey: .userID)) else {
            throw DecodingError.dataCorruptedError(forKey: .login, in: container, debugDescription: "invalid profile")
        }
        self = value
    }

    /// One to 39 bytes of `[A-Za-z0-9-]`, not starting with `-`.
    public static func isValidLogin(_ login: String) -> Bool {
        let bytes = Array(login.utf8)
        guard (1...39).contains(bytes.count), bytes[0] != UInt8(ascii: "-") else { return false }
        return bytes.allSatisfy {
            (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0)
                || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) || $0 == UInt8(ascii: "-")
        }
    }
}

public enum HumanStepKind: String, Codable, CaseIterable, Sendable {
    case mfa, captcha
}

extension ReadReply {
    public init(_ status: ReadStatus, accounts: [AccountSummary]? = nil, requestID: UUID? = nil,
                profile: AccountProfile? = nil) {
        self.init(status: status.wire, accounts: accounts, requestID: requestID,
                  login: profile?.login, userID: profile?.userID)
    }

    /// `nil` for a status outside the closed vocabulary.
    public var parsedStatus: ReadStatus? { ReadStatus(wire: status) }

    /// `nil` unless both profile fields are present and valid.
    public var profile: AccountProfile? {
        guard let login, let userID else { return nil }
        return AccountProfile(login: login, userID: userID)
    }

    /// Exact field layout for each status: the wire carries nothing a status does not define.
    public var isWellFormed: Bool {
        guard let status = parsedStatus else { return false }
        let hasProfileField = login != nil || userID != nil
        switch status {
        case .outcome(.completed):
            guard requestID == nil else { return false }
            if accounts != nil { return !hasProfileField }
            return profile != nil
        case .outcome(.ready):
            return accounts == nil && requestID == nil && !hasProfileField
        case .outcome(.cancelled), .outcome(.approvalRequired), .outcome(.humanStepRequired):
            return accounts == nil && requestID != nil && !hasProfileField
        case .failure:
            return accounts == nil && requestID == nil && !hasProfileField
        }
    }
}
