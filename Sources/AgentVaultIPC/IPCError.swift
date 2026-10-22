import Foundation

/// Fixed public failure codes. They never carry peer data, request bytes or handler errors.
public enum IPCError: String, Error, Sendable, Codable, CaseIterable {
    case invalidConfiguration = "invalid_configuration"
    case invalidRequest = "invalid_request"
    case requestTooLarge = "request_too_large"
    case busy
    case unavailable
    case connectionFailed = "connection_failed"
    case brokerRejected = "broker_rejected"
    case timeout
    case malformedReply = "malformed_reply"

    /// Codes a broker may place on the wire. Anything else in an error envelope is malformed.
    static let wireCodes: Set<IPCError> = [.invalidRequest, .requestTooLarge, .busy, .unavailable]
}

/// Thrown by an admin `begin` handler to refuse a request with a domain status token.
public struct AdminRejection: Error, Sendable, Equatable {
    public let status: String
    public init(status: String) { self.status = status }
}
