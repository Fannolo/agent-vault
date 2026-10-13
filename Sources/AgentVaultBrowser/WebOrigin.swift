import Foundation

/// An exact scheme + host + port triple. There is no suffix, subdomain or wildcard matching.
public struct WebOrigin: Hashable, Sendable {
    public let scheme: String
    public let host: String
    public let port: Int

    public init?(url: URL?) {
        guard let url, let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(),
              scheme == "https" || scheme == "http", !host.isEmpty, url.user == nil, url.password == nil
        else { return nil }
        self.scheme = scheme
        self.host = host
        self.port = url.port ?? (scheme == "https" ? 443 : 80)
    }

    public func matches(_ url: URL?) -> Bool { WebOrigin(url: url) == self }

    /// JavaScript `location.origin` spelling, used by the in-page recipes.
    var serialized: String {
        let isDefault = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
        return isDefault ? "\(scheme)://\(host)" : "\(scheme)://\(host):\(port)"
    }

    func url(path: String) -> URL? { URL(string: serialized + path) }

    /// Anchored expression for WebKit content rules, whose regex dialect has no alternation.
    /// Hosts here are DNS names or IPv4 literals, so only the dot needs escaping.
    var contentRuleFilter: String {
        "^" + serialized.replacingOccurrences(of: ".", with: "\\.") + "/"
    }
}
