import AgentVaultContracts
import Foundation

// Continuing-site sessions: a host-created browser context that logs in privately and then accepts
// closed, typed page operations. Separate from fixed workflows: a `HostWorkflow` run never becomes
// a session, and nothing here names a selector, script, CDP method, cookie or browser connection.

/// Sites the host compiles a `SitePolicy` for. Distinct from `HostWorkflow`, so a fixed grant's
/// workflow cannot name one. Production builds compile none yet.
public enum HostSite: String, CaseIterable, Sendable {
    case syntheticFixture
}

/// An element of one observation. Opaque to callers: they echo it back. It binds the document
/// (a host-wide counter, so no two sessions or documents share a value), the control epoch
/// (bumped by takeover and release) and the element's row in that document's table.
public struct SiteTarget: Sendable, Hashable {
    public static let maximumElement = 4095
    public let document: UInt64
    public let control: UInt64
    public let element: Int

    public init?(document: UInt64, control: UInt64, element: Int) {
        guard document >= 1, control >= 1, (0...Self.maximumElement).contains(element) else { return nil }
        self.document = document; self.control = control; self.element = element
    }
}

public enum SiteCommand: Sendable, Equatable {
    /// An absolute URL. A request only: the host's site policy decides whether it may load.
    case navigate(String)
    case click(SiteTarget)
    /// Replaces the value of a plain text field. Never a password field.
    case typePublic(SiteTarget, String)
    /// Chooses an option by its index in the observed element's `options`.
    case select(SiteTarget, option: Int)
    case press(NamedKey)
    case scroll(dy: Int)

    public static let maximumURLBytes = 2048
    public static let maximumTextBytes = 1024
    public static let maximumOption = 255

    public var fits: Bool {
        switch self {
        case .navigate(let url): Self.plain(url, maximum: Self.maximumURLBytes)
        case .click, .press: true
        case .typePublic(_, let text): text.isEmpty || Self.plain(text, maximum: Self.maximumTextBytes)
        case .select(_, let option): (0...Self.maximumOption).contains(option)
        case .scroll(let dy): (-HumanInput.maximumWheelDelta...HumanInput.maximumWheelDelta).contains(dy) && dy != 0
        }
    }

    static func plain(_ text: String, maximum: Int) -> Bool {
        (1...maximum).contains(text.utf8.count) && !text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

public enum SiteMode: String, CaseIterable, Sendable {
    /// The agent may observe and operate.
    case agent
    /// A person has control: agent observation and input are refused until release.
    case human
}

public enum SiteAuth: String, CaseIterable, Sendable {
    case signedOut
    case signedIn
    /// The site showed its password form again after the private login.
    case rejected
    /// The site asked for a step this host does not perform (for example a one-time code).
    case humanRequired
}

public enum SiteRole: String, CaseIterable, Sendable {
    case link, button, submit, textField, password, checkbox, radio, select
}

/// One interactive element. A password field never carries a value.
public struct SiteElement: Sendable, Equatable {
    public static let maximumLabelBytes = 256
    public static let maximumValueBytes = 1024
    public static let maximumOptions = SiteCommand.maximumOption + 1

    public let ref: Int
    public let role: SiteRole
    public let label: String
    public let value: String
    public let options: [String]

    public init?(ref: Int, role: SiteRole, label: String, value: String, options: [String]) {
        guard (0...SiteTarget.maximumElement).contains(ref), label.utf8.count <= Self.maximumLabelBytes,
              value.utf8.count <= Self.maximumValueBytes, options.count <= Self.maximumOptions,
              options.allSatisfy({ $0.utf8.count <= Self.maximumLabelBytes }),
              role != .password || value.isEmpty, role == .select || options.isEmpty else { return nil }
        self.ref = ref; self.role = role; self.label = label; self.value = value; self.options = options
    }
}

/// What the agent may see of the current page: typed fields only, no markup, cookies or storage.
public struct SiteObservation: Sendable, Equatable {
    public static let maximumElements = 256
    public static let maximumTextItems = 256
    public static let maximumTextBytes = 1024
    public static let maximumPathBytes = 1024
    public static let maximumOriginBytes = 256

    public let document: UInt64
    public let control: UInt64
    public let mode: SiteMode
    public let auth: SiteAuth
    /// The main frame's origin when it is within the site policy, otherwise empty.
    public let origin: String
    /// The main frame's path, without query or fragment.
    public let path: String
    public let title: String
    public let elements: [SiteElement]
    public let text: [String]

    public init?(document: UInt64, control: UInt64, mode: SiteMode, auth: SiteAuth, origin: String, path: String,
                 title: String, elements: [SiteElement], text: [String]) {
        guard document >= 1, control >= 1, origin.utf8.count <= Self.maximumOriginBytes,
              path.utf8.count <= Self.maximumPathBytes, title.utf8.count <= SiteElement.maximumLabelBytes,
              elements.count <= Self.maximumElements, text.count <= Self.maximumTextItems,
              Set(elements.map(\.ref)).count == elements.count,
              text.allSatisfy({ $0.utf8.count <= Self.maximumTextBytes }) else { return nil }
        self.document = document; self.control = control; self.mode = mode; self.auth = auth
        self.origin = origin; self.path = path; self.title = title; self.elements = elements; self.text = text
    }

    /// The reference an agent sends back to act on `element`.
    public func target(_ element: SiteElement) -> SiteTarget? {
        SiteTarget(document: document, control: control, element: element.ref)
    }

    /// The same observation with its last elements and text removed.
    func truncated(elements keep: Int, text keepText: Int) -> SiteObservation {
        SiteObservation(document: document, control: control, mode: mode, auth: auth, origin: origin, path: path,
                        title: title, elements: Array(elements.prefix(keep)), text: Array(text.prefix(keepText)))!
    }
}
