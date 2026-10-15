import Foundation

// Human continuation: raster frames out, bounded input events in. No URL, script, file,
// clipboard, cookie or navigation verb exists in this vocabulary.

/// One JPEG frame of a paused challenge. The pixel size bounds every pointer event that a
/// person may send against it.
public struct HumanFrame: Sendable, Equatable {
    public static let maximumJPEGBytes = 262_144
    public static let maximumWidth = 1280
    public static let maximumHeight = 900

    /// Monotonic within one human step; inputs name the latest frame they were aimed at.
    public let sequence: UInt64
    public let width: Int
    public let height: Int
    public let jpeg: Data

    public init?(sequence: UInt64, width: Int, height: Int, jpeg: Data) {
        guard sequence > 0, sequence <= Self.maximumSequence,
              (1...Self.maximumWidth).contains(width), (1...Self.maximumHeight).contains(height),
              (4...Self.maximumJPEGBytes).contains(jpeg.count),
              jpeg.prefix(2) == Data([0xFF, 0xD8]), jpeg.suffix(2) == Data([0xFF, 0xD9]) else { return nil }
        self.sequence = sequence; self.width = width; self.height = height; self.jpeg = jpeg
    }

    /// Exactly representable by every JSON decoder on the path.
    public static let maximumSequence: UInt64 = 1 << 53
}

public enum PointerPhase: String, CaseIterable, Sendable { case down, up, move }

public enum NamedKey: String, CaseIterable, Sendable {
    case enter, tab, backspace, delete, escape, arrowLeft, arrowRight, arrowUp, arrowDown
}

public enum HumanInput: Sendable, Equatable {
    /// Frame pixel coordinates.
    case pointer(PointerPhase, x: Int, y: Int)
    case wheel(dx: Int, dy: Int)
    case key(NamedKey)
    /// One to 64 UTF-8 bytes, excluding Unicode Cc/Cf control and format scalars.
    case text(String)

    public static let maximumTextBytes = 64
    public static let maximumWheelDelta = 2000

    /// Bounds that hold for any frame; the host also checks pointers against the frame it served.
    public func fits(width: Int = HumanFrame.maximumWidth, height: Int = HumanFrame.maximumHeight) -> Bool {
        guard width > 0, height > 0 else { return false }
        return switch self {
        case .pointer(_, let x, let y): (0..<width).contains(x) && (0..<height).contains(y)
        case .wheel(let dx, let dy):
            // Range checks, not `abs`, so `Int.min` is refused instead of trapping.
            (-Self.maximumWheelDelta...Self.maximumWheelDelta).contains(dx)
                && (-Self.maximumWheelDelta...Self.maximumWheelDelta).contains(dy) && (dx != 0 || dy != 0)
        case .key: true
        case .text(let text):
            (1...Self.maximumTextBytes).contains(text.utf8.count)
                && !text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
        }
    }
}

/// One to 32 events, each within the bounds of the frame they target.
public struct HumanInputBatch: Sendable, Equatable {
    public static let maximumEvents = 32
    public let events: [HumanInput]

    public init?(_ events: [HumanInput], width: Int = HumanFrame.maximumWidth, height: Int = HumanFrame.maximumHeight) {
        guard (1...Self.maximumEvents).contains(events.count),
              events.allSatisfy({ $0.fits(width: width, height: height) }) else { return nil }
        self.events = events
    }
}
