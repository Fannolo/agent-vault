import AgentVaultContracts
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

/// A broker frame that ImageIO has checked and decoded. The JPEG is untrusted: its container type,
/// image count, orientation and actual pixel size are read from the header before any pixel is
/// decoded, and must match the declared frame size inside the frame bounds.
public struct HumanFrameImage: @unchecked Sendable {
    public let sequence: UInt64
    public let width: Int
    public let height: Int
    public let image: CGImage

    public static let maximumPixels = HumanFrame.maximumWidth * HumanFrame.maximumHeight

    public init?(_ frame: HumanFrame) {
        let noCache = [kCGImageSourceShouldCache: false] as CFDictionary
        guard let source = CGImageSourceCreateWithData(frame.jpeg as CFData, noCache),
              CGImageSourceGetStatus(source) == .statusComplete,
              CGImageSourceGetType(source) as String? == UTType.jpeg.identifier,
              CGImageSourceGetCount(source) == 1,
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, noCache) as? [CFString: Any],
              let width = (properties[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
              let height = (properties[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue,
              width == frame.width, height == frame.height, width * height <= Self.maximumPixels,
              (properties[kCGImagePropertyOrientation] as? NSNumber)?.intValue ?? 1 == 1 else { return nil }
        let decode = [kCGImageSourceShouldCache: true, kCGImageSourceShouldCacheImmediately: true] as CFDictionary
        guard let image = CGImageSourceCreateImageAtIndex(source, 0, decode),
              image.width == width, image.height == height else { return nil }
        self.sequence = frame.sequence; self.width = width; self.height = height; self.image = image
    }
}

/// Aspect-fit placement of a frame in a view, and the inverse map from a view point to a frame pixel.
public struct FrameGeometry: Equatable, Sendable {
    public let frameWidth: Int
    public let frameHeight: Int
    public let viewSize: CGSize

    public init(frameWidth: Int, frameHeight: Int, viewSize: CGSize) {
        self.frameWidth = frameWidth; self.frameHeight = frameHeight; self.viewSize = viewSize
    }

    /// Where the frame is drawn, in view coordinates with the origin at the top left.
    public var imageRect: CGRect {
        guard frameWidth > 0, frameHeight > 0, viewSize.width > 0, viewSize.height > 0 else { return .zero }
        let scale = min(viewSize.width / CGFloat(frameWidth), viewSize.height / CGFloat(frameHeight))
        let size = CGSize(width: CGFloat(frameWidth) * scale, height: CGFloat(frameHeight) * scale)
        return CGRect(x: (viewSize.width - size.width) / 2, y: (viewSize.height - size.height) / 2,
                      width: size.width, height: size.height)
    }

    /// The frame pixel under a top-left-origin view point, or `nil` outside the drawn frame.
    /// With `clamped`, a point outside maps to the nearest edge pixel (a drag released outside).
    public func pixel(at point: CGPoint, clamped: Bool = false) -> (x: Int, y: Int)? {
        let rect = imageRect
        guard rect.width > 0, rect.height > 0, point.x.isFinite, point.y.isFinite,
              clamped || rect.contains(point) else { return nil }
        let x = Int(((point.x - rect.minX) / rect.width * CGFloat(frameWidth)).rounded(.down))
        let y = Int(((point.y - rect.minY) / rect.height * CGFloat(frameHeight)).rounded(.down))
        return (min(max(x, 0), frameWidth - 1), min(max(y, 0), frameHeight - 1))
    }
}
