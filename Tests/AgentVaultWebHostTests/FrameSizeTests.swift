@testable import AgentVaultWebHost
import CoreGraphics
import Foundation
import ImageIO
import Testing
import UniformTypeIdentifiers

/// A real JPEG of a known size, encoded by ImageIO rather than by the host.
private func jpeg(width: Int, height: Int) -> Data {
    let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
    context.setFillColor(CGColor(red: 0.2, green: 0.4, blue: 0.6, alpha: 1))
    context.fill(CGRect(x: 0, y: 0, width: width, height: height))
    let output = NSMutableData()
    let destination = CGImageDestinationCreateWithData(output, UTType.jpeg.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, context.makeImage()!, [kCGImageDestinationLossyCompressionQuality: 0.6] as CFDictionary)
    CGImageDestinationFinalize(destination)
    return output as Data
}

@Suite struct FrameSizeTests {
    @Test func hostReadsTheEncodedPixelSizeOfAFrame() {
        for (width, height) in [(37, 21), (400, 120), (1280, 900), (1, 899)] {
            let size = WebRun.jpegSize(jpeg(width: width, height: height))
            #expect(size?.width == width && size?.height == height, "\(width)x\(height)")
        }
    }

    @Test func malformedImagesHaveNoSize() {
        let good = jpeg(width: 10, height: 10)
        for bad in [Data(), Data([0xFF, 0xD8]), Data([0x89, 0x50, 0x4E, 0x47]) + good.dropFirst(4), good.prefix(20),
                    Data([0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x00, 0, 0, 0, 0, 0, 0])] {
            #expect(WebRun.jpegSize(bad) == nil)
        }
    }
}
