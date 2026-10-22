#if DEBUG
import AgentVaultContracts
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

/// Generated challenge pictures for tests, previews and the screenshot tour. DEBUG only.
package enum SyntheticFrames {
    package static func jpeg(width: Int, height: Int, shade: Double = 0.85) -> Data {
        let space = CGColorSpace(name: CGColorSpace.sRGB)!
        let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                                bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
        context.setFillColor(CGColor(red: shade, green: shade, blue: shade + 0.1 > 1 ? 1 : shade + 0.1, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        context.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        let card = CGRect(x: width / 4, y: height / 4, width: width / 2, height: height / 2)
        context.fill(card)
        context.setFillColor(CGColor(red: 0.2, green: 0.4, blue: 0.9, alpha: 1))
        context.fill(CGRect(x: card.minX + card.width * 0.1, y: card.minY + card.height * 0.15,
                            width: card.width * 0.8, height: card.height * 0.18))
        let data = NSMutableData()
        let destination = CGImageDestinationCreateWithData(data, UTType.jpeg.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(destination, context.makeImage()!, [kCGImageDestinationLossyCompressionQuality: 0.7] as CFDictionary)
        CGImageDestinationFinalize(destination)
        return data as Data
    }

    package static func frame(_ sequence: UInt64, width: Int = 640, height: Int = 420) -> HumanFrame {
        HumanFrame(sequence: sequence, width: width, height: height, jpeg: jpeg(width: width, height: height))!
    }
}
#endif
