#if DEBUG
import AppKit
import SwiftUI

/// DEBUG-only GUI verification: walks every screen of the running app and writes in-process
/// window renderings (no screen-recording permission, nothing system-wide) to a directory.
@MainActor
public enum ScreenshotTour {
    public static func run(model: AppModel, directory: URL) async {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? await Task.sleep(for: .milliseconds(1200))
        for section in AppSection.allCases {
            model.selection = section
            try? await Task.sleep(for: .milliseconds(700))
            snapshot(named: section.rawValue, to: directory)
        }
        model.selection = .accounts
        for sheet in [AppSheet.enroll, .pair, .grant] {
            model.sheet = sheet
            try? await Task.sleep(for: .milliseconds(800))
            snapshot(named: "sheet-\(sheet.rawValue)", to: directory, sheet: true)
            model.sheet = nil
            try? await Task.sleep(for: .milliseconds(500))
        }
        model.selection = .requests
        if let step = model.humanSteps.first, await model.openHumanStep(step) {
            try? await Task.sleep(for: .milliseconds(1500))
            snapshot(named: "sheet-human-step", to: directory, sheet: true)
            await model.dismissHumanStep()
        }
        NSApp.terminate(nil)
    }

    private static func snapshot(named name: String, to directory: URL, sheet: Bool = false) {
        guard let window = NSApp.windows.first(where: { $0.isVisible && $0.contentView != nil && $0.attachedSheet != nil || $0.isVisible && $0.title == "Agent Vault" }) ?? NSApp.windows.first
        else { return }
        let target = sheet ? (window.attachedSheet ?? window) : window
        guard let view = target.contentView?.superview ?? target.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        if let png = rep.representation(using: .png, properties: [:]) {
            try? png.write(to: directory.appendingPathComponent("\(name).png"), options: .atomic)
        }
    }
}
#endif
