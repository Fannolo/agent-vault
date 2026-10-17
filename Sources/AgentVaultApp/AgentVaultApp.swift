import AgentVaultAppSupport
import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct AgentVaultApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model: AppModel

    init() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.first == "--print-approval-public-key" {
            let outcome = ApprovalCommand.runBlocking(arguments: arguments)
            FileHandle.standardOutput.write(Data(outcome.stdout.utf8))
            FileHandle.standardError.write(Data(outcome.stderr.utf8))
            exit(outcome.code)
        }
        _model = State(initialValue: AppComposition.makeModel())
    }

    var body: some Scene {
        Window("Agent Vault", id: "main") {
            RootView(model: model)
                .task {
                    #if DEBUG
                    if let path = ProcessInfo.processInfo.environment["AGENT_VAULT_UI_SCREENSHOTS"] {
                        await ScreenshotTour.run(model: model, directory: URL(fileURLWithPath: path, isDirectory: true))
                    }
                    #endif
                }
        }
        .defaultSize(width: 980, height: 640)
    }
}
