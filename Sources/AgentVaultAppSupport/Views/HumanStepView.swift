import AgentVaultContracts
import AppKit
import SwiftUI

/// The challenge window: one validated frame of one paused step, and the person's pointer, wheel
/// and keyboard input aimed at it. It is not a browser: there is no address, navigation, clipboard,
/// file or page text, only pixels in and closed events out.
struct HumanStepView: View {
    let model: HumanStepModel
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            ZStack {
                RasterSurface(model: model)
                    .background(Color.black.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                if model.frame == nil { overlay }
            }
            .frame(minWidth: 640, minHeight: 450)
            footer
        }
        .padding(20)
        .frame(minWidth: 700)
        .accessibilityIdentifier("human-step")
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(model.step.service.displayName) sign-in needs you · \(model.step.kind.displayName)")
                    .font(.title3.weight(.semibold))
                Text("Account \(shortID(model.step.accountID)) · request \(shortID(model.step.runID)) · step \(model.step.epoch)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Label(statusText(at: context.date), systemImage: statusSymbol).foregroundStyle(statusColor)
                    .monospacedDigit()
            }
        }
    }

    private var overlay: some View {
        VStack(spacing: 8) {
            if model.phase == .connecting { ProgressView() }
            Text(overlayText).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .padding()
    }

    private var footer: some View {
        HStack {
            if model.finishBlockedByUndeliveredInput && !model.isEnded {
                Label("Some input was not delivered. Check the picture, then press I finished again.",
                      systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            } else {
                Text("Only this sign-in step is shown. Click and type here as you would on the page.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if model.isEnded {
                Button("Close", action: dismiss).keyboardShortcut(.defaultAction)
            } else {
                Button("Cancel sign-in", role: .destructive) { Task { await model.cancel() } }
                    .disabled(model.phase == .finishing)
                Button("Close") { dismiss() }
                Button("I finished") { Task { await model.finish() } }
                    .buttonStyle(.borderedProminent).disabled(model.phase != .live)
            }
        }
    }

    private func statusText(at date: Date) -> String {
        switch model.phase {
        case .connecting: "Connecting · \(clock(model.remaining(at: date)))"
        case .live: "Live · \(clock(model.remaining(at: date))) left"
        case .finishing: "Checking the page…"
        case .ended(let ending): Self.describe(ending)
        }
    }

    private var statusSymbol: String {
        switch model.phase {
        case .connecting, .finishing: "hourglass"
        case .live: "dot.radiowaves.left.and.right"
        case .ended(.concluded), .ended(.nextStep): "checkmark.circle"
        case .ended: "xmark.circle"
        }
    }

    private var statusColor: Color {
        switch model.phase {
        case .live: .green
        case .connecting, .finishing: .secondary
        case .ended(.concluded), .ended(.nextStep): .green
        case .ended: .orange
        }
    }

    private var overlayText: String {
        switch model.phase {
        case .connecting: "Waiting for the first picture of the page."
        case .live, .finishing: ""
        case .ended(let ending): Self.describe(ending)
        }
    }

    static func describe(_ ending: HumanStepModel.Ending) -> String {
        switch ending {
        case .concluded: "Done. The agent can collect the result."
        case .nextStep(let kind): "Another \(kind.displayName) step is needed. Open it from Requests."
        case .cancelled: "Sign-in cancelled."
        case .closed: "Closed. The step stays open until its deadline."
        case .expired: "This step expired."
        case .unavailable: "This step is no longer available."
        case .connectionLost: "The broker connection was lost. Open the step again from Requests."
        }
    }

    private func clock(_ seconds: TimeInterval) -> String {
        let whole = Int(seconds.rounded(.down))
        return String(format: "%d:%02d", whole / 60, whole % 60)
    }
}

/// Draws the current frame aspect-fit and turns AppKit events into model calls.
struct RasterSurface: NSViewRepresentable {
    let model: HumanStepModel

    func makeNSView(context: Context) -> RasterView {
        let view = RasterView()
        view.model = model
        return view
    }

    func updateNSView(_ view: RasterView, context: Context) {
        view.model = model
        view.show(model.frame?.image)
    }
}

final class RasterView: NSView {
    weak var model: HumanStepModel?
    private var tracking: NSTrackingArea?

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        layer?.contentsGravity = .resizeAspect
        layer?.magnificationFilter = .linear
    }

    required init?(coder: NSCoder) { nil }

    override var isFlipped: Bool { true }
    override var acceptsFirstResponder: Bool { true }

    func show(_ image: CGImage?) { layer?.contents = image }

    override func updateTrackingAreas() {
        if let tracking { removeTrackingArea(tracking) }
        let area = NSTrackingArea(rect: bounds, options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect], owner: self)
        addTrackingArea(area)
        tracking = area
        super.updateTrackingAreas()
    }

    private func point(_ event: NSEvent) -> CGPoint { convert(event.locationInWindow, from: nil) }

    override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        model?.pointer(.down, at: point(event), in: bounds.size)
    }
    override func mouseDragged(with event: NSEvent) { model?.pointer(.move, at: point(event), in: bounds.size) }
    override func mouseMoved(with event: NSEvent) { model?.pointer(.move, at: point(event), in: bounds.size) }
    override func mouseUp(with event: NSEvent) { model?.pointer(.up, at: point(event), in: bounds.size) }

    override func scrollWheel(with event: NSEvent) {
        let scale: Double = event.hasPreciseScrollingDeltas ? 1 : 40
        model?.wheel(dx: -event.scrollingDeltaX * scale, dy: -event.scrollingDeltaY * scale)
    }

    override func keyDown(with event: NSEvent) {
        // Command shortcuts (paste included) are not part of the vocabulary.
        guard !event.modifierFlags.contains(.command) else { return }
        if let key = Self.namedKeys[event.keyCode] {
            model?.key(key)
        } else if let characters = event.characters {
            model?.type(characters)
        }
    }

    static let namedKeys: [UInt16: NamedKey] = [
        36: .enter, 76: .enter, 48: .tab, 51: .backspace, 117: .delete, 53: .escape,
        123: .arrowLeft, 124: .arrowRight, 125: .arrowDown, 126: .arrowUp
    ]
}
