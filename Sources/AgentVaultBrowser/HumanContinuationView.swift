import AppKit
import WebKit

/// Dedicated view in which a person completes MFA or CAPTCHA. Agent Vault neither reads nor
/// types into it, and the same origin and subresource restrictions still apply.
@MainActor
public final class HumanContinuationView: NSView {
    public let kind: HumanStepKind
    public var onContinue: (@MainActor () -> Void)?
    public var onCancel: (@MainActor () -> Void)?

    init(webView: WKWebView, kind: HumanStepKind) {
        self.kind = kind
        super.init(frame: NSRect(x: 0, y: 0, width: 900, height: 760))
        let title = kind == .mfa ? "Complete the two-factor step yourself."
                                 : "Complete the verification challenge yourself."
        let label = NSTextField(wrappingLabelWithString: title + " Agent Vault does not bypass, read or automate this step.")
        let done = NSButton(title: "I finished — continue", target: self, action: #selector(finish))
        done.keyEquivalent = "\r"
        let cancel = NSButton(title: "Cancel and discard session", target: self, action: #selector(cancel))
        let buttons = NSStackView(views: [cancel, done])
        let header = NSStackView(views: [label, buttons])
        header.orientation = .horizontal
        header.spacing = 12
        header.edgeInsets = NSEdgeInsets(top: 10, left: 12, bottom: 10, right: 12)
        label.setContentHuggingPriority(.defaultLow, for: .horizontal)
        webView.removeFromSuperview()
        let column = NSStackView(views: [header, webView])
        column.orientation = .vertical
        column.spacing = 0
        column.alignment = .leading
        column.translatesAutoresizingMaskIntoConstraints = false
        addSubview(column)
        NSLayoutConstraint.activate([
            column.leadingAnchor.constraint(equalTo: leadingAnchor), column.trailingAnchor.constraint(equalTo: trailingAnchor),
            column.topAnchor.constraint(equalTo: topAnchor), column.bottomAnchor.constraint(equalTo: bottomAnchor),
            webView.widthAnchor.constraint(equalTo: column.widthAnchor), header.widthAnchor.constraint(equalTo: column.widthAnchor)
        ])
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError() }

    @objc private func finish() { onContinue?() }
    @objc private func cancel() { onCancel?() }
}
