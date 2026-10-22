import AgentVaultContracts
import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct AuditView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: "Audit", subtitle: "Who asked for what and the outcome. Metadata only; no credentials or results.") {
                HStack {
                    Button { Task { await model.refreshAudit() } } label: { Label("Reload", systemImage: "arrow.clockwise") }
                    Button { export() } label: { Label("Export…", systemImage: "square.and.arrow.up") }
                        .disabled(model.audit.isEmpty)
                }
            }
            switch model.auditStatus {
            case .loaded where model.audit.isEmpty:
                EmptyState(title: "No audit entries", detail: "Activity will appear here.", symbol: "list.bullet.rectangle")
            case .loaded:
                Table(model.audit) {
                    TableColumn("Time") { Text($0.timestamp.formatted(date: .abbreviated, time: .standard)) }.width(min: 190)
                    TableColumn("Client") { Text(shortID($0.clientID)).monospaced() }
                    TableColumn("Account") { Text($0.accountID.map(shortID) ?? "–").monospaced() }
                    TableColumn("Action") { Text($0.action ?? "–").monospaced() }
                    TableColumn("Outcome") { Text($0.outcome) }
                }
            case .unavailable:
                EmptyState(title: "Audit unavailable", detail: "The broker is not connected or does not expose its audit log yet.", symbol: "exclamationmark.triangle")
            case .notLoaded:
                EmptyState(title: "Audit not loaded", detail: "Choose Reload to read the broker's audit log.", symbol: "list.bullet.rectangle")
            }
        }
        .task { await model.refreshAudit() }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "agent-vault-audit.json"
        panel.message = "Exports safe metadata only: time, client, account, action and outcome."
        if panel.runModal() == .OK, let url = panel.url { model.exportAudit(to: url) }
    }
}
