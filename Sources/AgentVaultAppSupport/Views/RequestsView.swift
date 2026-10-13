import AgentVaultContracts
import SwiftUI

struct RequestsView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: "Requests", subtitle: "Frozen agent requests waiting for your decision.") { EmptyView() }
            if !model.pendingItems.isEmpty {
                List(model.pendingItems) { item in
                    let request = item.summary
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(request.action.rawValue).font(.headline.monospaced())
                            Text("Client \(shortID(request.clientID)) → account \(shortID(request.accountID)) · expires \(request.expiresAt.formatted(date: .omitted, time: .shortened))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if item.state != .waiting {
                            Text(item.state == .approved ? "Approved — waiting for the agent" : "Status not recognized")
                                .foregroundStyle(.secondary)
                        } else {
                        Button("Reject") { Task { await model.reject(request) } }.disabled(model.isBusy)
                        Button("Approve") { Task { await model.approve(request) } }
                            .buttonStyle(.borderedProminent).disabled(model.isBusy)
                        }
                    }
                    .padding(.vertical, 4)
                }
            } else {
                EmptyState(title: "Nothing waiting", detail: "Requests that need approval appear here.", symbol: "hand.raised")
            }
        }
    }
}
