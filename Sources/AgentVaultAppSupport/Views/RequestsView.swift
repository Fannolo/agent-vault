import AgentVaultContracts
import SwiftUI

struct RequestsView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: "Requests", subtitle: "Frozen agent requests waiting for your decision.") { EmptyView() }
            if !model.humanSteps.isEmpty {
                List(model.humanSteps) { step in HumanStepRow(model: model, step: step) }
                    .frame(maxHeight: CGFloat(min(model.humanSteps.count, 3)) * 56 + 12)
                    .accessibilityIdentifier("human-steps")
            }
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
            } else if model.humanSteps.isEmpty {
                EmptyState(title: "Nothing waiting", detail: "Requests that need approval appear here.", symbol: "hand.raised")
            }
        }
    }
}

/// A paused sign-in step. Opening it needs a fresh signed approval naming this exact step.
struct HumanStepRow: View {
    let model: AppModel
    let step: HumanStepSummary

    var body: some View {
        HStack {
            Image(systemName: step.kind == .mfa ? "lock.shield" : "puzzlepiece")
            VStack(alignment: .leading, spacing: 2) {
                Text("\(step.service.displayName) sign-in needs you · \(step.kind.displayName)").font(.headline)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let left = max(0, Int(step.expiresAt.timeIntervalSince(context.date)))
                    Text("Account \(shortID(step.accountID)) · request \(shortID(step.runID)) · step \(step.epoch) · "
                         + String(format: "%d:%02d left", left / 60, left % 60))
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
            }
            Spacer()
            Button("Open") { Task { await model.openHumanStep(step) } }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy || model.humanStep != nil || step.expiresAt <= Date())
        }
        .padding(.vertical, 4)
    }
}
