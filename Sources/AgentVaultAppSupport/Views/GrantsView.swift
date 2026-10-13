import AgentVaultContracts
import SwiftUI

struct GrantSheet: View {
    let model: AppModel
    let clients: [ClientSummary]
    let accounts: [AccountSummary]
    @Environment(\.dismiss) private var dismiss
    @State private var clientID: UUID?
    @State private var accountID: UUID?
    @State private var duration = GrantDuration.oneHour
    @State private var calls = 10
    @State private var always = true

    private var plan: GrantPlan? {
        guard let clientID, let accountID else { return nil }
        return GrantPlan(clientID: clientID, accountID: accountID, duration: duration, callLimit: calls, alwaysRequireApproval: always)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("New grant").font(.title3.weight(.semibold))
            Picker("Client", selection: $clientID) {
                Text("Choose…").tag(UUID?.none)
                ForEach(clients.filter { !$0.revoked }) { Text("Client \(shortID($0.id)) · UID \($0.uid)").tag(Optional($0.id)) }
            }
            Picker("Account", selection: $accountID) {
                Text("Choose…").tag(UUID?.none)
                ForEach(accounts) { Text("\($0.service.displayName) · \(shortID($0.id))").tag(Optional($0.id)) }
            }
            Picker("Expires after", selection: $duration) {
                ForEach(GrantDuration.allCases) { Text($0.label).tag($0) }
            }
            Stepper("Calls allowed: \(calls)", value: $calls, in: 1...GrantPlan.maxCalls)
            Toggle("Require my approval for every call", isOn: $always)
            if let plan { Text(AdminSummary.text(for: plan.request) + " for \(duration.label).").font(.callout).foregroundStyle(.secondary) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Create Grant") {
                    guard let plan else { return }
                    Task { if await model.grant(plan) { dismiss() } }
                }
                .keyboardShortcut(.defaultAction).disabled(plan == nil || model.isBusy)
            }
        }
        .padding(22).frame(width: 480)
    }
}

struct GrantsView: View {
    let model: AppModel
    @State private var revoking: GrantSummary?

    var body: some View {
        let snapshot = model.snapshot
        VStack(spacing: 0) {
            ScreenHeader(title: "Grants", subtitle: "Exact permission for one client to use one account.") {
                Button { model.sheet = .grant } label: { Label("New Grant", systemImage: "plus") }
                    .disabled(snapshot == nil || snapshot?.accounts.isEmpty == true || snapshot?.clients.contains { !$0.revoked } != true)
            }
            if let grants = snapshot?.grants, !grants.isEmpty {
                List(grants) { grant in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Client \(shortID(grant.clientID)) → account \(shortID(grant.accountID))").font(.headline)
                            Text(detail(grant)).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if grant.revoked { Text("Revoked").foregroundStyle(.secondary) }
                        else { Button("Revoke…", role: .destructive) { revoking = grant } }
                    }
                    .padding(.vertical, 4)
                }
            } else {
                EmptyState(title: "No grants", detail: "Agents can do nothing until you create a grant.", symbol: "checkmark.shield")
            }
        }
        .confirmationDialog("Revoke this grant?", isPresented: Binding(
            get: { revoking != nil }, set: { if !$0 { revoking = nil } }), presenting: revoking) { grant in
            Button("Revoke Grant", role: .destructive) { Task { await model.revoke(grant: grant) } }
        } message: { _ in Text("The client loses access immediately and any browser session is discarded.") }
    }

    private func detail(_ grant: GrantSummary) -> String {
        "\(grant.callsRemaining) calls left · expires \(grant.expiresAt.formatted(date: .abbreviated, time: .shortened))"
            + (grant.requiresApproval ? " · every call needs approval" : "")
    }
}
