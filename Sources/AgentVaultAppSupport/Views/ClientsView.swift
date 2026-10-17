import AgentVaultContracts
import SwiftUI

struct PairSheet: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var uidText = ""
    @State private var result: UUID?

    private var uid: UInt32? { UInt32(uidText.trimmingCharacters(in: .whitespaces)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Pair client").font(.title3.weight(.semibold))
            if let result {
                Text("Paired. Configure the MCP client with this ID:")
                Text(result.uuidString).font(.body.monospaced()).textSelection(.enabled)
                HStack {
                    Button("Copy ID") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(result.uuidString, forType: .string)
                    }
                    Spacer()
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            } else {
                TextField("Client user ID (UID)", text: $uidText)
                Text("The macOS user ID the agent's bridge runs as. The broker identifies the client by this UID, not by anything the agent says.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Pair") {
                        guard let uid else { return }
                        Task { if await model.pair(uid: uid) { result = model.lastPairedClientID } }
                    }
                    .keyboardShortcut(.defaultAction).disabled(uid == nil || model.isBusy)
                }
            }
        }
        .padding(22).frame(width: 440)
    }
}

struct ClientsView: View {
    let model: AppModel
    @State private var revoking: ClientSummary?

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: "Clients", subtitle: "Agent bridges the broker recognizes by authenticated user ID.") {
                Button { model.sheet = .pair } label: { Label("Pair Client", systemImage: "plus") }
                    .disabled(model.brokerReachable != true)
            }
            if let clients = model.snapshot?.clients, !clients.isEmpty {
                List(clients) { client in
                    HStack {
                        VStack(alignment: .leading) {
                            Text("Client \(shortID(client.id))").font(.headline)
                            Text("UID \(client.uid)").font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if client.revoked { Text("Revoked").foregroundStyle(.secondary) }
                        else { Button("Revoke…", role: .destructive) { revoking = client } }
                    }
                    .padding(.vertical, 4)
                }
            } else {
                EmptyState(title: "No paired clients", detail: "Pair a client before creating grants.", symbol: "app.connected.to.app.below.fill")
            }
        }
        .confirmationDialog("Revoke this client?", isPresented: Binding(
            get: { revoking != nil }, set: { if !$0 { revoking = nil } }), presenting: revoking) { client in
            Button("Revoke Client", role: .destructive) { Task { await model.revoke(client: client) } }
        } message: { _ in Text("All of its grants stop immediately and any browser session is discarded.") }
    }
}
