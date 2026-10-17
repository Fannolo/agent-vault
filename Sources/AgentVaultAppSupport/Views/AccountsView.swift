import AgentVaultContracts
import SwiftUI

/// Credential fields live only in this view's state and are cleared as soon as the request is sent.
struct CredentialForm: View {
    let service: WireService
    @Binding var username: String
    @Binding var secret: String
    var body: some View {
        if service.usesPassword {
            TextField("Username", text: $username).textContentType(.username).autocorrectionDisabled()
            SecureField("Password", text: $secret).textContentType(.password)
        } else {
            SecureField(service == .github ? "Personal access token" : "Credential", text: $secret)
        }
    }
}

struct EnrollSheet: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var service = WireService.github
    @State private var username = ""
    @State private var secret = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add account").font(.title3.weight(.semibold))
            Picker("Service", selection: $service) {
                ForEach(model.features.enrollableServices, id: \.self) { Text($0.displayName).tag($0) }
            }
            CredentialForm(service: service, username: $username, secret: $secret)
            Text("The credential goes only to the broker. This app never stores it. You will be asked to approve with Touch ID or your password.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { clear(); dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add Account") {
                    let (name, value, chosen) = (username, secret, service)
                    clear()
                    Task { if await model.enroll(service: chosen, secret: value, username: name) { dismiss() } }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(secret.isEmpty || (service.usesPassword && username.isEmpty) || model.isBusy)
            }
        }
        .padding(22).frame(width: 440)
        .onDisappear(perform: clear)
    }

    private func clear() { secret = ""; username = "" }
}

struct RotateSheet: View {
    let model: AppModel
    let account: AccountSummary
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var secret = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Replace credential").font(.title3.weight(.semibold))
            Text("\(account.service.displayName) · \(shortID(account.id))").foregroundStyle(.secondary)
            CredentialForm(service: account.service, username: $username, secret: $secret)
            HStack {
                Spacer()
                Button("Cancel") { clear(); dismiss() }.keyboardShortcut(.cancelAction)
                Button("Replace") {
                    let (name, value) = (username, secret)
                    clear()
                    Task { if await model.rotate(account: account, secret: value, username: name) { dismiss() } }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(secret.isEmpty || (account.service.usesPassword && username.isEmpty) || model.isBusy)
            }
        }
        .padding(22).frame(width: 440)
        .onDisappear(perform: clear)
    }

    private func clear() { secret = ""; username = "" }
}

struct AccountsView: View {
    let model: AppModel
    @State private var rotating: AccountSummary?
    @State private var deleting: AccountSummary?

    var body: some View {
        VStack(spacing: 0) {
            ScreenHeader(title: "Accounts", subtitle: "Credentials held by the broker. Agents never receive them.") {
                Button { model.sheet = .enroll } label: { Label("Add Account", systemImage: "plus") }
                    .disabled(model.brokerReachable != true)
            }
            if let accounts = model.snapshot?.accounts, !accounts.isEmpty {
                List(accounts) { account in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(account.service.displayName).font(.headline)
                            Text("\(shortID(account.id)) · \(account.status)").font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Replace…") { rotating = account }
                        Button("Delete…", role: .destructive) { deleting = account }
                    }
                    .padding(.vertical, 4)
                }
            } else {
                EmptyState(title: "No accounts", detail: model.brokerReachable == true
                           ? "Add an account to let approved agents use it." : "Connect to the broker to manage accounts.",
                           symbol: "person.crop.circle")
            }
        }
        .sheet(item: $rotating) { RotateSheet(model: model, account: $0) }
        .confirmationDialog("Delete this account and its stored credential?", isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }), presenting: deleting) { account in
            Button("Delete Account", role: .destructive) { Task { await model.delete(account: account) } }
        } message: { account in
            Text("\(account.service.displayName) \(shortID(account.id)). Its grants stop working.")
        }
    }
}
