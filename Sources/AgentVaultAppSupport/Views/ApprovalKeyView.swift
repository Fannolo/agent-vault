import SwiftUI

struct ApprovalKeyView: View {
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ScreenHeader(title: "Approval Key", subtitle: "Signs your approvals. The private key never leaves this Mac's secure hardware or Keychain.") { EmptyView() }
            VStack(alignment: .leading, spacing: 12) {
                if let registration = model.registration {
                    LabeledContent("Protection", value: label(registration.protection))
                    Text("SHA-256 fingerprint: \(registration.sha256Fingerprint)")
                        .font(.caption.monospaced()).textSelection(.enabled)
                    if registration.protection == .softwareFixture {
                        Label("Preview key: not protected. Never use this build to approve real changes.", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    Text("Public key to register with the broker installer (base64, X9.63 P-256):").font(.callout)
                    Text(registration.publicKeyBase64).font(.caption.monospaced()).textSelection(.enabled)
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                    Button("Copy Public Key") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(registration.publicKeyBase64, forType: .string)
                    }
                    if registration.protection != .softwareFixture {
                        Button("Test Approval") { Task { await model.testApprovalKey() } }
                            .disabled(model.approvalKeyTest == .testing)
                        switch model.approvalKeyTest {
                        case .notTested: Text("Test a local approval using Touch ID or your Mac password.")
                        case .testing: ProgressView("Waiting for macOS approval…")
                        case .passed: Label("Approval test passed", systemImage: "checkmark.shield.fill")
                        case .cancelled: Text("Approval test cancelled. You can try again.")
                        case .failed: Text("Approval test failed. The protected key could not be verified.")
                        }
                    }
                } else if let problem = model.keyProblem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Button("Try Again") { Task { await model.loadApprovalKey() } }
                } else {
                    Text("No approval key has been loaded yet.")
                    Button("Create or Load Approval Key") { Task { await model.loadApprovalKey() } }
                }
            }
            .padding(.horizontal, 20)
            Spacer()
        }
        .task { if model.registration == nil && model.keyProblem == nil { await model.loadApprovalKey() } }
    }

    private func label(_ protection: ApprovalKeyProtection) -> String {
        switch protection {
        case .secureEnclave: "Secure Enclave + user presence"
        case .keychainUserPresence: "Keychain + user presence"
        case .softwareFixture: "Software fixture (preview only)"
        }
    }
}
