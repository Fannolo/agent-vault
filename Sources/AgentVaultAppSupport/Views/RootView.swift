import AgentVaultContracts
import SwiftUI

extension AppSection {
    var title: String {
        switch self {
        case .accounts: "Accounts"
        case .clients: "Clients"
        case .grants: "Grants"
        case .requests: "Requests"
        case .audit: "Audit"
        case .approvalKey: "Approval Key"
        }
    }
    var symbol: String {
        switch self {
        case .accounts: "person.crop.circle.badge.checkmark"
        case .clients: "app.connected.to.app.below.fill"
        case .grants: "checkmark.shield"
        case .requests: "hand.raised"
        case .audit: "list.bullet.rectangle"
        case .approvalKey: "key"
        }
    }
}

public struct RootView: View {
    @Bindable var model: AppModel

    public init(model: AppModel) { self.model = model }

    public var body: some View {
        NavigationSplitView {
            List(AppSection.allCases, selection: Binding(get: { model.selection }, set: { model.selection = $0 ?? .accounts })) { section in
                Label(section.title, systemImage: section.symbol)
                    .badge(section == .requests ? (model.snapshot?.pending.count ?? 0) : 0)
                    .tag(section)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
            .safeAreaInset(edge: .bottom) { BrokerStatus(model: model).padding(10) }
        } detail: {
            VStack(spacing: 0) {
                if let notice = model.notice { NoticeBar(notice: notice) { model.notice = nil } }
                switch model.selection {
                case .accounts: AccountsView(model: model)
                case .clients: ClientsView(model: model)
                case .grants: GrantsView(model: model)
                case .requests: RequestsView(model: model)
                case .audit: AuditView(model: model)
                case .approvalKey: ApprovalKeyView(model: model)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .frame(minWidth: 860, minHeight: 540)
        .sheet(item: $model.sheet) { sheet in
            switch sheet {
            case .enroll: EnrollSheet(model: model)
            case .pair: PairSheet(model: model)
            case .grant: GrantSheet(model: model, clients: model.snapshot?.clients ?? [], accounts: model.snapshot?.accounts ?? [])
            }
        }
        .task { await model.refresh() }
    }
}

struct BrokerStatus: View {
    let model: AppModel
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(text).font(.caption).foregroundStyle(.secondary)
            Spacer()
            Button { Task { await model.refresh() } } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless).help("Refresh").disabled(model.isBusy)
        }
    }
    private var color: Color { model.brokerReachable == true ? .green : (model.brokerReachable == false ? .red : .gray) }
    private var text: String {
        switch model.brokerReachable {
        case .some(true): "Broker connected"
        case .some(false): "Broker not connected"
        case .none: "Checking broker…"
        }
    }
}

struct NoticeBar: View {
    let notice: Notice
    let dismiss: () -> Void
    var body: some View {
        HStack {
            Image(systemName: notice.kind == .success ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
            Text(notice.text).lineLimit(3)
            Spacer()
            Button("Dismiss", action: dismiss).buttonStyle(.borderless)
        }
        .padding(10)
        .background((notice.kind == .success ? Color.green : Color.orange).opacity(0.18))
        .accessibilityIdentifier("notice-bar")
    }
}

struct EmptyState: View {
    let title: String
    let detail: String
    let symbol: String
    var body: some View {
        ContentUnavailableView(title, systemImage: symbol, description: Text(detail))
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ScreenHeader<Trailing: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var trailing: Trailing
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title2.weight(.semibold))
                Text(subtitle).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            trailing
        }
        .padding([.horizontal, .top], 20).padding(.bottom, 10)
    }
}

func shortID(_ id: UUID) -> String { AdminSummary.short(id) }
