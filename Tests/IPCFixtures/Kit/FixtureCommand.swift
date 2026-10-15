import AgentVaultContracts
import AgentVaultIPC
import Foundation

/// Synthetic broker, bridge, human-app and attacker roles for the cross-process IPC proof.
/// Every value is synthetic. Each command prints exactly one JSON object on stdout.
public enum FixtureCommand {
    public enum Binary: String, Sendable { case genuine, impostor }

    public static func main(binary: Binary) -> Never {
        var args = Array(CommandLine.arguments.dropFirst())
        guard !args.isEmpty else { finish(["outcome": "usage"], status: 64) }
        let command = args.removeFirst()
        let options = parse(args)
        guard let path = options["config"], let configuration = load(path) else {
            finish(["outcome": IPCError.invalidConfiguration.rawValue], status: 65)
        }
        switch command {
        case "check-config":
            let role: IPCConfiguration.Role = switch options["role"] {
            case "read": .readClient
            case "admin": .adminClient
            default: .broker
            }
            do throws(IPCError) {
                try configuration.validate(for: role)
                finish(["outcome": "ok"])
            } catch {
                finish(["outcome": error.rawValue], status: 1)
            }
        case "serve": serve(configuration, binary: binary, options: options)
        default: run { await client(command, configuration, options: options) }
        }
    }

    // MARK: Broker

    private static func serve(_ configuration: IPCConfiguration, binary: Binary, options: [String: String]) -> Never {
        let delay = UInt64(options["delay-ms"].flatMap(Int.init) ?? 0)
        var limits = IPCLimits.standard
        if let value = options["per-connection"].flatMap(Int.init) { limits.maxInFlightPerConnection = value }
        let issued = Issued()
        let record = Recorder(path: options["record"])
        let accountID = UUID(uuidString: "00000000-0000-4000-8000-00000000a001")!
        let server: VaultXPCServer
        do {
            server = try VaultXPCServer(configuration: configuration, limits: limits, read: { uid, request in
                record.append("read \(request.operation.rawValue) uid=\(uid)")
                switch request.operation {
                case .accounts:
                    return ReadReply(.outcome(.completed), accounts: [AccountSummary(id: accountID, service: .demo)])
                case .run:
                    try await Task.sleep(nanoseconds: delay * 1_000_000)
                    let login = binary == .impostor ? "impostor" : "uid-\(uid)"
                    return ReadReply(.outcome(.completed), profile: AccountProfile(login: login, userID: Int(uid)))
                case .resume, .cancel:
                    return ReadReply(.failure(.accessDenied))
                }
            }, snapshot: { uid in
                record.append("snapshot uid=\(uid)")
                return AdminSnapshot(accounts: [AccountSummary(id: accountID, service: .demo)],
                                     clients: [ClientSummary(id: accountID, uid: uid, revoked: false)], grants: [],
                                     pending: [PendingSummary(id: accountID, clientID: accountID, accountID: accountID,
                                                              action: .demoStatus, expiresAt: Date() + 60,
                                                              status: "approved")],
                                     audit: [AuditSummary(timestamp: Date(), clientID: accountID, accountID: nil,
                                                          action: nil, outcome: "client_revoked")])
            }, begin: { uid, request in
                record.append("begin \(request.operation.rawValue) uid=\(uid)")
                guard request.operation != .enroll else { throw AdminRejection(status: "fixture_holds_no_credentials") }
                let challenge = AdminChallenge(id: UUID(), payload: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
                                               expiresAt: Date().addingTimeInterval(60))
                issued.insert(challenge.id)
                return challenge
            }, authorize: { uid, id, _ in
                record.append("authorize uid=\(uid)")
                return issued.consume(id) ? AdminReply(status: "applied", id: id) : AdminReply(status: "unknown_challenge")
            })
        } catch {
            finish(["outcome": error.rawValue], status: 1)
        }
        server.activate()
        dispatchMain()
    }

    // MARK: Clients

    private static func client(_ command: String, _ configuration: IPCConfiguration,
                               options: [String: String]) async -> [String: Any] {
        do throws(IPCError) {
            switch command {
            case "read":
                let client = try VaultReadClient(configuration: configuration, timeout: 10)
                let request = options["op"] == "accounts"
                    ? ReadRequest(operation: .accounts)
                    : ReadRequest(operation: .run, accountID: UUID(), action: .demoStatus)
                let reply = try await client.perform(request)
                return ["outcome": "ok", "status": reply.status, "login": reply.login ?? "",
                        "accounts": reply.accounts?.count ?? 0]
            case "admin":
                let client = try VaultAdminClient(configuration: configuration, timeout: 10)
                let snapshot = try await client.snapshot()
                guard case .challenge(let challenge) = try await client.begin(AdminRequest(operation: .prune)) else {
                    return ["outcome": "unexpected_rejection"]
                }
                guard case .rejected(let refused) = try await client.begin(AdminRequest(operation: .enroll).with {
                    $0.service = .demo; $0.credential = Data("SYNTHETIC".utf8)
                }) else { return ["outcome": "unexpected_challenge"] }
                let signature = Data(repeating: 0x5a, count: 64)
                let first = try await client.authorize(id: challenge.id, signature: signature)
                let replay = try await client.authorize(id: challenge.id, signature: signature)
                return ["outcome": "ok", "snapshotUID": snapshot.clients.first?.uid ?? 0,
                        "pendingStatus": snapshot.pending.first?.status ?? "", "audit": snapshot.audit.count,
                        "enroll": refused.status, "authorize": first.status, "replay": replay.status]
            case "burst":
                let client = try VaultReadClient(configuration: configuration, timeout: 10)
                let count = options["count"].flatMap(Int.init) ?? 12
                let outcomes = await withTaskGroup(of: String.self) { group in
                    for _ in 0..<count {
                        group.addTask {
                            do throws(IPCError) {
                                _ = try await client.perform(ReadRequest(operation: .run, accountID: UUID(),
                                                                         action: .demoStatus))
                                return "ok"
                            } catch { return error.rawValue }
                        }
                    }
                    return await group.reduce(into: [String: Int]()) { $0[$1, default: 0] += 1 }
                }
                return ["outcome": "ok", "counts": outcomes]
            default:
                return await RawProbe.run(command, configuration, options: options)
            }
        } catch {
            return ["outcome": error.rawValue]
        }
    }

    // MARK: Plumbing

    private static func parse(_ args: [String]) -> [String: String] {
        var options: [String: String] = [:]
        var index = 0
        while index + 1 < args.count, args[index].hasPrefix("--") {
            options[String(args[index].dropFirst(2))] = args[index + 1]
            index += 2
        }
        return options
    }

    private static func load(_ path: String) -> IPCConfiguration? {
        try? IPCConfiguration.load(contentsOf: path)
    }

    private static func run(_ body: @escaping @Sendable () async -> [String: Any]) -> Never {
        Task {
            let result = UncheckedResult(value: await body())
            finish(result.value)
        }
        dispatchMain()
    }

    static func finish(_ result: [String: Any], status: Int32 = 0) -> Never {
        let data = (try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])) ?? Data("{}".utf8)
        FileHandle.standardOutput.write(data + Data("\n".utf8))
        exit(status)
    }
}

private struct UncheckedResult: @unchecked Sendable { let value: [String: Any] }

/// Appends one line per handler call so the harness can prove which broker saw which call.
private final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private let handle: FileHandle?

    init(path: String?) {
        guard let path, FileManager.default.createFile(atPath: path, contents: nil,
                                                       attributes: [.posixPermissions: 0o600]) else {
            handle = nil
            return
        }
        handle = FileHandle(forWritingAtPath: path)
    }

    func append(_ line: String) {
        lock.withLock { handle?.write(Data((line + "\n").utf8)) }
    }
}

private final class Issued: @unchecked Sendable {
    private let lock = NSLock()
    private var ids: Set<UUID> = []
    func insert(_ id: UUID) { lock.withLock { _ = ids.insert(id) } }
    func consume(_ id: UUID) -> Bool { lock.withLock { ids.remove(id) != nil } }
}

extension AdminRequest {
    func with(_ body: (inout AdminRequest) -> Void) -> AdminRequest {
        var copy = self
        body(&copy)
        return copy
    }
}
