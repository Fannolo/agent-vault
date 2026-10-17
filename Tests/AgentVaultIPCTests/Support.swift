@testable import AgentVaultIPC
import AgentVaultContracts
import Foundation
import Security

/// Signing identity of the process running the tests, read with public Security.framework API.
let host: (cdhash: String, identifier: String) = {
    var code: SecCode?
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
          let info = info as? [String: Any], let unique = info[kSecCodeInfoUnique as String] as? Data,
          let identifier = info[kSecCodeInfoIdentifier as String] as? String else {
        fatalError("test host is not signed")
    }
    return (unique.map { String(format: "%02x", $0) }.joined(), identifier)
}()
let hostCDHash = host.cdhash

let wrongCDHash = String(repeating: "0", count: 40)
let me = UInt32(getuid())

/// Three distinct requirement texts that all pin this process, so one process can play every role.
func pinned(_ hash: String = hostCDHash) -> (broker: String, read: String, admin: String) {
    ("cdhash H\"\(hash)\"", "identifier \"\(host.identifier)\" and cdhash H\"\(hash)\"",
     "cdhash H\"\(hash)\" and identifier \"\(host.identifier)\"")
}

func developmentConfiguration(broker: String = pinned().broker, read: String = pinned().read,
                              admin: String = pinned().admin, brokerUID: UInt32 = me,
                              allowedUID: UInt32 = me) -> IPCConfiguration {
    IPCConfiguration(readServiceName: "dev.agentvault.test.read", adminServiceName: "dev.agentvault.test.admin",
                     brokerRequirement: broker, readRequirement: read, adminRequirement: admin,
                     brokerUID: brokerUID, allowedUID: allowedUID, development: true)
}

let productionRequirements = (
    broker: #"anchor apple generic and identifier "dev.agentvault.broker" and certificate leaf[subject.OU] = "3JWAQ92CB4" and cdhash H"0000000000000000000000000000000000000000""#,
    read: #"anchor apple generic and identifier "dev.agentvault.bridge" and certificate leaf[subject.OU] = "3JWAQ92CB4" and cdhash H"0000000000000000000000000000000000000000""#,
    admin: #"anchor apple generic and identifier "dev.agentvault.app" and certificate leaf[subject.OU] = "3JWAQ92CB4" and cdhash H"0000000000000000000000000000000000000000""#
)

func productionConfiguration(brokerUID: UInt32 = 260, allowedUID: UInt32 = 501) -> IPCConfiguration {
    IPCConfiguration(readServiceName: "dev.agentvault.broker.read",
                     adminServiceName: "dev.agentvault.broker.admin",
                     brokerRequirement: productionRequirements.broker, readRequirement: productionRequirements.read,
                     adminRequirement: productionRequirements.admin, brokerUID: brokerUID, allowedUID: allowedUID,
                     development: false)
}

final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [UInt32] = []
    func record(_ uid: UInt32) { lock.withLock { values.append(uid) } }
    var uids: [UInt32] { lock.withLock { values } }
}

/// A broker on anonymous listeners plus clients connected to it, all inside the test process.
final class Loopback: @unchecked Sendable {
    let server: VaultXPCServer
    let readEndpoint: NSXPCListenerEndpoint
    let adminEndpoint: NSXPCListenerEndpoint
    let recorder = Recorder()
    let clientConfiguration: IPCConfiguration

    init(server serverConfiguration: IPCConfiguration = developmentConfiguration(),
         client: IPCConfiguration = developmentConfiguration(), limits: IPCLimits = .standard,
         read: VaultXPCServer.ReadHandler? = nil, snapshot: VaultXPCServer.SnapshotHandler? = nil,
         begin: VaultXPCServer.BeginHandler? = nil, authorize: VaultXPCServer.AuthorizeHandler? = nil,
         continuation: VaultXPCServer.ContinuationHandler? = nil, closed: VaultXPCServer.ClosedHandler? = nil) {
        let readListener = NSXPCListener.anonymous(), adminListener = NSXPCListener.anonymous()
        let recorder = recorder
        let handlers = VaultXPCServer.Handlers(
            read: read ?? { uid, request in
                recorder.record(uid)
                return ReadReply(.outcome(.completed), profile: AccountProfile(login: "uid-\(uid)", userID: Int(uid)))
            },
            snapshot: snapshot ?? { uid in
                recorder.record(uid)
                return AdminSnapshot(accounts: [], clients: [ClientSummary(id: UUID(), uid: uid, revoked: false)],
                                     grants: [], pending: [])
            },
            begin: begin ?? { _, _ in
                AdminChallenge(id: UUID(), payload: Data(repeating: 7, count: 32), expiresAt: Date() + 60)
            },
            authorize: authorize ?? { _, id, _ in AdminReply(status: "applied", id: id) },
            continuation: continuation ?? { _, _ in .noFrame }, closed: closed ?? { _ in })
        server = VaultXPCServer(validated: serverConfiguration, limits: limits, readListener: readListener,
                                adminListener: adminListener, handlers: handlers)
        server.activate()
        readEndpoint = readListener.endpoint
        adminEndpoint = adminListener.endpoint
        clientConfiguration = client
    }

    func readClient(timeout: TimeInterval = 3) -> VaultReadClient {
        VaultReadClient(validated: clientConfiguration, endpoint: readEndpoint, timeout: timeout)
    }

    func adminClient(timeout: TimeInterval = 3) -> VaultAdminClient {
        VaultAdminClient(validated: clientConfiguration, endpoint: adminEndpoint, timeout: timeout)
    }

    deinit { server.invalidate() }
}

func json(_ text: String) -> Data { Data(text.utf8) }
