@testable import AgentVaultIPC
import AgentVaultContracts
import AgentVaultCore
import Foundation
import Testing

/// The fixed read and signed admin operations, over real Unix sockets, into the real broker
/// through the daemon's own handler composition.
@Suite(.serialized) struct BrokerSocketTests {
    @Test func signedAdministrationAndReadsRoundTripThroughSocketsIntoTheBroker() async throws {
        let rig = try BrokerRig()
        try await withStack(handlers: rig.handlers) { stack in
            let admin = stack.adminClient(), read = stack.readClient()
            #expect(try await admin.snapshot().accounts.isEmpty)

            func signed(_ request: AdminRequest) async throws -> AdminReply {
                guard case .challenge(let challenge) = try await admin.begin(request) else { throw Unexpected(what: "challenge") }
                return try await admin.authorize(id: challenge.id, signature: try rig.sign(challenge))
            }
            var enroll = AdminRequest(operation: .enroll); enroll.service = .demo; enroll.credential = canary
            let enrolled = try await signed(enroll)
            #expect(enrolled.status == "completed")
            let accountID = try #require(enrolled.id)

            // A signature over a different challenge, and a replay, change nothing.
            var pair = AdminRequest(operation: .pairClient); pair.uid = me
            guard case .challenge(let first) = try await admin.begin(pair),
                  case .challenge(let second) = try await admin.begin(pair) else { throw Unexpected(what: "challenges") }
            #expect(try await admin.authorize(id: second.id, signature: try rig.sign(first)).status == VaultError.denied.rawValue)
            #expect(try await admin.authorize(id: first.id, signature: try rig.sign(first)).status == "completed")
            #expect(try await admin.authorize(id: first.id, signature: try rig.sign(first)).status == VaultError.denied.rawValue)
            #expect(try rig.state.snapshot().clients.count == 1)

            // Pairing another UID is refused by the broker's policy, before any challenge exists.
            var foreign = AdminRequest(operation: .pairClient); foreign.uid = stranger
            guard case .rejected = try await admin.begin(foreign) else { throw Unexpected(what: "rejection") }

            // The read socket has no grant yet: the kernel UID maps to the paired client only.
            #expect(try await read.perform(ReadRequest(operation: .accounts)).accounts?.isEmpty == true)
            let clientID = try #require(rig.state.snapshot().clients.first?.id)
            var grant = AdminRequest(operation: .grant)
            grant.clientID = clientID; grant.accountID = accountID
            grant.duration = 300; grant.callLimit = 3; grant.requiresApproval = false
            #expect(try await signed(grant).status == "completed")

            #expect(try await read.perform(ReadRequest(operation: .accounts)).accounts?.map(\.id) == [accountID])
            let ran = try await read.perform(ReadRequest(operation: .run, accountID: accountID, action: .demoStatus))
            #expect(ran.status == "ready")
            #expect(try await admin.snapshot().grants.first?.callsRemaining == 2)

            // No reply on either socket carries the enrolled credential.
            let raw = try RawPeer(stack.configuration.admin.path)
            defer { raw.close() }
            #expect(raw.request(id: 9, .snapshot, Data()))
            guard case .reply(9, let body) = raw.read(within: 3) else { throw Unexpected(what: "raw snapshot") }
            #expect(body.range(of: canary) == nil && body.range(of: Data(accountID.uuidString.utf8)) != nil)
        }
    }

    @Test func disconnectCancelsTheBrokerReadButAdminMutationsComplete() async throws {
        let events = Events()
        let rig = try BrokerRig(adapter: BlockingAdapter(events: events),
                                secrets: MemorySecrets(saveDelay: 0.5, events: events))
        let account = try await rig.broker.enroll(service: .demo, credential: canary)
        let client = try await rig.broker.registerClient(uid: me)
        _ = try await rig.broker.grant(clientID: client.id, accountID: account.id, duration: 300, callLimit: 5)

        try await withStack(handlers: rig.handlers) { stack in
            let read = stack.readClient()
            let pending = Task { try? await read.perform(ReadRequest(operation: .run, accountID: account.id, action: .demoStatus)) }
            #expect(await events.await("adapter started"))
            await read.close()
            #expect(await events.await("adapter cancelled"), "the broker read stops with its connection")
            #expect(await pending.value == nil)

            // A signed rotation whose connection closes mid-mutation still completes, exactly once.
            let admin = stack.adminClient()
            var rotate = AdminRequest(operation: .rotate); rotate.accountID = account.id; rotate.credential = rotatedCanary
            guard case .challenge(let challenge) = try await admin.begin(rotate) else { throw Unexpected(what: "challenge") }
            let signature = try rig.sign(challenge)
            let saved = events.count("saved")
            let call = Task { () -> IPCError? in
                do { _ = try await admin.authorize(id: challenge.id, signature: signature); return nil }
                catch { return error as? IPCError }
            }
            try await Task.sleep(for: .milliseconds(150))
            await admin.close()
            #expect(await call.value == .connectionFailed, "the outcome is reported unknown, not retried")
            var rotated: Account?
            for _ in 0..<150 {
                if let current = try rig.state.snapshot().accounts.first, current.lifecycle == .active,
                   current.credentialID != account.credentialID { rotated = current; break }
                try await Task.sleep(for: .milliseconds(20))
            }
            let current = try #require(rotated)
            #expect(try rig.secrets.load(for: current.credentialID) == rotatedCanary)
            #expect(events.count("saved") == saved + 1)
            let fresh = stack.adminClient()
            #expect(try await fresh.snapshot().accounts.map(\.status) == ["active"])
        }
    }
}
