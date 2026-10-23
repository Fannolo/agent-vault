@testable import AgentVaultWebHostProtocol
import AgentVaultContracts
import Foundation
import Testing

private let session = UUID(uuidString: "00000000-0000-4000-8000-000000000002")!
private let sessionText = session.uuidString
private let operation = UUID(uuidString: "00000000-0000-4000-8000-000000000003")!
private let target = SiteTarget(document: 3, control: 2, element: 7)!
private let account = CredentialVersion(item: UUID(uuidString: "00000000-0000-4000-8000-000000000004")!, version: 3)!

private func rejects(_ json: String) -> Bool { (try? HostWire.decodeRequest(Data(json.utf8))) == nil }
private func rejectsReply(_ json: String) -> Bool { (try? HostWire.decodeReply(Data(json.utf8))) == nil }

private let page = SiteObservation(
    document: 9, control: 2, mode: .agent, auth: .signedIn, origin: "https://example.test", path: "/notes", title: "Notes",
    elements: [SiteElement(ref: 0, role: .link, label: "Home", value: "https://example.test/home", options: [])!,
               SiteElement(ref: 4, role: .password, label: "Password", value: "", options: [])!,
               SiteElement(ref: 5, role: .select, label: "Priority", value: "low", options: ["low", "high"])!],
    text: ["Saved: one"])!

@Suite struct SiteWireTests {
    static let commands: [HostCommand] = [
        .openSite(session: session, site: .syntheticFixture, lifetime: 900), .siteObserve(session: session),
        .siteLogin(session: session, operation: operation, account: account, credential: credential),
        .siteOperate(session: session, operation: operation, command: .navigate("https://example.test/a?b=c")),
        .siteOperate(session: session, operation: operation, command: .click(target)),
        .siteOperate(session: session, operation: operation, command: .typePublic(target, "hello")),
        .siteOperate(session: session, operation: operation, command: .typePublic(target, "")),
        .siteOperate(session: session, operation: operation, command: .select(target, option: 1)),
        .siteOperate(session: session, operation: operation, command: .press(.tab)),
        .siteOperate(session: session, operation: operation, command: .scroll(dy: -300)),
        .siteTakeover(session: session), .siteRelease(session: session),
    ]

    @Test(arguments: commands) func everySiteCommandRoundTripsOnTheControlLane(_ command: HostCommand) throws {
        let request = HostRequest(id: 7, command: command)
        #expect(try HostWire.decodeRequest(try HostWire.encode(request)) == request)
        #expect(command.lane == .control && command.run == session)
    }

    @Test(arguments: [HostReply.site(page), .siteUnknown, .rejected(.staleTarget), .rejected(.credentialOrigin)])
    func siteRepliesRoundTrip(_ reply: HostReply) throws {
        let response = HostResponse(request: 9, run: session, reply: reply)
        #expect(try HostWire.decodeReply(try HostWire.encode(response)) == .response(response))
    }

    @Test(arguments: SiteAuth.allCases) func everyAuthStateRoundTrips(_ auth: SiteAuth) throws {
        let observation = SiteObservation(document: 1, control: 1, mode: .agent, auth: auth, origin: "", path: "", title: "",
                                          elements: [], text: [])!
        let response = HostResponse(request: 2, run: session, reply: .site(observation))
        #expect(try HostWire.decodeReply(try HostWire.encode(response)) == .response(response))
    }

    @Test func siteOperationsHaveExactlyTheirKeysAndBounds() {
        let click = #"{"op":"siteOperate","request":1,"run":"\#(sessionText)","operation":"\#(operation.uuidString)","action":"click","target":{"document":3,"control":2,"element":7}}"#
        #expect(!rejects(click))
        for (old, new) in [(#""element":7"#, #""element":7,"selector":"x""#), (#""element":7"#, #""element":4096"#),
                           (#""document":3"#, #""document":0"#), (#""control":2,"#, ""),
                           (#""action":"click""#, #""action":"evaluate""#), (#""action":"click""#, #""action":"fill""#),
                           (#""operation":"\#(operation.uuidString)","#, ""),
                           (#""action":"click""#, #""action":"click","script":"x""#)] {
            #expect(rejects(click.replacingOccurrences(of: old, with: new)), "\(new)")
        }
        func operate(_ fields: String) -> String {
            #"{"op":"siteOperate","request":1,"run":"\#(sessionText)","operation":"\#(operation.uuidString)",\#(fields)}"#
        }
        #expect(!rejects(operate(#""action":"navigate","url":"https://example.test/""#)))
        #expect(rejects(operate(#""action":"navigate","url":"https://example.test/\n""#)))
        #expect(rejects(operate(#""action":"navigate","url":"\#(String(repeating: "a", count: 2049))""#)))
        #expect(rejects(operate(#""action":"type","target":{"document":3,"control":2,"element":7},"text":"\#(String(repeating: "a", count: 1025))""#)))
        #expect(rejects(operate(#""action":"select","target":{"document":3,"control":2,"element":7},"option":256"#)))
        #expect(rejects(operate(#""action":"scroll","dy":0"#)))
        #expect(rejects(operate(#""action":"press","key":"F12""#)))
        // A login names the credential version it uses, exactly, and nothing derived from the secret.
        let secret = Data("u\np".utf8).base64EncodedString()
        func login(_ account: String) -> String {
            #"{"op":"siteLogin","request":1,"run":"\#(sessionText)","operation":"\#(operation.uuidString)",\#(account)"credential":"\#(secret)"}"#
        }
        let item = account.item.uuidString
        #expect(!rejects(login(#""account":{"item":"\#(item)","version":3},"#)))
        for bad in ["", #""account":{"item":"\#(item)"},"#, #""account":{"item":"\#(item)","version":0},"#,
                    #""account":{"item":"x","version":3},"#, #""account":{"item":"\#(item)","version":3,"digest":"ab"},"#] {
            #expect(rejects(login(bad)), "\(bad)")
        }
        // A site cannot be named as a workflow, nor a workflow as a site.
        #expect(rejects(#"{"op":"openSite","request":1,"run":"\#(sessionText)","site":"githubWebProfile","lifetime":60}"#))
        #expect(rejects(#"{"op":"start","request":1,"run":"\#(sessionText)","workflow":"syntheticFixture","credential":"\#(Data("u\np".utf8).base64EncodedString())","lifetime":60}"#))
        #expect(rejects(#"{"op":"openSite","request":1,"run":"\#(sessionText)","site":"syntheticFixture","lifetime":60,"url":"https://x"}"#))
    }

    @Test func observationsCarryNoPasswordValueAndFitTheReplyCap() throws {
        let encoded = String(decoding: try HostWire.encode(HostResponse(request: 1, run: session, reply: .site(page))), as: UTF8.self)
        let leaked = encoded.replacingOccurrences(of: #""label":"Password","options":[],"ref":4,"role":"password","value":"""#,
                                                  with: #""label":"Password","options":[],"ref":4,"role":"password","value":"hunter2""#)
        #expect(leaked != encoded && rejectsReply(leaked), "a password element with a value is malformed")
        #expect(rejectsReply(encoded.replacingOccurrences(of: #""title":"Notes""#, with: #""title":"Notes","cookie":"sid=1""#)))
        #expect(SiteElement(ref: 1, role: .password, label: "", value: "x", options: []) == nil)
        let huge = SiteObservation(
            document: 1, control: 1, mode: .agent, auth: .signedIn, origin: "https://example.test", path: "/", title: "",
            elements: (0..<256).map { SiteElement(ref: $0, role: .select, label: String(repeating: "l", count: 256), value: "",
                                                  options: Array(repeating: String(repeating: "o", count: 256), count: 256))! },
            text: Array(repeating: String(repeating: "t", count: 1024), count: 256))!
        #expect((try? HostWire.encode(HostResponse(request: 1, run: session, reply: .site(huge)))) == nil)
        let fitted = HostWire.fitted(huge)
        #expect(!fitted.elements.isEmpty)
        #expect(try HostWire.encode(HostResponse(request: HostWire.maximumCounter, run: session, reply: .site(fitted))).count
                <= HostWire.maximumReplyBytes)
    }

    @Test func siteCommandsAcceptOnlySiteReplies() {
        let operate = HostCommand.siteOperate(session: session, operation: operation, command: .press(.enter))
        #expect(HostReply.site(page).answers(operate) && HostReply.siteUnknown.answers(operate))
        #expect(!HostReply.profile(profile).answers(operate) && !HostReply.accepted.answers(operate))
        #expect(!HostReply.siteUnknown.answers(.siteObserve(session: session)), "an observation has no effect to be unknown")
        // An observation can fail; a change of control is always reported as an observation.
        #expect(HostReply.failed(.rendererUnavailable).answers(.siteObserve(session: session)))
        #expect(!HostReply.failed(.rendererUnavailable).answers(.siteTakeover(session: session)))
        #expect(!HostReply.failed(.rendererUnavailable).answers(.siteRelease(session: session)))
        #expect(!HostReply.site(page).answers(.start(run: session, workflow: .browserDemo, credential: credential, lifetime: 5)))
        #expect(!HostReply.site(page).answers(.classify(run: session)))
    }
}
