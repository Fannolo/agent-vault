@testable import AgentVaultWebHostProtocol
import AgentVaultContracts
import Foundation
import Testing

private let run = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!
private let runText = run.uuidString

private func text(_ data: Data) -> String { String(decoding: data, as: UTF8.self) }
private func data(_ text: String) -> Data { Data(text.utf8) }
private func base64(_ text: String) -> String { Data(text.utf8).base64EncodedString() }

private func rejectsCommand(_ json: String) -> Bool {
    (try? HostWire.decodeRequest(data(json))) == nil
}

private func rejectsReply(_ json: String) -> Bool {
    (try? HostWire.decodeReply(data(json))) == nil
}

@Suite struct HostWireTests {
    static let batch = HumanInputBatch([.pointer(.down, x: 0, y: 0), .pointer(.up, x: 1279, y: 899),
                                        .wheel(dx: -2000, dy: 5), .key(.enter), .text("123456")])!

    static let commands: [HostCommand] = [
        .start(run: run, workflow: .githubWebProfile, credential: credential, lifetime: 900),
        .start(run: run, workflow: .browserDemo, credential: credential, lifetime: 1),
        .classify(run: run), .end(run: run), .showHuman(run: run, step: 1),
        .frame(run: run, step: 3, after: 0), .input(run: run, step: 3, frame: 9, batch: batch)
    ]

    @Test(arguments: commands) func everyCommandRoundTripsExactly(_ command: HostCommand) throws {
        let request = HostRequest(id: 7, command: command)
        let encoded = try HostWire.encode(request)
        #expect(try HostWire.decodeRequest(encoded) == request)
        #expect(encoded.count <= HostWire.maximumCommandBytes)
    }

    static let replies: [HostReply] = [
        .profile(profile), .humanStep(.captcha), .failed(.challengeOriginBlocked),
        .frame(step: 2, HumanFrame(sequence: 5, width: 1280, height: 900, jpeg: tinyJPEG)!), .noFrame(step: 2),
        .accepted, .ended, .rejected(.staleStep)
    ]

    @Test(arguments: replies) func everyReplyRoundTripsExactly(_ reply: HostReply) throws {
        let response = HostResponse(request: 9, run: run, reply: reply)
        #expect(try HostWire.decodeReply(try HostWire.encode(response)) == .response(response))
    }

    @Test func maximalFrameFitsTheReplyCap() throws {
        var jpeg = Data(repeating: 0x5A, count: HumanFrame.maximumJPEGBytes)
        jpeg.replaceSubrange(0..<2, with: [0xFF, 0xD8]); jpeg.replaceSubrange(jpeg.count - 2..<jpeg.count, with: [0xFF, 0xD9])
        let frame = HumanFrame(sequence: HumanFrame.maximumSequence, width: 1280, height: 900, jpeg: jpeg)!
        let encoded = try HostWire.encode(HostResponse(request: HostWire.maximumCounter, run: run,
                                                       reply: .frame(step: HostWire.maximumCounter, frame)))
        #expect(encoded.count <= HostWire.maximumReplyBytes)
        #expect(HumanFrame(sequence: 1, width: 1, height: 1, jpeg: jpeg + Data([0xFF, 0xD9])) == nil)
    }

    @Test func startHasExactlyItsKeys() {
        let valid = #"{"op":"start","request":1,"run":"\#(runText)","workflow":"githubWebProfile","credential":"\#(base64("u\np"))","lifetime":60}"#
        #expect(!rejectsCommand(valid))
        // Missing, extra, null, duplicate and renamed keys.
        #expect(rejectsCommand(#"{"op":"start","request":1,"run":"\#(runText)","workflow":"githubWebProfile","lifetime":60}"#))
        #expect(rejectsCommand(valid.replacingOccurrences(of: #""lifetime":60"#, with: #""lifetime":60,"url":"https://evil""#)))
        #expect(rejectsCommand(valid.replacingOccurrences(of: #""lifetime":60"#, with: #""lifetime":null"#)))
        #expect(rejectsCommand(valid.replacingOccurrences(of: #""lifetime":60"#, with: #""lifetime":60,"lifetime":61"#)))
        #expect(rejectsCommand(valid.replacingOccurrences(of: #""op":"start""#, with: #""op":"evaluate""#)))
        #expect(rejectsCommand(valid.replacingOccurrences(of: "githubWebProfile", with: "https://github.com")))
        // Lifetime bounds and number forms.
        for bad in ["0", "901", "60.0", "6e1", "true", "\"60\"", "-1", "99999999999999999999"] {
            #expect(rejectsCommand(valid.replacingOccurrences(of: #""lifetime":60"#, with: #""lifetime":\#(bad)"#)), "lifetime \(bad)")
        }
        // Credentials are checked against the one credential grammar and must be canonical base64.
        for bad in [base64("no-separator"), base64("u\n"), base64("u\np\u{7}"), "not base64!", base64("u\np") + "\n",
                    Data(repeating: 0x61, count: 4097).base64EncodedString()] {
            #expect(rejectsCommand(valid.replacingOccurrences(of: base64("u\np"), with: bad)))
        }
        // Run IDs are 36-character UUIDs; request numbers are positive counters.
        #expect(rejectsCommand(valid.replacingOccurrences(of: runText, with: "not-a-run")))
        #expect(rejectsCommand(valid.replacingOccurrences(of: #""request":1"#, with: #""request":0"#)))
        #expect(rejectsCommand(valid.replacingOccurrences(of: #""request":1"#, with: #""request":9007199254740993"#)))
    }

    @Test func inputEventsAreClosedAndBounded() {
        func command(_ events: String) -> String {
            #"{"op":"input","request":1,"run":"\#(runText)","step":1,"frame":1,"events":[\#(events)]}"#
        }
        #expect(!rejectsCommand(command(#"{"type":"pointer","phase":"down","x":3,"y":4}"#)))
        #expect(!rejectsCommand(command(#"{"type":"text","text":"123456"}"#)))
        for bad in [
            "",                                                             // empty batch
            #"{"type":"pointer","phase":"down","x":1280,"y":4}"#,           // outside any frame
            #"{"type":"pointer","phase":"drag","x":1,"y":4}"#,              // unknown phase
            #"{"type":"wheel","dx":2001,"dy":0}"#, #"{"type":"wheel","dx":0,"dy":0}"#,
            #"{"type":"key","key":"F12"}"#,
            #"{"type":"text","text":""}"#, #"{"type":"text","text":"\#(String(repeating: "a", count: 65))"}"#,
            #"{"type":"text","text":"a\nb"}"#,
            #"{"type":"script","text":"alert(1)"}"#, #"{"type":"navigate","url":"https://evil"}"#,
            #"{"type":"text","text":"a","extra":1}"#,
            Array(repeating: #"{"type":"key","key":"tab"}"#, count: 33).joined(separator: ",")
        ] {
            #expect(rejectsCommand(command(bad)), "events \(bad.prefix(60))")
        }
    }

    @Test func syntaxDepthAndSizeAreBoundedBeforeDecoding() {
        let deep = String(repeating: "[", count: 70) + String(repeating: "]", count: 70)
        #expect(rejectsCommand(#"{"op":"end","request":1,"run":"\#(runText)","x":\#(deep)}"#))
        #expect(rejectsCommand(#"{"op":"end","request":1,"run":"\#(runText)"} trailing"#))
        #expect(rejectsCommand("[]"))
        let big = #"{"op":"end","request":1,"run":"\#(runText)","pad":"\#(String(repeating: "a", count: 16_400))"}"#
        #expect(throws: HostWireError.requestTooLarge) { try HostWire.decodeRequest(data(big)) }
        #expect(throws: HostWireError.invalidRequest) { try HostWire.decodeRequest(Data()) }
    }

    @Test func repliesHaveExactlyTheirKeys() {
        let profileReply = #"{"reply":"profile","request":1,"run":"\#(runText)","login":"octocat","userID":583231}"#
        #expect(!rejectsReply(profileReply))
        #expect(rejectsReply(profileReply.replacingOccurrences(of: #","userID":583231"#, with: "")))
        #expect(rejectsReply(profileReply.replacingOccurrences(of: "octocat", with: "-bad")))
        #expect(rejectsReply(profileReply.replacingOccurrences(of: "583231", with: "0")))
        #expect(rejectsReply(profileReply.replacingOccurrences(of: #""userID":583231"#, with: #""userID":583231,"cookie":"sid=1""#)))
        #expect(rejectsReply(#"{"reply":"failed","request":1,"run":"\#(runText)","failure":"failed:boom"}"#))
        #expect(rejectsReply(#"{"reply":"html","request":1,"run":"\#(runText)","html":"<p>"}"#))
        #expect(rejectsReply(#"{"error":"invalid_request","reply":"ended"}"#))
        #expect(rejectsReply(#"{"error":"malformed_reply"}"#))
        #expect((try? HostWire.decodeReply(errorEnvelope(.busy))) == .error(.busy))
        let frame = #"{"reply":"frame","request":1,"run":"\#(runText)","step":1,"sequence":1,"width":2,"height":2,"jpeg":"\#(tinyJPEG.base64EncodedString())"}"#
        #expect(!rejectsReply(frame))
        #expect(rejectsReply(frame.replacingOccurrences(of: #""width":2"#, with: #""width":1281"#)))
        #expect(rejectsReply(frame.replacingOccurrences(of: tinyJPEG.base64EncodedString(), with: Data("GIF89a".utf8).base64EncodedString())))
        #expect(rejectsReply(String(repeating: " ", count: HostWire.maximumReplyBytes) + "{}"))
    }

    @Test func eachCommandAcceptsOnlyItsOwnReplies() {
        let frame = HumanFrame(sequence: 4, width: 2, height: 2, jpeg: tinyJPEG)!
        #expect(HostReply.profile(profile).answers(.start(run: run, workflow: .browserDemo, credential: credential, lifetime: 5)))
        #expect(!HostReply.profile(profile).answers(.end(run: run)))
        #expect(!HostReply.accepted.answers(.classify(run: run)))
        #expect(!HostReply.ended.answers(.start(run: run, workflow: .browserDemo, credential: credential, lifetime: 5)))
        #expect(HostReply.frame(step: 2, frame).answers(.frame(run: run, step: 2, after: 3)))
        #expect(!HostReply.frame(step: 1, frame).answers(.frame(run: run, step: 2, after: 3)), "frame of another step")
        #expect(!HostReply.frame(step: 2, frame).answers(.frame(run: run, step: 2, after: 4)), "frame not newer")
        #expect(!HostReply.noFrame(step: 1).answers(.frame(run: run, step: 2, after: 0)))
        let request = HostRequest(id: 3, command: .end(run: run))
        #expect(HostResponse(request: 3, run: run, reply: .ended).answers(request))
        #expect(!HostResponse(request: 4, run: run, reply: .ended).answers(request))
        #expect(!HostResponse(request: 3, run: UUID(), reply: .ended).answers(request))
    }
}
