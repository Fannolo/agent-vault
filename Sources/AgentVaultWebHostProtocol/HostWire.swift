import AgentVaultContracts
import AgentVaultJSON
import Foundation

/// Fixed transport codes. They never carry peer data, request bytes or handler text.
public enum HostWireError: String, Error, Sendable, CaseIterable {
    case invalidRequest = "invalid_request"
    case requestTooLarge = "request_too_large"
    case busy
    case unavailable
    case malformedReply = "malformed_reply"

    /// Codes a host may put in an error envelope.
    static let wireCodes: Set<HostWireError> = [.invalidRequest, .requestTooLarge, .busy, .unavailable]
}

/// Exact-shape JSON for both directions. Every object has one key set per operation; a missing,
/// extra, duplicated or `null` key, a fractional or out-of-range number, or a value outside its
/// bound is rejected before a typed value exists. Encoders validate their own output the same way.
public enum HostWire {
    /// A start carries at most a 4096-byte credential, about 5.5 KiB in base64.
    public static let maximumCommandBytes = 16_384
    /// A frame reply carries at most a 256 KiB JPEG, about 342 KiB in base64.
    public static let maximumReplyBytes = 393_216
    /// Request numbers, step epochs and frame sequences stay exactly representable as JSON numbers.
    public static let maximumCounter: UInt64 = 1 << 53

    // MARK: Commands

    public static func encode(_ request: HostRequest) throws(HostWireError) -> Data {
        let command = request.command
        var object: [String: Any] = ["request": request.id, "run": command.run.uuidString]
        switch command {
        case .start(_, let workflow, let credential, let lifetime):
            object["op"] = "start"; object["workflow"] = workflow.rawValue
            object["credential"] = credential.bytes.base64EncodedString(); object["lifetime"] = lifetime
        case .classify: object["op"] = "classify"
        case .end: object["op"] = "end"
        case .showHuman(_, let step): object["op"] = "showHuman"; object["step"] = step
        case .frame(_, let step, let after): object["op"] = "frame"; object["step"] = step; object["after"] = after
        case .input(_, let step, let frame, let batch):
            object["op"] = "input"; object["step"] = step; object["frame"] = frame
            object["events"] = batch.events.map(eventObject)
        }
        let data = try serialize(object, error: .invalidRequest)
        guard try decodeRequest(data) == request else { throw .invalidRequest }
        return data
    }

    public static func decodeRequest(_ data: Data) throws(HostWireError) -> HostRequest {
        guard data.count <= maximumCommandBytes else { throw .requestTooLarge }
        var fields = try Fields(data, error: .invalidRequest)
        let op = try fields.string("op")
        let id = try fields.counter("request", minimum: 1)
        let run = try fields.uuid("run")
        let command: HostCommand
        switch op {
        case "start":
            guard let workflow = HostWorkflow(rawValue: try fields.string("workflow")),
                  let bytes = Data(base64Encoded: try fields.string("credential")),
                  let credential = WebLoginCredential(bytes), credential.bytes == bytes else { throw .invalidRequest }
            let lifetime = try fields.integer("lifetime", 1...HostCommand.maximumLifetime)
            command = .start(run: run, workflow: workflow, credential: credential, lifetime: lifetime)
        case "classify": command = .classify(run: run)
        case "end": command = .end(run: run)
        case "showHuman": command = .showHuman(run: run, step: try fields.counter("step", minimum: 1))
        case "frame":
            command = .frame(run: run, step: try fields.counter("step", minimum: 1),
                             after: try fields.counter("after", minimum: 0))
        case "input":
            let step = try fields.counter("step", minimum: 1), frame = try fields.counter("frame", minimum: 1)
            let items = try fields.array("events", maximum: HumanInputBatch.maximumEvents)
            var events: [HumanInput] = []
            for item in items { events.append(try event(item)) }
            guard let batch = HumanInputBatch(events) else { throw .invalidRequest }
            command = .input(run: run, step: step, frame: frame, batch: batch)
        default: throw .invalidRequest
        }
        try fields.finish()
        return HostRequest(id: id, command: command)
    }

    private static func eventObject(_ event: HumanInput) -> [String: Any] {
        switch event {
        case .pointer(let phase, let x, let y): ["type": "pointer", "phase": phase.rawValue, "x": x, "y": y]
        case .wheel(let dx, let dy): ["type": "wheel", "dx": dx, "dy": dy]
        case .key(let key): ["type": "key", "key": key.rawValue]
        case .text(let text): ["type": "text", "text": text]
        }
    }

    private static func event(_ value: Any) throws(HostWireError) -> HumanInput {
        var fields = try Fields(value, error: .invalidRequest)
        let event: HumanInput
        switch try fields.string("type") {
        case "pointer":
            guard let phase = PointerPhase(rawValue: try fields.string("phase")) else { throw .invalidRequest }
            event = .pointer(phase, x: try fields.integer("x", 0...(HumanFrame.maximumWidth - 1)),
                             y: try fields.integer("y", 0...(HumanFrame.maximumHeight - 1)))
        case "wheel":
            let bound = HumanInput.maximumWheelDelta
            event = .wheel(dx: try fields.integer("dx", -bound...bound), dy: try fields.integer("dy", -bound...bound))
        case "key":
            guard let key = NamedKey(rawValue: try fields.string("key")) else { throw .invalidRequest }
            event = .key(key)
        case "text": event = .text(try fields.string("text"))
        default: throw .invalidRequest
        }
        try fields.finish()
        guard event.fits() else { throw .invalidRequest }
        return event
    }

    // MARK: Replies

    public enum Envelope: Sendable, Equatable {
        case response(HostResponse)
        case error(HostWireError)
    }

    public static func encode(_ response: HostResponse) throws(HostWireError) -> Data {
        var object: [String: Any] = ["request": response.request, "run": response.run.uuidString]
        switch response.reply {
        case .profile(let profile):
            object["reply"] = "profile"; object["login"] = profile.login; object["userID"] = profile.userID
        case .humanStep(let kind): object["reply"] = "humanStep"; object["kind"] = kind.rawValue
        case .failed(let failure): object["reply"] = "failed"; object["failure"] = failure.rawValue
        case .frame(let step, let frame):
            object["reply"] = "frame"; object["step"] = step; object["sequence"] = frame.sequence
            object["width"] = frame.width; object["height"] = frame.height
            object["jpeg"] = frame.jpeg.base64EncodedString()
        case .noFrame(let step): object["reply"] = "noFrame"; object["step"] = step
        case .accepted: object["reply"] = "accepted"
        case .ended: object["reply"] = "ended"
        case .rejected(let rejection): object["reply"] = "rejected"; object["rejection"] = rejection.rawValue
        }
        let data = try serialize(object, error: .unavailable)
        guard case .response(response) = try decodeReply(data) else { throw .unavailable }
        return data
    }

    public static func errorReply(_ code: HostWireError) -> Data {
        // A closed string enum always serializes.
        try! JSONSerialization.data(withJSONObject: ["error": code.rawValue], options: [.sortedKeys])
    }

    public static func decodeReply(_ data: Data) throws(HostWireError) -> Envelope {
        guard data.count <= maximumReplyBytes else { throw .malformedReply }
        var fields = try Fields(data, error: .malformedReply)
        if fields.contains("error") {
            guard let code = HostWireError(rawValue: try fields.string("error")),
                  HostWireError.wireCodes.contains(code) else { throw .malformedReply }
            try fields.finish()
            return .error(code)
        }
        let kind = try fields.string("reply")
        let request = try fields.counter("request", minimum: 1)
        let run = try fields.uuid("run")
        let reply: HostReply
        switch kind {
        case "profile":
            guard let profile = AccountProfile(login: try fields.string("login"),
                                               userID: try fields.integer("userID", 1...Int(maximumCounter))) else {
                throw .malformedReply
            }
            reply = .profile(profile)
        case "humanStep":
            guard let step = HumanStepKind(rawValue: try fields.string("kind")) else { throw .malformedReply }
            reply = .humanStep(step)
        case "failed":
            guard let failure = HostFailure(rawValue: try fields.string("failure")) else { throw .malformedReply }
            reply = .failed(failure)
        case "frame":
            let step = try fields.counter("step", minimum: 1), sequence = try fields.counter("sequence", minimum: 1)
            let width = try fields.integer("width", 1...HumanFrame.maximumWidth)
            let height = try fields.integer("height", 1...HumanFrame.maximumHeight)
            guard let jpeg = Data(base64Encoded: try fields.string("jpeg")),
                  let frame = HumanFrame(sequence: sequence, width: width, height: height, jpeg: jpeg) else {
                throw .malformedReply
            }
            reply = .frame(step: step, frame)
        case "noFrame": reply = .noFrame(step: try fields.counter("step", minimum: 1))
        case "accepted": reply = .accepted
        case "ended": reply = .ended
        case "rejected":
            guard let rejection = HostRejection(rawValue: try fields.string("rejection")) else { throw .malformedReply }
            reply = .rejected(rejection)
        default: throw .malformedReply
        }
        try fields.finish()
        return .response(HostResponse(request: request, run: run, reply: reply))
    }

    // MARK: Exact fields

    private static func serialize(_ object: [String: Any], error: HostWireError) throws(HostWireError) -> Data {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { throw error }
        return data
    }

    /// Reads each key exactly once; `finish` fails if any key was not read.
    private struct Fields {
        private var remaining: [String: Any]
        private let error: HostWireError

        init(_ data: Data, error code: HostWireError) throws(HostWireError) {
            guard (try? JSONObjectGuard.validate(data)) != nil,
                  let object = try? JSONSerialization.jsonObject(with: data) else { throw code }
            try self.init(object, error: code)
        }

        init(_ value: Any, error: HostWireError) throws(HostWireError) {
            guard let object = value as? [String: Any] else { throw error }
            remaining = object; self.error = error
        }

        func contains(_ key: String) -> Bool { remaining[key] != nil }

        mutating func finish() throws(HostWireError) {
            guard remaining.isEmpty else { throw error }
        }

        private mutating func take(_ key: String) throws(HostWireError) -> Any {
            guard let value = remaining.removeValue(forKey: key) else { throw error }
            return value
        }

        mutating func string(_ key: String) throws(HostWireError) -> String {
            guard let value = try take(key) as? String else { throw error }
            return value
        }

        mutating func uuid(_ key: String) throws(HostWireError) -> UUID {
            let text = try string(key)
            guard text.utf8.count == 36, let uuid = UUID(uuidString: text) else { throw error }
            return uuid
        }

        mutating func array(_ key: String, maximum: Int) throws(HostWireError) -> [Any] {
            guard let value = try take(key) as? [Any], value.count <= maximum else { throw error }
            return value
        }

        /// A JSON integer: not a boolean, not written with a fraction or exponent, within `range`.
        mutating func integer(_ key: String, _ range: ClosedRange<Int>) throws(HostWireError) -> Int {
            let value = try take(key)
            guard let number = value as? NSNumber, CFGetTypeID(number) == CFNumberGetTypeID(),
                  !CFNumberIsFloatType(number), range.contains(number.intValue),
                  number == NSNumber(value: number.intValue) else { throw error }
            return number.intValue
        }

        mutating func counter(_ key: String, minimum: UInt64) throws(HostWireError) -> UInt64 {
            UInt64(try integer(key, Int(minimum)...Int(HostWire.maximumCounter)))
        }
    }
}
