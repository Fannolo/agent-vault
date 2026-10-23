@_spi(CredentialUse) import AgentVaultCredentials
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
            object["credential"] = credential.withCanonicalBytes { Data($0).base64EncodedString() }; object["lifetime"] = lifetime
        case .classify: object["op"] = "classify"
        case .end: object["op"] = "end"
        case .showHuman(_, let step): object["op"] = "showHuman"; object["step"] = step
        case .frame(_, let step, let after): object["op"] = "frame"; object["step"] = step; object["after"] = after
        case .input(_, let step, let frame, let batch):
            object["op"] = "input"; object["step"] = step; object["frame"] = frame
            object["events"] = batch.events.map(eventObject)
        case .openSite(_, let site, let lifetime): object["op"] = "openSite"; object["site"] = site.rawValue; object["lifetime"] = lifetime
        case .siteObserve: object["op"] = "siteObserve"
        case .siteLogin(_, let operation, let account, let credential):
            object["op"] = "siteLogin"; object["operation"] = operation.uuidString
            object["account"] = ["item": account.item.uuidString, "version": account.version]
            object["credential"] = credential.withCanonicalBytes { Data($0).base64EncodedString() }
        case .siteOperate(_, let operation, let site):
            object["op"] = "siteOperate"; object["operation"] = operation.uuidString
            object.merge(siteCommandObject(site)) { _, new in new }
        case .siteTakeover: object["op"] = "siteTakeover"
        case .siteRelease: object["op"] = "siteRelease"
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
                  let credential = WebLoginCredential(bytes) else { throw .invalidRequest }
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
        case "openSite":
            guard let site = HostSite(rawValue: try fields.string("site")) else { throw .invalidRequest }
            command = .openSite(session: run, site: site, lifetime: try fields.integer("lifetime", 1...HostCommand.maximumLifetime))
        case "siteObserve": command = .siteObserve(session: run)
        case "siteLogin":
            let operation = try fields.uuid("operation")
            var account = try Fields(try fields.value("account"), error: .invalidRequest)
            let item = try account.uuid("item"), version = try account.counter("version", minimum: 1)
            try account.finish()
            guard let used = CredentialVersion(item: item, version: version),
                  let bytes = Data(base64Encoded: try fields.string("credential")),
                  let credential = WebLoginCredential(bytes) else { throw .invalidRequest }
            command = .siteLogin(session: run, operation: operation, account: used, credential: credential)
        case "siteOperate":
            command = .siteOperate(session: run, operation: try fields.uuid("operation"), command: try siteCommand(&fields))
        case "siteTakeover": command = .siteTakeover(session: run)
        case "siteRelease": command = .siteRelease(session: run)
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

    private static func targetObject(_ target: SiteTarget) -> [String: Any] {
        ["document": target.document, "control": target.control, "element": target.element]
    }

    private static func siteCommandObject(_ command: SiteCommand) -> [String: Any] {
        switch command {
        case .navigate(let url): ["action": "navigate", "url": url]
        case .click(let target): ["action": "click", "target": targetObject(target)]
        case .typePublic(let target, let text): ["action": "type", "target": targetObject(target), "text": text]
        case .select(let target, let option): ["action": "select", "target": targetObject(target), "option": option]
        case .press(let key): ["action": "press", "key": key.rawValue]
        case .scroll(let dy): ["action": "scroll", "dy": dy]
        }
    }

    private static func siteTarget(_ value: Any) throws(HostWireError) -> SiteTarget {
        var fields = try Fields(value, error: .invalidRequest)
        let document = try fields.counter("document", minimum: 1), control = try fields.counter("control", minimum: 1)
        let element = try fields.integer("element", 0...SiteTarget.maximumElement)
        try fields.finish()
        guard let target = SiteTarget(document: document, control: control, element: element) else { throw .invalidRequest }
        return target
    }

    private static func siteCommand(_ fields: inout Fields) throws(HostWireError) -> SiteCommand {
        let command: SiteCommand
        switch try fields.string("action") {
        case "navigate": command = .navigate(try fields.string("url"))
        case "click": command = .click(try siteTarget(try fields.value("target")))
        case "type": command = .typePublic(try siteTarget(try fields.value("target")), try fields.string("text"))
        case "select":
            command = .select(try siteTarget(try fields.value("target")),
                              option: try fields.integer("option", 0...SiteCommand.maximumOption))
        case "press":
            guard let key = NamedKey(rawValue: try fields.string("key")) else { throw .invalidRequest }
            command = .press(key)
        case "scroll":
            let bound = HumanInput.maximumWheelDelta
            command = .scroll(dy: try fields.integer("dy", -bound...bound))
        default: throw .invalidRequest
        }
        guard command.fits else { throw .invalidRequest }
        return command
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
        case .site(let observation):
            object.merge(observationObject(observation)) { _, new in new }; object["reply"] = "site"
        case .siteUnknown: object["reply"] = "siteUnknown"
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
        case "site": reply = .site(try observation(&fields))
        case "siteUnknown": reply = .siteUnknown
        default: throw .malformedReply
        }
        try fields.finish()
        return .response(HostResponse(request: request, run: run, reply: reply))
    }

    private static func observationObject(_ observation: SiteObservation) -> [String: Any] {
        ["document": observation.document, "control": observation.control, "mode": observation.mode.rawValue,
         "auth": observation.auth.rawValue, "origin": observation.origin, "path": observation.path,
         "title": observation.title, "text": observation.text,
         "elements": observation.elements.map { element -> [String: Any] in
             ["ref": element.ref, "role": element.role.rawValue, "label": element.label, "value": element.value,
              "options": element.options]
         }]
    }

    private static func observation(_ fields: inout Fields) throws(HostWireError) -> SiteObservation {
        let document = try fields.counter("document", minimum: 1), control = try fields.counter("control", minimum: 1)
        guard let mode = SiteMode(rawValue: try fields.string("mode")),
              let auth = SiteAuth(rawValue: try fields.string("auth")) else { throw .malformedReply }
        let origin = try fields.string("origin"), path = try fields.string("path"), title = try fields.string("title")
        let text = try fields.strings("text", maximum: SiteObservation.maximumTextItems)
        var elements: [SiteElement] = []
        for item in try fields.array("elements", maximum: SiteObservation.maximumElements) {
            var element = try Fields(item, error: .malformedReply)
            let ref = try element.integer("ref", 0...SiteTarget.maximumElement)
            guard let role = SiteRole(rawValue: try element.string("role")) else { throw .malformedReply }
            let label = try element.string("label"), value = try element.string("value")
            let options = try element.strings("options", maximum: SiteElement.maximumOptions)
            try element.finish()
            guard let parsed = SiteElement(ref: ref, role: role, label: label, value: value, options: options) else {
                throw .malformedReply
            }
            elements.append(parsed)
        }
        guard let observation = SiteObservation(document: document, control: control, mode: mode, auth: auth, origin: origin,
                                                path: path, title: title, elements: elements, text: text) else {
            throw .malformedReply
        }
        return observation
    }

    /// `observation` with trailing text, then trailing elements, removed until any reply carrying it fits.
    public static func fitted(_ observation: SiteObservation) -> SiteObservation {
        var elements = observation.elements.count, text = observation.text.count
        while true {
            let candidate = observation.truncated(elements: elements, text: text)
            let probe = HostResponse(request: maximumCounter, run: UUID(), reply: .site(candidate))
            if (try? encode(probe)) != nil || (elements == 0 && text == 0) { return candidate }
            if text > 0 { text /= 2 } else { elements /= 2 }
        }
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

        mutating func value(_ key: String) throws(HostWireError) -> Any { try take(key) }

        mutating func strings(_ key: String, maximum: Int) throws(HostWireError) -> [String] {
            guard let value = try take(key) as? [String], value.count <= maximum else { throw error }
            return value
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
