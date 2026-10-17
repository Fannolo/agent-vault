import AgentVaultContracts
import AgentVaultJSON
import Foundation

// Human continuation wire. Each operation and each event has one exact key set; anything else,
// including duplicate keys, nulls, extra nesting and out-of-range numbers, fails before a typed
// value exists. Error replies never echo request bytes, so typed text cannot reach a log.

extension WireCodec {
    static func encode(_ request: ContinuationRequest) throws(IPCError) -> Data {
        var wire = WireContinuationRequest(operation: request.operation.token, lease: request.lease)
        switch request.operation {
        case .frame(let after): wire.after = after
        case .input(let batch, let frame, let events):
            wire.batch = batch; wire.frame = frame; wire.events = events.events.map(WireHumanEvent.init)
        case .finish, .cancel, .close: break
        }
        guard let data = try? encoder().encode(wire) else { throw .invalidRequest }
        _ = try decodeContinuation(data, limits: .standard)
        return data
    }

    static func decodeContinuation(_ data: Data, limits: IPCLimits) throws(IPCError) -> ContinuationRequest {
        guard data.count <= min(limits.maxRequestBytes, ContinuationLimits.maxRequestBytes) else { throw .requestTooLarge }
        do { try JSONObjectGuard.validate(data) }
        catch { throw .invalidRequest }
        let decoder = decoder()
        guard let tree = try? decoder.decode(JSONTree.self, from: data), continuationRequestShape.admits(tree),
              case .object(let fields) = tree,
              let wire = try? decoder.decode(WireContinuationRequest.self, from: data) else { throw .invalidRequest }
        let keys = Set(fields.keys)
        let sequences = 0...HumanFrame.maximumSequence
        let operation: ContinuationRequest.Operation
        switch wire.operation {
        case "frame":
            guard keys == ["operation", "lease", "after"], let after = wire.after, sequences.contains(after) else { throw .invalidRequest }
            operation = .frame(after: after)
        case "input":
            guard keys == ["operation", "lease", "batch", "frame", "events"],
                  let batch = wire.batch, (1...HumanFrame.maximumSequence).contains(batch),
                  let frame = wire.frame, (1...HumanFrame.maximumSequence).contains(frame),
                  case .array(let items)? = fields["events"], let events = wire.events, items.count == events.count
            else { throw .invalidRequest }
            var inputs: [HumanInput] = []
            for (item, event) in zip(items, events) {
                guard case .object(let eventFields) = item, let input = event.input(keys: Set(eventFields.keys)) else {
                    throw .invalidRequest
                }
                inputs.append(input)
            }
            guard let bounded = HumanInputBatch(inputs) else { throw .invalidRequest }
            operation = .input(batch: batch, frame: frame, bounded)
        case "finish", "cancel", "close":
            guard keys == ["operation", "lease"] else { throw .invalidRequest }
            operation = wire.operation == "finish" ? .finish : wire.operation == "cancel" ? .cancel : .close
        default:
            throw .invalidRequest
        }
        return ContinuationRequest(lease: wire.lease, operation: operation)
    }

    static func continuationReply(_ reply: ContinuationReply, limits: IPCLimits) -> Data? {
        switch reply {
        case .frame(let frame):
            return self.reply(WireFrame(sequence: frame.sequence, width: frame.width, height: frame.height, jpeg: frame.jpeg),
                              kind: .humanFrame, limits: limits)
        default:
            return self.reply(WireHumanReply(reply), kind: .humanReply, limits: limits)
        }
    }

    static func continuationEnvelope(_ kind: ReplyKind, _ data: Data) throws -> ContinuationReply {
        switch kind {
        case .humanFrame:
            let wire = try decoder().decode(Single<WireFrame>.self, from: data).value
            guard let frame = HumanFrame(sequence: wire.sequence, width: wire.width, height: wire.height, jpeg: wire.jpeg)
            else { throw IPCError.malformedReply }
            return .frame(frame)
        default:
            let wire = try decoder().decode(Single<WireHumanReply>.self, from: data).value
            guard let reply = wire.reply else { throw IPCError.malformedReply }
            return reply
        }
    }

    static let continuationRequestShape = Shape.object(
        required: ["operation", "lease"], optional: ["after", "batch", "frame", "events"],
        nested: ["events": .array(.object(required: ["type"], optional: ["phase", "x", "y", "dx", "dy", "key", "text"]),
                                  max: HumanInputBatch.maximumEvents)])
}

/// Continuation messages stay well inside the admin limits: 32 events of at most 64 text bytes
/// each, and one JPEG of at most 256 KiB in base64.
public enum ContinuationLimits {
    public static let maxRequestBytes = 8_192
}

extension ContinuationRequest.Operation {
    var token: String {
        switch self {
        case .frame: "frame"
        case .input: "input"
        case .finish: "finish"
        case .cancel: "cancel"
        case .close: "close"
        }
    }
}

private struct WireContinuationRequest: Codable {
    var operation: String
    var lease: UUID
    var after: UInt64?
    var batch: UInt64?
    var frame: UInt64?
    var events: [WireHumanEvent]?

    init(operation: String, lease: UUID) { self.operation = operation; self.lease = lease }
}

private struct WireHumanEvent: Codable {
    var type: String
    var phase: String?
    var x: Int?
    var y: Int?
    var dx: Int?
    var dy: Int?
    var key: String?
    var text: String?

    init(_ input: HumanInput) {
        switch input {
        case .pointer(let phase, let x, let y): type = "pointer"; self.phase = phase.rawValue; self.x = x; self.y = y
        case .wheel(let dx, let dy): type = "wheel"; self.dx = dx; self.dy = dy
        case .key(let key): type = "key"; self.key = key.rawValue
        case .text(let text): type = "text"; self.text = text
        }
    }

    func input(keys: Set<String>) -> HumanInput? {
        let value: HumanInput?
        switch type {
        case "pointer":
            guard keys == ["type", "phase", "x", "y"], let phase = phase.flatMap(PointerPhase.init), let x, let y else { return nil }
            value = .pointer(phase, x: x, y: y)
        case "wheel":
            let limit = HumanInput.maximumWheelDelta
            guard keys == ["type", "dx", "dy"], let dx, let dy, (-limit...limit).contains(dx), (-limit...limit).contains(dy)
            else { return nil }
            value = .wheel(dx: dx, dy: dy)
        case "key":
            guard keys == ["type", "key"], let key = key.flatMap(NamedKey.init) else { return nil }
            value = .key(key)
        case "text":
            guard keys == ["type", "text"], let text else { return nil }
            value = .text(text)
        default:
            value = nil
        }
        return value.flatMap { $0.fits() ? $0 : nil }
    }
}

struct WireFrame: Codable {
    let sequence: UInt64
    let width: Int
    let height: Int
    let jpeg: Data
}

struct WireHumanReply: Codable {
    let status: String
    let kind: HumanStepKind?

    init(_ reply: ContinuationReply) {
        switch reply {
        case .frame, .noFrame: status = "no_frame"; kind = nil
        case .delivered: status = "delivered"; kind = nil
        case .notDelivered: status = "not_delivered"; kind = nil
        case .concluded: status = "concluded"; kind = nil
        case .nextStep(let next): status = "next_step"; kind = next
        case .closed: status = "closed"; kind = nil
        case .failure(let failure): status = failure.rawValue; kind = nil
        }
    }

    var reply: ContinuationReply? {
        if status == "next_step" { return kind.map(ContinuationReply.nextStep) }
        guard kind == nil else { return nil }
        switch status {
        case "no_frame": return .noFrame
        case "delivered": return .delivered
        case "not_delivered": return .notDelivered
        case "concluded": return .concluded
        case "closed": return .closed
        default: return ContinuationFailure(rawValue: status).map(ContinuationReply.failure)
        }
    }
}
