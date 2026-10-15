# U3–U4: human continuation relay and window

Status: U3 (relay) is implemented against synthetic fixtures; U4 (window) follows in its own commit. No host, browser, installed service, protected key or real credential is involved. The production broker still composes no web host, so it lists no human step and every relay call is refused. **No production or isolation claim is made.**

## Usage (caller's view)

```swift
// App: one VaultAdminClient carries the signed open and every later call.
let step = snapshot.humanSteps[0]                       // run, epoch, kind, account, service, deadline
let lease = try await model.openHumanStep(step)         // begin → verify digest → user presence → authorize
let window = HumanStepModel(step: step, lease: lease, transport: transport)
HumanStepView(model: window)                            // validated JPEG in, bounded HumanInput out

// Daemon composition. The identity comes from the listener's accept path, never from a request.
begin:        { peer, request in try await admin.begin(request, connection: .init(minted: peer.id)) }
authorize:    { peer, id, sig in try await admin.authorize(id, signature: sig, connection: .init(minted: peer.id)) }
continuation: { peer, request in await continuation.perform(request, connection: .init(minted: peer.id)) }
connectionClosed: { peer in await broker.continuationConnectionClosed(.init(minted: peer.id)) }
```

## Contract

| Piece | Owner | Rule |
|---|---|---|
| `AdminConnection {uid, id}` | IPC | Minted once per accepted admin connection in `shouldAcceptNewConnection`. Its initializer is internal to IPC. The invalidation handler reports it to `connectionClosed`. |
| `ContinuationConnectionID(minted:)` | Core | Wraps that UUID. Only the daemon composition calls it, with `peer.id`. |
| `AdminRequest.openHumanStep` | Contracts | Exactly `requestID` (run), `accountID`, `stepEpoch` (1…2^53), `humanStepKind`. All four are signed in the `ApprovalIntent` digest. |
| `Administration.begin` | Core | Refuses an open that lacks a connection or does not name a step that exists now, with that run, epoch, kind and account. The frozen challenge records the connection. |
| `Administration.authorize` | Core | The challenge is consumed before anything else (unchanged single-use policy). An open must come from the connection that began it. The step is checked again and passed to `Broker.openHumanStep` as the exact signed `HumanStepID`. The reply `id` is the lease. |
| `Broker.openHumanStep` | Core | After `.opened`, calls `showHuman(step)`. Then it rechecks lease, step, deadline and authority. A host that cannot show the step gets no lease (`upstream_unavailable`), and the pause continues. |
| `VaultAdminRPC.continueHuman` | Contracts/IPC | One selector, a closed `ContinuationRequest`: `frame(after)`, `input(batch, frame, events)`, `finish`, `cancel`, `close`. Replies are `humanFrame` or `humanReply`. |
| `ContinuationOperations.perform` | Core | Parses the lease UUID into `ContinuationLeaseID` and maps every `VaultError` to the four-value `ContinuationFailure`. |
| `Broker.humanFrame` / `humanInput` / `closeHumanLease` | Core | Every call sweeps deadlines and checks lease, connection, current step and live authority. A lost authority ends the run. The check is repeated after the host replies, pinned to the same step. |

### Bounds and pacing

- Requests are ≤ 8 KiB. Each operation and each event type has one exact key set. Duplicate keys, nulls, strings for numbers, fractions, negative values, sequences above 2^53, unknown operations, unknown event types, keys or pointer phases fail before a typed value exists. The wire bounds wheel deltas (±2000) before `HumanInput.fits`, so `Int.min` never reaches `abs`.
- Replies stay ≤ 512 KiB. The largest legal frame (256 KiB JPEG, base64) fits. `next_step` requires `kind`, and no other status may carry one. The client refuses a frame that is not newer than `after`.
- XPC lanes: continuation calls use their own gates (2 per connection, 4 in total), so admin snapshot, begin, authorize and revocation keep their capacity under continuation saturation.
- Per lease: one frame poll and one input batch may be in flight. Frame polls are at least 50 ms apart (`busy` otherwise, without contacting the host).
- Input: `batch` must strictly increase per lease. It is consumed on admission, so a duplicate cannot race the original. `frame` must equal the latest frame this lease received. Every event must fit that frame's actual width and height. Failures return `not_delivered` without contacting the host.
- Relay state (`served`, `lastBatch`, pacing) is keyed by lease and is removed whenever the run's lease changes or the run leaves the table.

### Invalidation

Lease ends with: connection invalidation, `close`, `finish` (classifying), a new step (new epoch), conclusion, pause expiry, grant/client revocation, rotation intent, account deletion and host loss. `close` and connection loss keep the pause. A delayed signed open for step N cannot open step N+1, even when both have the same kind, because the signed epoch must match.

### Agent and audit surface

The agent read interface is unchanged: no frame, input or lease operation exists there, and polling and collection stay free. Administration audit records only `continuation_opened`, `continuation_closed`, `human_finished` and `human_cancelled`. Frames and input are never audited or logged. Failure replies are closed tokens that never echo request bytes.

## Accepted deviations from ROLLOUT

| ROLLOUT text | Implemented | Reason |
|---|---|---|
| Third Mach service `VaultContinuationRPC` with its own gates | One extra selector on the admin service, with separate continuation gates | The lease must be bound to the connection that performed the signed open. A second service would need a second connection identity and a cross-service binding. It would also need new configuration keys, plist entries and installer changes (U6). The capacity property (admin unaffected by continuation saturation) is held by the separate gates and tested over real XPC. |
| `HumanStepID`-only open | Open also signs account and kind | The person approves exactly what the summary showed. The broker rejects any mismatch at `begin` and again at `authorize`. |

## Merge notes for the parent

- `VaultXPCServer`: changes are limited to the handler typealiases, `Handlers` defaults, the accept path (identity, continuation `Peer`, admin invalidation handler) and `AdminEndpoint`. `Peer.dispatch` is unchanged, so the owner's in-flight task cancellation can be cherry-picked on top.
- `BrokerOverLinkTests` expects one `showHuman` command after the open. `ScriptedWebHost` gained frame/input scripting. Neither touches `start`.
- Shared docs that the parent owns need updates: IPC.md (new selector, reply kinds, snapshot `humanSteps`, `openHumanStep` keys, continuation lanes), THREAT-MODEL.md (raster channel is relayed but not yet backed by a host), IMPLEMENTATION-PLAN.md (U3/U4 verification).
