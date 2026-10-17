# U3–U4: human continuation relay and window

Status: U3 (relay) and U4 (window), originally built on corrected U1 (`0139ab5`), are integrated in the parent branch with the three race corrections and an additional Finish/Cancel liveness guard. Their evidence uses synthetic fixtures, software signing and local XPC. It does not exercise the real host-to-app flow, installed service, protected key or real credential. The production broker still composes no web host, so it lists no human step and every relay call is refused. **No production or isolation claim is made.**

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
| `ContinuationConnectionID(minted:isOpen:)` | Core | Wraps that UUID and the connection's liveness. Only the daemon composition calls it, with `peer.id` and `{ peer.isOpen }`. Equality and hashing use the UUID alone. |
| `AdminConnection.isOpen` | IPC | Cleared synchronously by the invalidation handler before the closed callback is scheduled. Lives with the connection, so it needs no tombstone. |
| `AdminRequest.openHumanStep` | Contracts | Exactly `requestID` (run), `accountID`, `stepEpoch` (1…2^53), `humanStepKind`. All four are signed in the `ApprovalIntent` digest. |
| `Administration.begin` | Core | Refuses an open that lacks a connection or does not name a step that exists now, with that run, epoch, kind and account. The frozen challenge records the connection. |
| `Administration.authorize` | Core | The challenge is consumed before anything else (unchanged single-use policy). An open must come from the connection that began it. The step is checked again and passed to `Broker.openHumanStep` as the exact signed `HumanStepID`. The reply `id` is the lease. |
| `Broker.openHumanStep` | Core | Refuses a connection that is no longer open, checked on the broker actor immediately before `.opened`. Either that check fails, or the closed callback (scheduled after liveness is cleared) runs later and ends the lease. After `.opened`, calls `showHuman(step)`. Then it rechecks lease, step, deadline and authority. A host that cannot show the step gets no lease (`upstream_unavailable`), and the pause continues. |
| `VaultAdminRPC.continueHuman` | Contracts/IPC | One selector, a closed `ContinuationRequest`: `frame(after)`, `input(batch, frame, events)`, `finish`, `cancel`, `close`. Replies are `humanFrame` or `humanReply`. |
| `ContinuationOperations.perform` | Core | Parses the lease UUID into `ContinuationLeaseID` and maps every `VaultError` to the four-value `ContinuationFailure`. |
| `Broker.humanFrame` / `humanInput` / `closeHumanLease` | Core | Every call sweeps deadlines and checks connection liveness, lease, connection, current step and live authority. A lost authority ends the run. The check is repeated after the host replies, pinned to the same step. |

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

## U4: the human step window

| Piece | Rule |
|---|---|
| `AppModel.openHumanStep(step)` | Builds `openHumanStep` from the listed `HumanStepSummary` and runs the existing begin → digest check → user presence → authorize sequence. The prompt names kind, step epoch, run, account and service. One window at a time. An expired step is refused before anyone is asked to sign. |
| `HumanStepModel` finish | Polling stops and new input is refused first. Queued input is then delivered in order and acknowledged before the finish is sent. If any batch is declined, the finish is not sent: the window returns to live with `finishBlockedByUndeliveredInput` and polling resumes. A poll reply that arrives after the finish started is ignored, so only the finish reply decides the ending. |
| `HumanStepModel` | Bound to one lease. It polls `frame(after: latest)` every 100 ms (250 ms after `busy`) and ends at the step deadline by its own clock, sending `close`. A refusal ends it as `unavailable`, a transport failure as `connectionLost` (the lease was bound to that connection), and explicit `finish`, `cancel` and `close` end it as `concluded`/`nextStep`, `cancelled` and `closed`. After it ends it clears its queue and frame and sends nothing more. |
| `HumanFrameImage` | Treats the JPEG as untrusted. Before decoding any pixel, ImageIO must report a complete, single-image JPEG, no orientation transform, an actual pixel size equal to the declared one, and at most 1280 × 900 pixels. A frame not newer than the one shown is ignored. |
| `FrameGeometry` | Aspect-fit placement (`resizeAspect`) and its inverse. Points outside the drawn frame are dropped. A pointer release outside is clamped to the nearest edge, so no button stays pressed. |
| Input | Each queued event carries the sequence of the frame it was aimed at. A new frame drops older queued events. Moves and adjacent text coalesce. Batches go out at most every 30 ms, one in flight, with increasing batch numbers. Text is printable only and split into ≤ 64-byte events. Command shortcuts (paste included) are ignored. Only named keys map to `NamedKey`. |
| `HumanStepView` | A sheet showing the service, kind, account, run, step, live status and countdown, an AppKit raster surface, and **I finished**, **Cancel sign-in** and **Close** buttons. No address, navigation, clipboard, file or page text exists. |
| DEBUG only | `InMemoryBroker` continuation (counts only, no typed text), `SyntheticFrames`, the preview step and the `sheet-human-step` screenshot-tour entry. `AppInvariantTests` requires `#if DEBUG` around each of them. |

## Verification

- `ContinuationRelayTests` (real `Administration`, `ContinuationOperations`, `Broker`), `ContinuationXPCTests`/`ContinuationWireTests` (real XPC listener and client), `HumanStepTests` (real `AppModel`/`HumanStepModel`/ImageIO), and `HumanContinuationE2ETests`. The last drives the app model over real XPC into the real broker in one process, with a scripted host.
- `scripts/verify-continuation-mutations.py` reverts 27 defenses one at a time (18 relay, 8 window, 1 composition), after a green baseline for each suite. The first U4 pass found one surviving mutant: the window filtered stale queued input both when a frame arrived and before sending. The duplicate was removed, and the remaining send-time filter is the one mutated. It edits files in place, restores them in `finally`, and sends no signal.
- Not covered: a real web host, Chromium raster or input, the installed Mach services, protected-key user presence, and separate UIDs.

## Independent judge corrections (after `4337660`)

| Probe | Defect | Correction | Regression |
|---|---|---|---|
| A signed authorize held past the connection's closed callback | It created a lease and relay on a dead identity | Connection liveness travels with the minted identity; the broker refuses to bind a lease to a closed connection | `aSignedOpenThatCompletesAfterItsConnectionClosedGrantsNoLease` (real XPC), `aConnectionThatHasClosedCanNeitherOpenNorUseALease` (Core) |
| `finish` with input in flight and more queued | Finish was sent before the batch was acknowledged, and queued text was discarded | Drain and acknowledge in order before finishing; a declined batch blocks finish explicitly | `finishDeliversQueuedInputInOrderBeforeAskingTheBroker`, `undeliveredInputBlocksFinishExplicitlyAndTheWindowStaysLive` |
| Polling while the broker reclassifies | The poller used the invalidated lease and ended the window as unavailable before the real success | Finish stops the poller and ignores its in-flight reply | `pollingDuringAFinishCannotTurnItsSuccessIntoUnavailable` (real XPC and broker), `aPollReplyArrivingDuringFinishDoesNotDecideTheEnding` |

The judge's three probes were rerun against the corrected sources (adapted only to `minted:isOpen:`). Each now fails at its REPRO expectation.

## Accepted deviations from ROLLOUT

| ROLLOUT text | Implemented | Reason |
|---|---|---|
| Third Mach service `VaultContinuationRPC` with its own gates | One extra selector on the admin service, with separate continuation gates | The lease must be bound to the connection that performed the signed open. A second service would need a second connection identity and a cross-service binding. It would also need new configuration keys, plist entries and installer changes (U6). The capacity property (admin unaffected by continuation saturation) is held by the separate gates and tested over real XPC. |
| `HumanStepID`-only open | Open also signs account and kind | The person approves exactly what the summary showed. The broker rejects any mismatch at `begin` and again at `authorize`. |

## Merge notes for the parent

- `VaultXPCServer`: changes are limited to the handler typealiases, `Handlers` defaults, the accept path (identity, continuation `Peer`, admin invalidation handler) and `AdminEndpoint`. `Peer.dispatch` is unchanged, so the owner's in-flight task cancellation can be cherry-picked on top.
- `BrokerOverLinkTests` expects one `showHuman` command after the open. `ScriptedWebHost` gained frame/input scripting. Neither touches `start`.
- Rebased onto `0986606` and then `0139ab5`. The continuation lane is a non-cancelling `Peer`, so it bypasses the read-handler registry as admin work does. The only conflict was the read/admin invalidation handlers in `VaultXPCServer`: both now call the owner's `peer.connectionInvalidated()`, and the admin one also reports the closed identity. The continuation lane does not cancel on invalidation, because a cancelled `finish` would cut short the broker's reply wait.
- New test target `AgentVaultContinuationE2ETests` links AppSupport and Core. Product targets are unchanged and `verify-boundaries.py` still passes.
- Shared docs that the parent owns need updates: IPC.md (new selector, reply kinds, snapshot `humanSteps`, `openHumanStep` keys, continuation lanes), THREAT-MODEL.md (raster channel is relayed but not yet backed by a host), IMPLEMENTATION-PLAN.md (U3/U4 verification).
