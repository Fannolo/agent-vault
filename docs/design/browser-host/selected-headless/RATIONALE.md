# Candidate B: sealed web host with a raster human channel

## Problem

The verified WebKit library cannot run in production. `HumanContinuationView` must be in the same process as its `WKWebView`. The broker is a `_agentvault` LaunchDaemon, and a LaunchDaemon cannot connect to the window server. Hosting the view under the agent's UID breaks session isolation. Hosting it under a private UID inside the console GUI session is not available either. TN2083 bars every EUID except root and the console user from the window server. Also, `launchd.plist` ignores `UserName` for agents. Core has no browser lifecycle: `SessionServiceAdapter` is keyed by grant UUID, the browser manager is keyed by account, and `resume` only knows approvals. A pause would be audited as `completed`. `failed:<code>` fails the wire token check. Profile IDs disagree (`Int?` vs `Int`), and so do credential caps (4096 vs 8192). These constraints must hold: one budget reservation per attempt, authority rechecked after credential load and before output, 120 s approval vs 600 s pause, no CDP/eval/navigation surface, App and Bridge never link Core.

## Usage (caller's view)

**Agent (MCP).** The four existing tools stay. `request_resume` now means "current state of this request".

```text
action_run {accountId, action:"github.web_profile"}  -> {"status":"human_step_required","requestID":"R"}
request_resume {requestId:"R"}                        -> {"status":"human_step_required","requestID":"R"}   (free; no budget)
   … a person finishes the step in the Agent Vault app …
request_resume {requestId:"R"}                        -> {"status":"completed","login":"octocat","userID":583231}
request_resume {requestId:"R"}                        -> error "access_denied"                              (delivered once)
```
With per-call approval, the first reply is `approval_required` with ID `A`. Resuming `A` after approval returns `human_step_required` with a new run ID `R`. The agent always resumes the ID from its latest reply.

**Human (App).** The Requests screen lists "GitHub sign-in needs you · two-factor · 9:12 left" beside approvals. **Open** runs the existing begin → digest → Touch ID → authorize ceremony with `.openHumanStep` and receives a lease. `HumanStepView` shows JPEG frames of the paused page. It sends clicks, keys and text up to 64 bytes. **I finished** asks the broker to reclassify. **Cancel** discards the session.

```swift
let lease = try await model.openHumanStep(step.id)          // signed, fresh user presence
let human = HumanStepModel(lease: lease, transport: XPCContinuationTransport(config))
HumanStepView(model: human)                                  // pixels in, HumanInput out
```

**Broker composition.**
```swift
let web = try config.browser.map { try WebHostLink(serviceName: $0.serviceName, hostRequirement: $0.requirement, hostUID: $0.uid) }
let broker = Broker(state: state, secrets: secrets, webHost: web)   // nil => browser disabled, as today
```

## Shape

Process map: `agent → bridge ─read XPC→ broker(_agentvault) ─host XPC→ webhost(_agentvaultweb) ─fd3/fd4→ chrome-headless-shell`, and `app ─admin XPC (signed open)/continuation XPC (lease)→ broker`. The app never talks to the host. The host accepts exactly one peer, the broker.

- **Data first.** `BrowserRun {RunID, RunBinding(client, account, action, grant), RunStage}` lives in memory inside the `Broker` actor, which is the only writer. `RunStage` is `dispatching | awaitingHuman(kind, HumanPauseDeadline, Lease?) | classifying | concluded(RunConclusion, CollectDeadline)`. Three ID types (`PendingInvocation.id`, `RunID`, `LeaseID`) and three deadline types (`Approval`, `HumanPause`, `Collect`) cannot be swapped (per type-system-discipline). The table is not persisted, because the browser context it names dies with either process (per make-operations-idempotent: a restart converges to "no runs").
- **One pure transition** `transition(run, event, now, windows, grant) -> (run?, effects)` holds every lifecycle rule. It is table-tested without a browser. `Broker` only performs effects (`endHostRun`, `showHuman`, `reclassify`, `audit`).
- **Budget once.** Reservation stays in `execute`. Polling, opening, input, reclassify and collecting reserve nothing.
- **Authority rechecks.** (1) Reserve. (2) After credential load. (3) When the host returns, after actor reentrancy. (4) On open, frame, input and finish. (5) Before every output. `stillAuthorized` deliberately ignores `callsUsed`, so a run that spent the grant's last call stays collectable.
- **Revocation** goes through `endRuns(predicate)` for grant, client, account rotation and account deletion. This replaces `SessionServiceAdapter`, which is deleted.
- **Closed vocabularies** live in Contracts: `ReadOutcomeStatus` and `ReadFailureStatus`, which Bridge, WireCodec and Core all derive from. `VaultError.readFailure` is an exhaustive switch. Precise `HostFailure` codes appear only in audit. `AccountProfile` requires both `login` and `userID`. `CredentialFormat.isValid` is the single grammar, called at enrollment, in the App and in the host.
- **Deep host interface.** Six commands: `start`, `showHuman`, `frame`, `input`, `reclassify`, `end`. Behind them sit Chromium spawn, pipe framing, a closed `CDPMethod` set, constant `Recipe`s in an isolated world, and a pure phase-aware `RequestGate`. During a human step, main-frame navigation is limited to that workflow's step paths, so the raster channel is a challenge surface and not a general browser. The `RequestGate` also keeps the existing exact-origin rules. Each run gets an incognito `BrowserContext` with in-memory cookies, disposed at conclusion.
- **Capacity.** The continuation service is a third Mach service with its own gates, so frame polling cannot starve revocation on the admin service.

## Synthesis decision

*For the parent arena.*

## Tradeoffs accepted

- We accept shipping and re-signing a pinned Chromium (~200 MB) with a release gate on its age, in exchange for documented headless operation, pipe-only control, screencast and input APIs.
- We accept a second service UID and LaunchDaemon in exchange for keeping a renderer escape away from the broker's Keychain database and integrity key.
- We accept relaying frames through the broker (≤256 KiB JPEG, ack-paced) in exchange for one authority holder and a host whose only peer is the broker.
- We accept losing paused runs on any broker or host restart (`session_lost`, budget not refunded) in exchange for having no persisted browser state.
- We accept that the agent can see frames if its host app holds Screen Recording permission, and can inject clicks if it holds Accessibility permission. Frames show only the challenge page, and the step-path gate limits what injected clicks can reach. A user-presence signature gates opening.
- We accept that a CAPTCHA served from an unreviewed third-party origin, or one that refuses headless browsers, ends as `challenge_unavailable`. User-agent and fingerprint spoofing are explicitly out of scope.

## Alternatives considered

The full comparison is in `DEPLOYMENT-ALTERNATIVES.md`.
- **Private-UID GUI host (WKWebView window in the Aqua session).** It lost on platform rules (TN2083, `UserName` ignored for agents). Getting there needs root, and Apple says not to rely on that path.
- **Renderer inside the broker UID.** It has the same interface with one fewer process, but a renderer exploit would reach the Keychain owner.
- **Headless WKWebView in the same sealed host.** The deployment would be identical, but WebKit has no supported input-injection or screencast API for an offscreen view, and its WebContent processes under a daemon are unprobed. It is the named fallback if Chromium fails P0, and it touches only the host's internals.
- **Same-UID host (App or LaunchAgent).** It fails the isolation requirement.

## Implementation reconciliation

### U0: contracts and the broker-owned run lifecycle (branch `feature/vault-browser-host`)

U0 is implemented against a scripted in-process host. No browser, Keychain item, network service or installed component is involved. Browser services stay disabled in the production broker: `BrokerMain` passes no `webSessions`, and `Administration.allowedServices` is still `[.demo, .github]`.

**Implemented as designed**

- Contracts: `ReadOutcomeStatus`, `ReadFailureStatus`, `ReadStatus`, `AccountProfile` (both fields required, `userID > 0`), `CredentialFormat` and `WebLoginCredential`. The bridge switches on `ReadReply.parsedStatus` and returns every failure status verbatim. Broker, app formatter and the WebKit library all use `CredentialFormat`. `GitHubProfile`, `GitHubAdapter.validateCredential`, `WebCredential`, `WebProfile`, the bridge's two hand lists, `BrowserOutcome.wireStatus` (`failed:<code>`) and the `120` literal are deleted.
- Core: separate `ApprovalID`, `BrowserRunID` and `ContinuationLeaseID` types; `LifecycleWindows` (approval 120 s, human pause 600 s, collect 120 s), each window capped by grant expiry; distinct `HumanPauseDeadline` and `CollectDeadline` types; one transition function, `BrowserRun.applying(_:now:windows:)`; `stillAuthorized`; and the Broker web branch with `resume` and `cancel` routing. `SessionServiceAdapter` is deleted in this unit, with all callers and tests migrated. No grouping with U1 was needed.
- Budget is reserved once, in `execute`. Polling, opening, finishing, reclassifying and collecting reserve nothing. `stillAuthorized` ignores the remaining-call budget, so the run that used a grant's last call stays collectable. `finish` uses the same check for API calls.
- Results are delivered at most once: a concluded run leaves the table before its terminal audit is written.
- A pause is audited as `human_step_required` and never as `completed`. Each run has exactly one terminal invocation-audit outcome: `completed`, `failed`, `response_suppressed`, `run_cancelled` or `result_uncollected`. Precise host codes are recorded only as `web_<code>`. Human actions (`continuation_opened`, `human_finished`, `human_cancelled`, `continuation_closed`) go to the administration audit, so agent traffic cannot evict them.

**Accepted deviations**

| Design text | Implemented | Reason |
|---|---|---|
| Core imports `AgentVaultWebHostProtocol` and uses a `WebHost` port with host wire types | Core defines `WebSessionExecutor`, which takes only domain values: `WebWorkflow`, `WebLoginCredential`, `WebStep` and `WebFailure`. U1's link will translate them to the host wire. | Judge amendment: Core's importable surface must not contain the credential-bearing command type. `verify-boundaries.py` now also asserts that Core does not link `AgentVaultBrowser`. |
| `transition(run, event, now, windows, grant)` as a free function | `BrowserRun.applying(event, now:, windows:)`. The grant expiry is captured in the run at reservation. Effects are `endHost`, `audit` and `humanAudit`; the broker owns cancellable deadline tasks. Host `start`/`reclassify` calls are made by the Broker at fixed points, not emitted as effects. | Credential bytes never enter run state. Each host request bumps the run `epoch`, and the reply is applied only if that epoch still awaits it. |
| `endRuns(predicate)` per lifecycle mutation | `reconcileRuns()`. After every grant revocation, client revocation, rotation intent/commit and account deletion, it ends each run whose binding fails `stillAuthorized`. Unreadable state counts as a loss of authority. The binding includes the credential ID. | One rule covers every authority source and cannot miss a predicate. Rotation ends runs before the old credential is deleted. |
| Lease bound to app PID (`Peer.pid`) | The lease is bound to an opaque `ContinuationConnectionID`, minted by the transport for each authenticated connection (U3). `continuationConnectionClosed` drops that connection's leases but keeps the pause. | Judge amendment: a lease must be bound to the connection, not to a PID. |
| Challenge epoch carried by frames and input | A preexisting `HumanStepID` binds the run and a monotonically increasing step epoch. The human snapshot exposes its kind and ID; signed opens must name that exact step. A lease is also connection-bound and ends on finish/new step/conclusion/disconnection. U3 binds frame IDs and input batches to this step and lease. | Parent review found that a lease minted only at open could authorize a later challenge. A regression now rejects a delayed open for step A after step B exists. |
| Late/stale host replies through tombstones | A reply for a removed or concluded run, or for an older epoch, is ignored. Its host run is then ended, even if `end` was already sent, to dispose of a context that a late `start` created. Authority is checked again before any reply is applied. | The broker's in-memory table and epoch decide staleness. Host-side tombstones and the priority of control over frames belong to the U1 link and U2 host. |
| Broker loss reports `session_lost` | After a broker restart the run table is empty, so an old run ID returns `access_denied`. The budget is not refunded. Host loss (the `losses` stream) concludes live runs as `session_lost`. | Nothing about runs is persisted, by design. |
| Teardown is fire-and-forget | Revocation, rotation and deletion await `end` after removing the run. Authority stops at once; the host link must bound `end`. | Rotation must order teardown before credential deletion. |
| Deadlines checked only on access | Every access also runs a lazy sweep. One cancellable task per retained run ends an unpolled pause and drops an uncollected result. Matching deadlines reuse the task; collection/cancellation removes it. Host replies also enforce the original pause deadline synchronously. | A paused context must not live past its pause just because nobody polls. |
| `ReadFailureStatus` list | Adds `operation_failed`, the token the daemon and bridge already used for unmapped errors. `VaultError.approvalRequired` and `.replay` (unused) are deleted. `VaultError.readFailure` is exhaustive. | One closed vocabulary from Core to the bridge. |
| Busy check after reservation | A full run table (4 live, 1 per account, 16 held) and a missing host are refused **before** reservation. A missing host also refuses before an approval request is created. | A run that cannot start costs no budget and no approval. |

**Deferred, unchanged from ROLLOUT**

Frame and input relay, `showHuman`, `HumanFrame`/`HumanInput`, `.openHumanStep` signing, the continuation XPC service and `humanSteps` in the snapshot belong to U3 and U4. `openHumanStep`, `concludeHumanStep` and `continuationConnectionClosed` exist on the Broker but have no production caller until U3. The WebKit library still compiles against the shared types. It is deleted in U5.

**Not addressed by U0**

Parent integration carries the R3 read reservation through both API and browser paths: host/run admission, then credential-slot admission, then approval/budget consumption. Reads remain capped at three of four actual workers. Fair per-client invocation retention is preserved. Web-path regression tests verify busy approval retry and absence of slot leaks after host rejection.

**Verification**

`swift test --force-resolved-versions -j 4` and `scripts/verify-boundaries.py` pass on this branch. `BrowserRunTests` drives the real `Broker` and `ReadOperations` through `ScriptedWebHost`. The worker reported a local mutation pass reverting 14 targeted defects one at a time. Its script is not committed, so that report is separate from the parent verification. Parent integration passed 218 tests, MCP and boundary checks after correcting three independently reproduced issues: late classification past the pause deadline, an open session after uncertain rotation, and accumulated sleeping timers. Parent also added the preexisting step binding and web/read-capacity integration tests. The reported worker mutations were: The defects:

- authority that respects the call budget
- a result delivered twice
- a late start not ended
- a repeated step resetting the deadline
- the approval window used for the pause
- a pause that outlives its grant
- no recheck after a host reply
- runs ended after credential deletion
- a pause audited as completed
- a lease not bound to its connection
- busy refused after reservation
- no deadline sweeper
- the bridge hiding failure codes
- the wire accepting a partial profile

None of this tests OS isolation or a real host.

### U1: host wire and broker link (branch `feature/vault-browser-link`)

Implemented against real XPC inside one process, with the host listener's actual identity checks. No browser, installed service or real credential is involved, and the production broker still composes no web host.

- `AgentVaultWebHostProtocol` holds the credential-bearing vocabulary: six commands (`start`, `classify`, `end`, `showHuman`, `frame`, `input`), `HostReply`, `HostFailure`, `HostRejection` and `HostWire`. Each object has one exact key set; duplicate, missing, extra, `null`, nested, fractional or out-of-range values fail before a typed value exists. Commands are capped at 16 KiB and replies at 384 KiB. No field names a URL, origin, selector, script, CDP method or policy. Core, Contracts, IPC, Runtime, CLI, App and both bridge targets cannot link it, and only the broker daemon may link `AgentVaultWebHostLink`; `verify-boundaries.py` enforces both.
- `HumanFrame`, `HumanInput` and `HumanInputBatch` live in Contracts because the app needs them. They carry no credential. Frames are 1–1280 × 1–900 JPEG of at most 256 KiB. A batch holds 1–32 events; text is 1–64 bytes excluding Unicode Cc/Cf control and format scalars.
- The port gained `showHuman`, `frame` and `input`, all keyed by `HumanStepID`. The host binds frames and input to that step epoch and to the latest frame sequence. U3 will relay them under a lease.
- Identity: `WebHostConfiguration` (service, host and broker requirements, host, broker and agent UIDs). Production needs three distinct non-root UIDs and full Developer ID pins, through the same `IPCConfiguration.isPinnedRequirement` rule as the other services. On the broker side it must agree with the broker's IPC identity. Development may share one UID, but every requirement must still pin a cdhash. A production file must be root-protected. The host listener accepts one peer at a time, checks UID and requirement on the connection and on every message, and runs `peerLost` teardown before it accepts another peer.
- The link authenticates every connection generation with an empty probe. Only the fixed `invalid_request` reply, from code that passes the host requirement and the host UID, unlocks commands. An impostor or a host with the wrong UID receives only `Data()`.
- **Judge contract (a), loss scoping:** `losses` is `AsyncStream<Set<BrowserRunID>>`. A run is bound to the generation that carried its start, and later commands go only to that generation. A closing generation reports exactly its bound, not-yet-ended runs, and the Broker ends only those. Tests cover a late notice after a new run, at Core and over real XPC.
- **Judge contract (b) and review R5-2, deadlines:** link budgets are absolute and include connection and probe time: start 15 s, classify 10 s, end 2 s, showHuman 5 s, frame and input 2 s each. `WebHostBudgets.fits` checks credential (5 s) + start + end + a 5 s margin ≤ the bridge's 30 s, and the production initializer refuses budgets that do not fit. Core enforces the same bound itself and does not trust the host to answer. `.dispatching` and `.classifying` carry a `HostReplyDeadline` (`LifecycleWindows.startReply` 15 s, `classifyReply` 10 s). The broker stops waiting at that deadline, concludes `web_timeout`, ends the context and frees the live and account slots. A deadline task enforces this even with no waiter. A late reply goes through `hostReplied` and ends any context it created. A start that times out in the link is followed by `end`. An `end` that is not confirmed drops the connection, so the host loses its only peer and tears everything down. Pending requests fail at once when their generation dies. Collecting and polling still reserve nothing.
- Review R5-3: a host lifetime below one second, or one that is not finite (for example after a clock jump), counts as loss of authority before any secret is sent.
- Bounded concurrency: link lanes (control 8, frame 4, teardown 16) and host lanes (8/4/16). Teardown is never queued behind frame or control work. Tombstones refuse a start after `end` and a duplicate start, without sending either.

Historical branch verification reported 264 registered Swift tests and passing MCP and
boundary checks. The native storage fixtures did not execute by default at that checkpoint.
The original thirteen mutation results used the unsafe cleanup described below; the later
scoped integration record is the accepted evidence. A boundary mutation linking the host
wire into Core was refused. The link-side "loss = every bound run" mutant is equivalent in
reachable states: a new generation exists only after the old one's close handler ran. The
web host's cross-process Mach-service path (`.privileged` lookup) and installed UIDs were
not covered.

**U1 corrections after independent judge review.** The judge confirmed three Medium defects and one Low, each with an isolated probe. All are fixed, and each has a regression test:

- *Credential sent after expiry during authentication.* `start` no longer takes a precomputed lifetime. It takes a `WebStartAuthority` that only the Broker can mint. The link awaits `lifetimeIfStillAuthorized()` after authenticating the generation, and immediately before the credential bytes are admitted and written. The bind step rechecks tombstones and binding under the lock with no further suspension. The Broker callback sweeps, then requires the same run, epoch and dispatch phase before its deadline, plus live `stillAuthorized`. It computes the lifetime at that instant: at least 1 s, at most 900 s. The dispatch deadline is `min(start window, grant expiry)`, and reaching grant expiry while dispatching ends the run as `response_suppressed` with teardown.
- *Cancelled initial caller.* Before this fix, a cancelled read left a paused run that nobody could address. The broker now stops waiting when its task is cancelled and ends the run (`run_cancelled`, host `end`). A late reply then ends the context it created. The read XPC listener cancels a connection's in-flight handlers when that connection is invalidated, so a vanished bridge really cancels. Admin handlers always run to completion, so signed lifecycle mutations keep their journal semantics.
- *Unbounded generation state.* `end` now removes the run from its generation. After 200 start/end cycles on one connection, 0 runs are retained.
- *Low:* `HumanInput.fits` uses range checks and refuses non-positive frame sizes, so `Int.min` and degenerate sizes return `false` instead of trapping.
- *U2 obligation, carried into the listener:* peer loss is terminal. The listener cancels the old peer's running handlers, drops their results, refuses every later peer and runs `peerLost`. The host must also refuse context creation once teardown starts.
- *Harness:* the mutation script used a name-based `pkill`, which could interrupt independent test runs; matching log times do not prove signal delivery.
  It now signals only process groups it created. It first requires every targeted test to pass unmutated, and `deploy/tests/test_webhost_link_mutations.py` proves an independent sentinel survives. The `0986606` branch run reported all twenty-two mutations detected; the final integration adds two registration guards.

## Open questions and risks

- Does `chrome-headless-shell` start, render and screencast as a LaunchDaemon under `_agentvaultweb`, with its own sandbox enabled and before any GUI login? The probe answered this only under `sandbox-exec` with `--no-sandbox`. This is P0.
- Which entitlements does the re-signed shell need under the hardened runtime (`allow-jit`?), and does notarization accept them?
- Should the human channel be allowed for an account whose grant does not require per-call approval? This design says yes: opening is always signed with fresh user presence.
- Does GitHub serve its MFA pages to `HeadlessChrome` without challenge escalation? This needs a live check, using a user-designated test account and a separate instruction.

## Next implementation step

U0 and U1 are integrated. The final U1 registration fix reserves task keys before task
creation, preventing completed-task retention and cancelling registration after invalidation.
The root [integration record](../../../verification/browser-u1-integration.json) supersedes
the historical branch counts above: 281 registered Swift tests including two native skips,
five owned-process checks and all twenty-four baseline-checked web-link mutations detected.
U2 implements the host executable; U3/U4 implement the protected human relay and native controls.
Production remains disabled pending these units and installed proof gates.
