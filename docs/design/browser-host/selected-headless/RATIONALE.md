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

None yet.

## Open questions and risks

- Does `chrome-headless-shell` start, render and screencast as a LaunchDaemon under `_agentvaultweb`, with its own sandbox enabled and before any GUI login? The probe answered this only under `sandbox-exec` with `--no-sandbox`. This is P0.
- Which entitlements does the re-signed shell need under the hardened runtime (`allow-jit`?), and does notarization accept them?
- Should the human channel be allowed for an account whose grant does not require per-call approval? This design says yes: opening is always signed with fresh user presence.
- Does GitHub serve its MFA pages to `HeadlessChrome` without challenge escalation? This needs a live check, using a user-designated test account and a separate instruction.

## Next implementation step

U0: add `ReadOutcomeStatus`/`ReadFailureStatus`, `AccountProfile` and `CredentialFormat` to Contracts. Add `BrowserRun`, the pure `transition`, `stillAuthorized` and `Windows` to Core, driven by an in-process `ScriptedWebHost`. Delete `SessionServiceAdapter`. Then table-test budget-once, delivered-once, the 120/600 split and revocation.
