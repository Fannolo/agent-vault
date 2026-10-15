# Rollout, proof gates and first unit

Each unit ends green on `swift test` plus `scripts/verify-boundaries.py`, and lands as its own commit. Units U0–U5 need no installation, real credential or root, so none of them waits on the OS proof gates. Browser stays disabled in the production composition until P0–P3 pass.

## Implementation units

| Unit | Content | Ends verified by |
|---|---|---|
| **U0 (smallest first)** | Contracts: `ReadOutcomeStatus`, `ReadFailureStatus`, `ReadStatus`, `AccountProfile`, `CredentialFormat`, `WebLoginCredential`. Core: `RunID`, `LeaseID`, deadline types, `Windows`, `BrowserRun`, pure `transition`, `stillAuthorized`, `WebHost` port, `Broker` web branch + `resume`/`cancel` routing + `endRuns`, audit stages. Delete `SessionServiceAdapter`, `GitHubProfile`, the bridge's hand lists and the 120 literal. | Table tests on `transition`. Broker tests with an in-process `ScriptedWebHost`: budget once, delivered once, 120≠600, pause ≤ grant, revoke/rotate/delete end runs, last call collectable, reentrancy (revoke during `start`), audit never says `completed` on a pause. WireCodec rejects `failed:x`. |
| U1 | `AgentVaultWebHostProtocol` (`HostCommand`/`HostReply`/`HostWire`) and the `WebHostLink` client. Fuzz targets added to `AgentVaultParserFuzzTests`. | Exact-shape round trips; oversize and unknown keys rejected; probe before credential. |
| U2 | `AgentVaultWebHost` executable: `ChromiumPipe`, `CDPMethod`, `RequestGate` (pure), `Recipe` (ported), `WebRun`, `HostService`, single-peer listener, exit on peer loss. Fixture gains a challenge origin, step paths, a POST log, a service-worker page and a WebSocket page. | `RequestGate` exhaustive tests; ported hostile suite against the real headless shell (`AGENT_VAULT_TEST_CHROMIUM`); source invariants: no `--no-sandbox`, no `remote-debugging-port`, no `Runtime.evaluate`, `CDPMethod` closed. |
| U3 | Third XPC service (`VaultContinuationRPC`) with its own gates; `Peer.pid`; `ContinuationOperations`; `.openHumanStep` admin operation and `humanSteps` in the snapshot. | IPC tests: admin capacity holds under continuation saturation; lease pid binding; WireCodec shapes. |
| U4 | App: `HumanStepModel`, `HumanStepView`, `XPCContinuationTransport`, Requests list, feature flag driven by the broker's `browserEnabled`. | App tests with an in-memory transport; screenshot tour entry for the human step. |
| U5 | **Synthetic end-to-end fixture-host test** (`sketch/6-SyntheticE2ETest.swift`), then delete `AgentVaultBrowser`, `HumanContinuationView` and `AgentVaultBrowserTests`; update boundary rules and docs (BROWSER-DEPLOYMENT, THREAT-MODEL, IPC). | E2E suite green in the development (same-UID) configuration; boundary script passes the new rules. |
| U6 | Release and installer: `_agentvaultweb` user, `dev.agentvault.webhost.plist`, `/private/var/db/agent-vault-web`, config `browser` block, `deploy/webhost/chromium.pin.json` (version, URL, SHA-256), re-sign script (Bite `3JWAQ92CB4`, hardened runtime, minimal entitlements), age gate, SBOM entry. | `verify-installer.py` dry run; signature and entitlement inspection of the bundle. Signing evidence stays local, not committed. |

Units that touch disjoint targets can go to parallel implementers (Claude/Codex) once U0's contracts are merged: U1+U2 (host side), U3+U4 (app side). U5 joins them.

## OS proof gates (disposable macOS VM only, never on the user's machine, synthetic accounts only)

| Gate | Procedure | Pass condition |
|---|---|---|
| **P0 renderer in daemon** | Install the webhost plist and the signed shell in the VM. Reboot to the login window with no user logged in. Run the U2 fixture flow through the broker. Repeat with a user logged in, and during fast user switching. | Frames and profile are produced, with Chromium's sandbox on (check `ps` for renderer `--type=renderer` and that `--no-sandbox` is absent). No `_RegisterApplication` or WindowServer errors fatal to rendering. Record the needed entitlements. On failure: implement A′ inside the host and rerun. |
| P1 agent cannot reach session | As the agent UID: read `/private/var/db/agent-vault-web`, `lsof -p` and attach to the host/Chromium pids, look up and connect to `dev.agentvault.webhost`, scan `lsof -i` for listeners, signal the host. | Every attempt is denied. No TCP listener is owned by `_agentvaultweb`. |
| P2 human continuation installed | Signed App on a real GUI login: open (Touch ID), complete fixture MFA and fixture CAPTCHA, cancel, let it expire. | The typed result reaches the MCP bridge. Cancel and expiry leave zero contexts (host debug counter, process tree). |
| P3 lifecycle under load | Revoke, rotate, delete and expire during the pause. Kill the broker, then kill the host, mid-pause. Saturate continuation while revoking via admin. | Run removed and context disposed in every case. Revocation latency is unaffected by continuation saturation. |
| P4 live GitHub (separate user instruction) | A user-designated test account in the VM. Verify selectors, asset and challenge origins, and headless acceptance. | The workflow completes, or fails closed with a recorded reason. Policy edits are reviewed, never widened to make a page pass. |

No production isolation claim is made before P0–P3 pass on an installed system. P4 gates enabling `githubWeb` in shipped configuration.

## U0 test list (write first)

1. `reserve → humanStep → resume×3 → open → finish → profile → collect`: `callsUsed == 1`, result delivered once.
2. Approval run: invocation `consumed` at dispatch; `RunID ≠ invocation ID`; invocation expiry (120 s) does not end the paused run.
3. A pause started at t=0 ends at `min(600, grant.expiresAt)`; reclassify returning `humanStep` again keeps the original deadline.
4. `revokeGrant` during `ScriptedWebHost.start` (suspended): output suppressed, `end` called, audit `response_suppressed`.
5. `revokeClient`, `rotate`, `deleteAccount`, and host loss each end or conclude the right runs only (another account's run survives).
6. A grant with `callLimit 1`: the run is still collectable after its reservation.
7. Audit never records `completed` for `human_step_required`.
8. WireCodec: a `ReadReply` whose status is not in `ReadStatus` is rejected. The bridge maps every `ReadFailureStatus` case verbatim.
