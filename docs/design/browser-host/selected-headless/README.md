# Candidate B: sealed web host + raster human channel

The design runs the browser in a separate LaunchDaemon (`_agentvaultweb`) that drives a pinned Chromium headless shell over private pipes. People complete MFA and CAPTCHA steps through JPEG frames and bounded input events, relayed by the broker into the human app. Core gains an in-memory, broker-owned run lifecycle with one pure transition function. The WebKit library and `SessionServiceAdapter` are deleted rather than adapted.

Status: design plus scratch probe. Nothing was built in the repository, installed, signed or run with real credentials. **No production or isolation claim is made.**

## Files

| File | Content |
|---|---|
| `RATIONALE.md` | One-page rationale: problem, usage (caller's view), shape, tradeoffs, alternatives, risks, next step |
| `DEPLOYMENT-ALTERNATIVES.md` | Five deployments (A chosen, A′ fallback, B/C/D rejected) plus one sub-choice (E), each challenged with doc, probe or inference tags |
| `ROLLOUT.md` | Units U0–U6, OS proof gates P0–P4, the U0 test list |
| `sketch/1-Contracts.swift` | Closed read statuses, `AccountProfile`, `CredentialFormat`, human continuation DTOs, `VaultContinuationRPC` |
| `sketch/2-WebHostProtocol.swift` | Broker↔host commands, steps, failures, wire |
| `sketch/3-Core-BrowserRuns.swift` | IDs, deadline types, `Windows`, `WebHost` port, `BrowserRun`, `transition` table, `stillAuthorized`, Broker diff |
| `sketch/4-WebHost.swift` | Host process, `ChromiumPipe`, closed `CDPMethod`, `RequestGate`, `Recipe`, `WebRun` |
| `sketch/5-Composition-App-Graph.swift` | `WebHostLink`, daemon composition, third XPC service, App model and view, bridge diff, package graph and boundary rules |
| `sketch/6-SyntheticE2ETest.swift` | The synthetic end-to-end fixture-host test suite |
| `proto/RESULTS.md`, `proto/pipe_cdp_probe.py`, `proto/*.swift` | Scratch probes and measured results |

All sketch files pass `swiftc -parse`. They do not type-check standalone, because they reference repository modules.

## Key evidence

- **TN2083:** only EUID 0 or the console UID may use the window server. A daemon "cannot display any GUI". Together with `launchd.plist`'s "for agents, the UserName key is ignored", this rules out a private-UID GUI host without root.
- **Probe:** `chrome-headless-shell` 149 over `--remote-debugging-pipe` ran login, the off-origin gate, the isolated-world recipe, the screencast frame, human MFA input and the typed profile, leaving no cookie on disk. It produced identical results with WindowServer, Dock, pasteboard and TSM lookups denied. An AppKit control saw 0 screens under that denial. This was not run as a LaunchDaemon, and Chromium's sandbox was off under `sandbox-exec`. That gap is gate P0.
- **Chrome 136+** ignores debug switches on the default profile and requires a custom `--user-data-dir`.

## Red-flag screen

- **Shallow module:** the host exposes six commands that hide spawn, CDP, gate, recipes and screencast. The App sees pixels and `HumanInput` only.
- **Information leakage:** CDP exists only inside an executable target. Precise `HostFailure` codes stay in audit. Agents see `ReadFailureStatus`, mapped in one Core switch.
- **Split ownership:** the run's authority state is owned by the Broker alone. The host's context map is a resource map, ended by `end`, by its own lifetime cap (≤900 s), or by losing its broker peer. Either side's loss converges to "no context".
- **Two ways:** `resume` serves approvals and runs through one entry. The WebKit path coexists only until U5 (unwired) and is then deleted.
- **Hand-synced lists:** fixed. The bridge's status lists, `failed:<code>`, the duplicate workflow enum and the 4096-vs-8192 credential checks are each replaced by one source. One list remains outside the build's checks: the Mach service names in the plist and in the config. `verify-installer.py` must compare them.
- **Importable internals:** `AgentVaultWebHostProtocol` is kept out of App and Bridge closures by `verify-boundaries.py`. The host is an executable target.

## Smallest first unit

U0 is pure Swift, with no browser and no OS dependency. It covers the contracts reconciliation, the Core run lifecycle against a scripted host, and the deletion of `SessionServiceAdapter`. Its tests pin budget-once, delivered-once, the 120 s/600 s split, pause ≤ grant, revocation during dispatch, and the corrected audit stages. See `ROLLOUT.md` § U0.
