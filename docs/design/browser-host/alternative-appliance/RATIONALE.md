# Candidate A: private browser appliance

## Problem
The browser must retain cookies and credentials outside the agent UID while a person can finish MFA/CAPTCHA. Existing WKWebView ownership cannot cross the daemon's absent GUI session. Broker approval and browser pause are different lifecycles; grant UUID is not a browser session ID. A deployment solution must resolve both facts before enabling browser enrollment.

## Usage (caller's view)
The bridge calls `broker.run(client:account:action:)`, receives `awaitingHuman(operationID)`, and later calls `broker.poll(client:operation:)`. Poll never dispatches or spends another attempt. The signed human app obtains a protected-key approval for `openChallenge(operationID)` and calls `human.open(proof:)`; it renders a cropped raster, relays only bounded challenge input, and calls `human.finish(lease:)`. Revocation remains `broker.revokeGrant(grantID)` and destroys every operation bound to that grant. See `Sketch.swift` for three concrete call sites and derived signatures.

## Shape
One ephemeral Linux browser appliance per operation, hosted by a signed, dedicated-UID macOS BrowserHost. A bundled QEMU TCG process uses no display, host mounts, guest NIC, shared clipboard, or desktop service. A read-only reviewed guest image runs a fixed workflow worker and Chromium with private debugging pipes and tmpfs profile. The only guest egress is a fixed-destination TLS tunnel relay over private virtio-serial; no raw network interface exists. BrowserHost owns process lifetime and validates every guest response. Broker owns authority and operation state. App receives only approved challenge pixels and constrained human controls, never a browser object or cookie API. This deep interface hides boot, CDP, origins, storage and teardown behind `start`, `challenge`, and `destroy`, per boundary-discipline. Core depends on a small domain executor protocol; public Contracts has no credential-bearing host messages.

## Synthesis decision
Runner recommendation only; parent synthesis pending. Choose the appliance for its explicit ownership and absence of macOS GUI-session assumptions. The same fixed workflow and raster interfaces can be implemented independently of appliance packaging, but ship one production backend, not a runtime fallback tree.

## Tradeoffs accepted
- We accept a larger signed distribution, guest update pipeline and slower cold start for a concrete headless execution environment with no WindowServer dependency.
- We accept bounded raster interaction instead of a native embedded browser; no clipboard, password autofill, file picker, WebAuthn/passkey or arbitrary navigation support.
- We accept one short-lived appliance per operation and a small global concurrency cap for clean revocation, grant isolation and no retained login profile.

## Alternatives considered
1. Native macOS Chromium/headless-shell under `_agentvault`, private pipes and the same raster bridge. Much smaller; reject as the chosen deployment until a real system-domain, no-login test establishes operation with sandbox enabled. Chrome's docs explicitly say unified headless creates platform windows and show `open -a` on macOS; neither proves WindowServer-independent operation. If that proof succeeds, parent should favor it over this appliance.
2. Separate macOS login account with WKWebView LaunchAgent and Fast User Switching. Browser ownership is valid under a private UID, but arranging a logged-in Aqua session and a human surface exposes session/login orchestration to installation and disrupts the user's desktop. `launchctl asuser` alone creates neither login nor WindowServer access. Reject; never substitute an agent-UID GUI helper.

## Implementation reconciliation
No implementation or production proof claimed. Parent can graft the lifecycle/raster design without accepting the appliance. No repo files, accounts, system settings, credentials or existing profiles changed.

## Open questions and risks
Can measured appliance startup and challenge latency meet the product target? Can the signed QEMU binary run with its reviewed JIT entitlement under the installed dedicated UID? Can the reviewed GitHub challenge be completed through bounded pixels/input without adding unreviewed origins? These are executable release gates, not reasons to postpone independent implementation.

## Next implementation step
Implement the broker operation state machine with a deterministic executor that pauses, completes and crashes; prove once-only attempt accounting and revocation during every await before adding any new credential transport.
