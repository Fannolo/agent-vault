# U5: real host and human-model composition

Private `verification-logs/...` paths in this historical U5 note are relative to the
original evidence worktree `/Users/alessandro/.t3/projects/agent-vault-worktrees/browser-e2e`,
where those logs remain locally available. They are not claimed to be copied into
other worktrees. Later secret-boundary runs have their own local evidence.

The U5 test target joins the real HostService, WebHostServer, WebHostLink, Core Broker,
read/admin XPC services, AppModel, HumanStepModel and ImageIO. Only this test target links
those implementation modules together. Product roles retain their previous dependency
boundaries; the production daemon still supplies no web host and browser enrollment stays off.

The anonymous XPC listeners enforce the current test executable's cdhash and kernel UID.
The admin challenge is signed by the DEBUG-only software fixture signer. A fresh synthetic
loopback site and private Chromium profile belong to each test. No existing browser profile,
Keychain, account, credential, installed Mach service or external website is used.

## Running the opt-in proof

```sh
python3 scripts/verify-headless-e2e.py --chromium /absolute/designated/chrome-headless-shell
```

The command explicitly sets `AGENT_VAULT_TEST_CHROMIUM` for its children, unsets the native
Keychain opt-in, builds its own worktree and runs `HeadlessContinuationE2ETests`. Without
that Chromium variable the suite has an observable skip trait. The driver imports
`run_owned` from the existing web-link mutation helper, without editing it. Builds and
test runners have bounded waits and owned process groups. Each run gets fresh private logs
under ignored `verification-logs/u5-*`; source and raw logs are not published by this command.

Each Swift stack retains ChromiumPipe's actual owned process handle. A 45-second watchdog
retains that handle after launch; if it fires the test fails, kills through the pinned
OwnedGroup and awaits reap. Normal and exceptional cleanup likewise kills and awaits that
owned browser independently of host end/teardown before removing its private directory.
No process is found by name and no remembered PID/group is signalled after its ownership ends.

## Exercised seams

- Both synthetic MFA and CAPTCHA pass through agent read XPC, the authenticated host link,
  a signed admin open, real cropped JPEG/ImageIO, bounded pointer/text/key input, Finish,
  and one typed profile delivered through agent read XPC. One attempt budget is spent.
- Future and previous challenge epochs are refused before signing. Finishing an unfinished
  challenge advances the broker epoch, keeps the original deadline and invalidates the old lease.
- Wrong frame and replayed batch IDs never reach the host; a newer served frame invalidates
  input to the old one. Closing or disconnecting a lease keeps the pause and permits a new
  signed open, while another connection cannot use the original lease.
- Grant revocation ends the model/context. An unpolled human pause expires. Host peer loss
  tears down its real browser context and produces session loss instead of a profile.
- Agent replies and stored audit contain no password, page, cookie, origin or JPEG payload.

The first full composition reproduced a U2/U3 mismatch: Core permits a new lease for the same
challenge after Close or connection loss, but the host required a strictly greater challenge
epoch. `showHuman` is now idempotent for the current positive epoch, preserves its latest frame
watermark and still refuses a lower epoch. It rechecks the phase/epoch after inspecting the
challenge. The direct U2 regression and browser mutations cover regression and watermark loss.

## Unit A verification

- Default `swift test --force-resolved-versions -j 4`: 366 registered tests / 29 suites,
  with explicit Chromium and native-Keychain opt-out skips; no failures. Private log:
  `verification-logs/u5-unit-a-kr93rx1r/swift.log`.
- Explicit real U5 plus direct U2 reopen regression: 8 registered tests / 2 suites, no skips,
  passing in 9.590 seconds. The MFA/CAPTCHA method has two parameter cases.
- Removing the old-epoch guard and resetting the same-step frame watermark were each detected
  by the direct regression after successful builds. Restored sources built and passed all eight
  selected tests. Private logs: `verification-logs/u5-reopen-mutations-qhq8l2nh/`.
- Default synthetic MCP and the product dependency-boundary check passed. The browser mutator
  now has 19 cases; only the two changed reopen defenses were rerun in this unit, so this note
  makes no claim that all 19 cases ran on this source.

## Unit B: one renderer path

The unused `Sources/AgentVaultBrowser` engine and `Tests/AgentVaultBrowserTests` were removed,
including the old in-process HumanContinuationView. BrowserFixture remains renderer-independent.
The app invariant now inspects the two real app targets, and the package graph refuses the old
engine/test targets while retaining the fixture and all product-role isolation checks.

| Removed verification | Current coverage |
|---|---|
| Exact origins, scheme/port/suffix/userinfo refusal | RequestGateTests, including migrated production-origin vectors |
| Off-origin navigation, resources, frames, popups and unsafe forms | RealBrowserTests hostile loopback cases and RequestGate/CSP cases |
| Reflected/invalid profile fields and typed results | RealBrowserTests plus U5 agent read-XPC collection |
| MFA/CAPTCHA, pause expiry and revocation | RealBrowserTests, Core run lifecycle and U5 native-model/XPC scenarios |
| Ephemeral per-account stores and independent destruction | RealBrowserTests now observes distinct fixture cookies, clean login requests and an unaffected second context after ending the first |
| Credential grammar/redaction and fixed recipes | HostWireTests and migrated host source/credential invariants |

The cookie-separation test passed before mutation. Removing the target's private-browser-context
binding then caused actual inherited Cookie headers on the second and later login POSTs; the
test detected both. The restored tree passed all 42 registered host/U5 tests in 8 suites,
without skips, in 28.483 seconds. Private logs:
`verification-logs/u5-context-mutation-vbsm8iq7/`.

The default suite passed 342 registered tests / 26 suites in 32.740 seconds, with explicit
Chromium/native-Keychain opt-out skips. Default synthetic MCP and package boundaries passed.
Private default log: `verification-logs/u5-unit-b-algvn96f/swift.log`. The browser mutator now
has 20 cases; this unit reran the new context-isolation mutant, not the complete catalogue.

Shared-doc updates left to the parent: README's WebKit feature bullet, ARCHITECTURE's Browser
row, BROWSER-DEPLOYMENT's legacy-library status and deleted test paths, THREAT-MODEL's engine
description, and IMPLEMENTATION-PLAN's current U5 state. Selected-design current-state text
can now mark U5 complete. Historical grounding and verification records must retain their
original source/artifact references rather than being rewritten as new proof.

## Limits

This proves native model/ImageIO behavior and authenticated XPC with a real synthetic browser.
It is not a visible GUI-window test, protected-key/user-presence proof, separate-UID isolation,
LaunchDaemon/pre-login startup proof, whole-process egress boundary, GitHub compatibility,
hardened distribution or notarization. The fixture CAPTCHA only exercises its reviewed local
challenge shape. Production remains disabled until the installed proof gates pass.

The parent owns updates to BROWSER-DEPLOYMENT, THREAT-MODEL, IPC, IMPLEMENTATION-PLAN and the
verification recorder. Add this separate opt-in command/check and preserve explicit skip
reporting. Historical U1–U4 counts do not describe changed U5 source.
