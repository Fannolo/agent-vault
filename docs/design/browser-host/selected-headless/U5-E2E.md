# U5: real host and human-model composition

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

## Limits

This proves native model/ImageIO behavior and authenticated XPC with a real synthetic browser.
It is not a visible GUI-window test, protected-key/user-presence proof, separate-UID isolation,
LaunchDaemon/pre-login startup proof, whole-process egress boundary, GitHub compatibility,
hardened distribution or notarization. The fixture CAPTCHA only exercises its reviewed local
challenge shape. Production remains disabled until the installed proof gates pass.

The parent owns updates to BROWSER-DEPLOYMENT, THREAT-MODEL, IPC, IMPLEMENTATION-PLAN and the
verification recorder. Add this separate opt-in command/check and preserve explicit skip
reporting. Historical U1–U4 counts do not describe changed U5 source.
