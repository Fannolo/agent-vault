# Browser component deployment boundary

`AgentVaultBrowser` is a verified library, not a deployed feature. It is **not** wired into
the production broker, and the human app refuses to enroll browser-backed accounts.

## What is verified

Automated tests (`Tests/AgentVaultBrowserTests`) drive real `WKWebView` sessions against a
synthetic loopback website (`AgentVaultBrowserFixture`) and prove, for that fixture:

- ephemeral, per-account, non-persistent data stores that are destroyed on revoke or timeout;
- exact scheme/host/port navigation policy, including server redirects, `localhost` versus
  `127.0.0.1`, meta refresh, script navigation, off-origin frames, downloads and popups;
- subresources limited to allowed origins by a WebKit content rule list;
- credential injection only on the exact origin, into one known form whose action stays on that
  origin, with exactly one username and one password field;
- typed output (`profile`, `human_step_required`, closed failure codes); no HTML, cookie, URL or script
  entry point is exposed, enforced by source-invariant tests;
- MFA and CAPTCHA pause the session; the library never submits or bypasses them.

## What is not established

- **No live verification.** GitHub selectors, headers, subresource hosts and the post-login page
  shape are assumptions. No real account or credential was used.
- **CAPTCHA domains are not allow-listed.** The production policy blocks third-party challenge
  hosts, so a real CAPTCHA step would fail closed until reviewed and verified live.
- **No deployed human continuation.** `HumanContinuationView` needs a WindowServer session in
  the same process as the web view. The production broker is a dedicated-UID LaunchDaemon in the
  system bootstrap domain with no GUI login session. The human app, a different process, cannot
  receive that view over the current data-only RPC, and nothing in this repository claims it can.
- The fixture origin can only be built in DEBUG builds (`BrowserPolicy.fixture`); production is
  fixed to `https://github.com`. `browser.demo` has no production origin.

## Production position

Keep browser enrollment and browser actions disabled (`AppFeatures.production`) until the
selected separate headless host, protected human continuation and installed isolation/egress
gates pass. The legacy WebKit component remains a fixture library; it is not the selected
production deployment.

## Selected production path (in progress)

The selected design is a separate `_agentvaultweb` headless host
([rationale](design/browser-host/selected-headless/RATIONALE.md)). U0 and U1 are integrated:
Core owns the lifecycle, closed statuses and credential/profile formats; the host link
uses authenticated XPC, fixed commands, scoped connection losses and bounded waits. A Core-only
admission token rechecks authority after probing and before credential dispatch. The
[U1 record](verification/browser-u1-integration.json) names its exact source and synthetic
checks. These host-link tests use a listener endpoint in one process; the separate ordinary
IPC checks use same-UID processes. Neither proves a deployed web-host service or private UID.

U2's `AgentVaultWebHost` executable is now present. It launches a designated headless shell
over inherited CDP pipes, with a fresh 0700 profile, fixed switches and Chromium's sandbox
enabled. Its closed method vocabulary, phase-aware request gate and document CSP support
fixed workflows. Each challenge frame is a bound crop, revalidated after capture; input
names the current step and latest frame. The service has four run slots and terminal teardown.
Nonblocking writes use per-call deadlines without holding the state lock; cold starts await
confirmed paused auto-attach before creating targets. Concluded IDs cannot be reused.

The [normal U2 record](verification/browser-u2-normal.json) includes the parent's separate
27-test real-host run and 27 link mutations at `39fea8e`. It predates the owned-group reaper
and does not run U2 browser mutations. Fixtures now await independent cleanup even when
teardown is mutated. Failed exit observation kills and waits; interrupted waits retry.
Only a confirmed reap reports success. An unconfirmed wait disables further signals.
Bounded source review accepted these corrections at `a7a2a4c`. The
[combined record](verification/browser-u2-u4-integration.json) at `9390b46` passes a
31-test real-host run and all 18 browser mutations after a passing baseline, with restored
source rebuilt. It also passes all 32 synthetic continuation mutations. Source and browser
executable hashes stay unchanged. The real host and human relay are still separate fixtures.

The measured renderer/GPU sandbox is not whole-process egress confinement: the browser and
network utility are unsandboxed. Fetch and CSP are in-browser policy. Interactive same-UID
fixtures do not establish `_agentvaultweb` LaunchDaemon startup, hardened distribution,
system-domain identity or GitHub policy/selector compatibility. All P0–P4 gates remain open.

U3/U4 now relay a signed, connection-bound step over the authenticated admin connection.
ImageIO validates a single JPEG's type, actual dimensions and orientation before display;
typed input names the latest frame. Finish drains input acknowledgments and stops polling.
Disconnect liveness is checked before lease creation, relay delivery and Finish/Cancel
admission. Synthetic app/XPC tests cover these paths; the full flow through a real host
remains U5 work. Host peer loss is terminal and teardown prevents new context creation.
The production broker still configures no host, the app refuses browser enrollment,
and every installed isolation and egress proof gate (P0–P4) remains open.
