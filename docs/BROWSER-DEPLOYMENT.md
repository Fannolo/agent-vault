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

App-safe contracts bound JPEG size/markers, declared dimensions, frame sequences and typed
input batches. They do not yet decode images or relay human input from the app. U2 supplies
the actual headless executable; U3/U4 supply signed, connection-bound continuation and native
raster/input controls. Host peer loss is terminal, and U2 must refuse context creation once
teardown starts. The production broker still configures no browser host, the app refuses
browser enrollment, and every installed isolation and egress proof gate (P0–P4) remains open.
