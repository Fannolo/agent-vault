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

Keep browser enrollment and browser actions disabled (`AppFeatures.production`) until a reviewed
isolated GUI host exists. A suitable design runs the web view in a separate per-user GUI
process with its own signing requirement, receives fixed workflow requests and credential bytes
over an authenticated channel, shows the human step itself, and returns only the typed outcomes
above. That host, its IPC and its review are future work.

## Selected production path (in progress)

The selected design is a separate `_agentvaultweb` headless host
([rationale](design/browser-host/selected-headless/RATIONALE.md)). Unit U0 is implemented:
the broker owns every browser run through the `WebSessionExecutor` port, the closed read
statuses and the credential and profile formats. This is verified only against a scripted
in-process host. The production broker still configures no browser host, and the app still
refuses browser enrollment. The host link, the host executable, the human continuation channel
and every installed isolation and egress proof gate (P0–P4) remain open.
