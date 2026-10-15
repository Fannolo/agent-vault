# Deployment alternatives, challenged

The question every option must answer: which process holds the cookies and the credential, under which UID? And how does a person's MFA or CAPTCHA input reach that process, without that process or its data becoming reachable from the agent's UID? Evidence tags: **[doc]** primary documentation, **[probe]** measured in `proto/` on this Mac, **[inference]** reasoning not yet measured.

## A. Sealed headless web host + raster continuation (chosen)

`dev.agentvault.webhost` is a LaunchDaemon in the system domain with `UserName _agentvaultweb`. It spawns a pinned, Bite-signed `chrome-headless-shell` with `--remote-debugging-pipe`, a fresh 0700 user-data directory and `--use-mock-keychain`. Each run gets an incognito browser context. The broker is its only peer. The App receives JPEG frames and sends `HumanInput` through the broker.

| Challenge | Answer |
|---|---|
| Does a daemon get a GUI? | It needs none. Headless rendering and screencast completed the synthetic MFA flow while every WindowServer, Dock, pasteboard and TSM Mach lookup was denied. A plain AppKit control dropped to 0 screens under the same profile **[probe]**. A real daemon context, with Chromium's sandbox on, is still unproven: that is **P0**. |
| Can the agent attach to the debugger? | No TCP port exists, only inherited fds 3/4 **[probe]**. Chrome 136+ refuses debug switches on the default profile, so a custom `--user-data-dir` is mandatory anyway **[doc: Chrome blog]**. The agent UID cannot open the fds of another UID's process **[inference → P1 test]**. |
| Cookies on disk? | The session cookie stayed in memory. No file under the user-data-dir contained it after the context was disposed **[probe]**. The dir is 0700 `_agentvaultweb` and is wiped on start and exit. |
| Arbitrary navigation? | A `Fetch.requestPaused` gate failed an off-origin 302 and an off-origin `<img>` **[probe]**. Production adds per-phase path rules, WebSocket blocking, popup closing and download denial. The ported hostile suite must also cover service workers. |
| Human MFA? | Click, `insertText`, Enter on the frame completed the MFA form. The agent's code never POSTed `/mfa` **[probe]**. |
| CAPTCHA? | Challenge origins are allowed only in `.humanStep(.captcha)` and only as subresources or frames. The production list starts empty, so the result is `challenge_unavailable` until a live review. A provider can also refuse headless browsers. There is no spoofing. |
| Interference with other apps? | Separate UID, separate data dir, mock keychain (no "Chrome Safe Storage" item), no port, no LaunchServices registration. The user's Chrome and profiles are untouched. |
| Supply chain | A pinned CfT version and SHA-256 sit in the public repo. The release script downloads, verifies, re-signs with Bite team `3JWAQ92CB4` under the hardened runtime and notarizes. A release gate fails when the pin is more than N days behind the newest stable CfT. |

Weakest point: P0 is unmeasured. If Chromium cannot run sandboxed in a LaunchDaemon, swap the renderer inside the host (see A′). The host keeps the same six commands, and Core, App and contracts do not change.

## A′. Same sealed host, headless WKWebView renderer (fallback, not shipped alongside)

Same process map. The renderer is offscreen `WKWebView` plus a nonpersistent store, which reuses today's verified policy and recipes.

- For: an Apple-signed system framework that updates with macOS; no 200 MB bundle.
- Against: `NSApplication` and an offscreen `WKWebView` loaded and snapshotted with WindowServer lookups denied **[probe]**, but WebContent and Networking are launchd XPC services that `sandbox-exec` did not constrain, so daemon behavior is unknown. AppKit "requires a GUI per-session bootstrap namespace" **[doc: TN2083]**. There is no supported input injection into a window-less view (it would need synthesized `NSEvent`s) and no screencast API (it would need repeated `takeSnapshot`).
- Verdict: weaker human channel and no better isolation. Keep it only as the P0-failure fallback.

## B. Private-UID GUI host in the console session (rejected)

A separately signed host runs as `_agentvaultweb` and shows `HumanContinuationView` in a real window.

- "A process can only use the global window server service if its EUID is 0 … or matches the UID of the console user. All other users are barred" **[doc: TN2083, Permission To Connect]**.
- A LaunchAgent cannot change UID: "for agents, the UserName key is ignored" **[doc: local `man launchd.plist`]**. Entering the Aqua bootstrap namespace as another UID needs root (`launchctl asuser`) or an `audit_session_join` handoff. Either way the EUID check above still applies.
- Variants: running as root fails least privilege, since web content would run as root. Running as the console UID equals the agent UID, which fails isolation.
- Verdict: blocked by documented platform rules, not by missing work.

## C. Renderer inside the broker UID (rejected)

The broker spawns Chromium as its own child under `_agentvault`. This means one fewer UID, plist and peer pin.

- A renderer plus sandbox escape from github.com content (or from a compromised asset origin) would land in the UID that owns `broker.keychain-db`, `keychain.password` and `state-integrity.key`. That exposes every account's credentials, not just the one in flight.
- Verdict: the interface is identical to A, so the extra UID buys a real reduction in blast radius at the cost of only installer work.

## D. Same-UID host: App-embedded or per-user LaunchAgent (rejected)

The agent shares the UID. It can read or replace the cookie directory, kill or restart the host, look up its Mach service, and race the host's files. Hardened runtime protects memory, not files. The brief says this does not meet isolation.

## E. App talks to the host directly for frames (rejected sub-choice within A)

The host would have to authenticate the App, track grant authority and accept a second peer class. Relaying through the broker keeps a single authority holder, and the host's only peer stays the broker.
