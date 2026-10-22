# Browser component deployment boundary

The selected implementation is `AgentVaultWebHost`, a separate fixed-workflow Chromium
host. The legacy WebKit engine, its target and its continuation view are removed. The
production broker configures no web host and the human app refuses browser enrollment.

## Local evidence and production limits

Synthetic loopback tests use real Chromium, the authenticated host link, Core, read/admin
XPC, AppModel, HumanStepModel and ImageIO. U5 joins those components to exercise challenge
frames/input, close/reopen, Finish, revocation, expiry and host loss, ending in a typed
profile. These listeners run under one interactive UID with a software fixture signer;
they do not prove a visible native window, real protected approval key or installed daemon.
See [U5 evidence and source checkpoints](design/browser-host/selected-headless/U5-E2E.md).
The parent integration checkpoint must be verified separately after review corrections.

Fixed origins/recipes, request interception, document CSP, paused target attachment and
private CDP pipes constrain the tested browser flow. No agent receives HTML, cookies,
storage, a profile path, debugging endpoint or reusable authenticated session. A bound
challenge crop is delivered only to the human app, not to an agent tool.

Live GitHub selectors, resources, challenge origins and landing pages are unverified.
The production challenge-origin list is empty and fails closed. The DEBUG loopback fixture
is not a production service. In-browser request policy is not whole-process egress
confinement. Signed distribution, dedicated-UID LaunchDaemon startup and installed
network/process isolation remain open P0–P4 gates. Keep browser enrollment/actions disabled
until those gates pass, even when deployment has been authorized.

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
executable hashes stay unchanged. That record predates U5, which joins the host and human
relay through synthetic authenticated XPC and the native app model.

The measured renderer/GPU sandbox is not whole-process egress confinement: the browser and
network utility are unsandboxed. Fetch and CSP are in-browser policy. Interactive same-UID
fixtures do not establish `_agentvaultweb` LaunchDaemon startup, hardened distribution,
system-domain identity or GitHub policy/selector compatibility. All P0–P4 gates remain open.

U3/U4 now relay a signed, connection-bound step over the authenticated admin connection.
ImageIO validates a single JPEG's type, actual dimensions and orientation before display;
typed input names the latest frame. Finish drains input acknowledgments and stops polling.
Disconnect liveness is checked before lease creation, relay delivery and Finish/Cancel
admission. U5 joins these paths to the real host with a synthetic origin and fixture signer.
Visible GUI and installed protected-key continuation remain unverified. Host peer loss is terminal and teardown prevents new context creation.
The production broker still configures no host, the app refuses browser enrollment,
and every installed isolation and egress proof gate (P0–P4) remains open.

## Offline distribution preparation

`prepare-webhost-release.py` validates and stages an explicitly supplied local browser,
host and evidence set. Its checked-in pin refuses preparation until reviewed inputs exist.
Archive hash and ZIP inspection use one bounded anonymous snapshot; publication uses pinned
directory descriptors and conservative trusted-ancestry/ACL checks. All activation, runtime
proof and notarization flags remain false, and configuration/plist outputs are disabled.
This is not an installer or P0–P4 proof. See the
[preparation scope](design/browser-host/selected-headless/U6-DISTRIBUTION-PREPARATION.md).
