# Implementation plan

## Headless delivery work: 23 October 2026

Shared broker Core, approval and credential modules now compile on Linux. GitHub Actions
run [39880214643](https://github.com/Fannolo/agent-vault/actions/runs/39880214643), at
`2219b11`, passed both jobs: Linux ran 55 VaultCore tests, 7 VaultSecret tests and 131
shared-root tests. Native macOS checks passed in the same run. Source review found no
actionable defect in the bounded streaming replacement. The later integration of the
reviewed credential-verifier timeout fix requires its own exact-head CI result.
This proves library portability, not a Linux daemon, dedicated service identity, secret
custody, cross-process durability, network containment or installed-host behavior.
The Linux manifest omits Keychain implementations rather than substituting weaker storage.
OrbStack remains stopped.

The native socket transport (commit `2571da2`) carries the fixed read and signed admin
calls over separate Unix sockets into the real broker, using the daemon's own handler
composition. Peer UIDs come from `SO_PEERCRED` on Linux and `getpeereid` on macOS; see
[IPC](IPC.md#unix-socket-transport). On macOS 15 with Swift 6.2.4, run through
`scripts/verify-socket-transport.py --full --mutations`: 19 socket tests pass, the root suite
reports 381 passing tests with existing opt-ins skipped, and `verify-mcp.py` and
`verify-boundaries.py` pass. All 8 transport mutations fail their named test, and the
synthetic canary scan of 22 logs is clean. Tests run every role under one UID; denied UIDs
are simulated by configuration. The Linux compile and test result needs root CI and is not
claimed here. The Linux broker exits `custody_unavailable` until vault key custody exists,
and the Linux MCP bridge is not built. Dedicated accounts, systemd units and an installed
host remain unproven.

The user authorized completion of private website login and continuing browser operation,
native Linux/headless service, cloud accounts/sync, import/export and installed distribution.
The end-to-end acceptance criteria are in [DELIVERY-PLAN.md](DELIVERY-PLAN.md). This is active
implementation work, not a completed product or release.

The membership verifier's fixed tables now live in `scripts/membership_spec.py`. Live
exchange and receipt replay share one sequence, and all policy/N1 source mutations use one
definition. A required negative-exchange check prevents both paths agreeing on an incomplete
run. Native backend-masking evidence now requires a compiler line for the mutated source.
The Python suite passes 64 tests in normal and optimized modes. Fresh complete recording
and controls remain pending; historical receipts are not evidence for these changed bytes.

`Packages/VaultSecret` provides a redacted immutable owned buffer and scoped trusted byte
access. Development integration now moves `WebLoginCredential` from agent-visible Contracts
to `AgentVaultCredentials`. Readable username/password/bytes properties are removed. Only
the private wire serializer and host fill adapter import its reveal SPI. A source/graph
allowlist rejects reveal imports elsewhere, including declared custom source paths.
Seven native buffer tests and four credential tests pass. The default root suite reports
356 passing tests, with existing opt-ins skipped. With Chromium 149.0.7827.55 enabled,
26 synthetic browser/continuation/secret-boundary tests pass. The guard/API-timeout suite
passes 10 tests normally and optimized; module boundaries and MCP checks pass. Compiler probes confirm the credential
is absent from Contracts, has no password property, and cannot reveal bytes without SPI.
This integration is awaiting independent review. It does not prove installed custody or
erase transient copies made by validation and the JSON/CDP serializer.

Local Linux attempts are retained as failures. One lost the Docker connection; a later run
passed all 55 Swift tests on each platform but interleaved framework output with corpus JSON,
which the strict recorder correctly refused. U1 recording commands now select `--no-parallel`.
Another attempt found Docker stopped before container creation. The user explicitly asked
to leave OrbStack stopped. New isolated Linux CI checks cover VaultCore and VaultSecret;
their results, plus complete exchange/control receipts, must be verified before claiming
the cleanup gate or Linux product integration complete.

The user selected Bite for hosting. The connected Bite Supabase organization has existing
application projects; Agent Vault needs separate project/storage. New-project provisioning
was declined by the user at the quoted $10/month. Do not provision a paid project. No
existing app schema, data or credentials have been changed. The managed-auth design revision
is accepted as an architecture option; deployment needs free or existing approved hosting
and an SMTP sender for public signup. Source work continues without paid provisioning.

## Membership implementation checkpoint: 22 October 2026

Synthetic U1 membership lineage and stateless revision authorization are verified in the
separate package. All 13 original codec files remain unchanged. The combined 55-test suite
passes on macOS and Linux, with matching outcomes for all 150 pinned Ed25519 cases.
Both producer directions, four independent A/B readers, two rejected signature flips and
two restored reads pass. All 20 M1–M10 policy controls are detected, with passing targets
before and after each mutation. Separate N1 reports native backend masking and exactly
14 intended Linux failures. Every control phase reruns the build command; phases share
scratch directories and use incremental rebuilds. Native N1's actual compilation is
manually confirmed in its retained build log.

The verifier passes 61 tests in normal and optimized Python. Root Swift reports 352 tests;
existing Chromium/Keychain opt-ins remain inactive. Boundary and MCP checks pass. Opus 5.5,
Grok 4.7 and Codex accept the corrected source and actual runtime evidence. Two recorder
defects were fixed: temporary-path aliases and Swift Testing's exact failure remarks.
Failed attempts remain failed; source restoration and owned-container removal are recorded.
See the [U1 evidence](verification/membership-u1.json).

`MEMBERSHIP.md` and `AGENTS.md` remain byte-identical to the measured epoch. The membership
document's pre-verification introduction is historical. The documentation-only status update
preserves the measured `7972b59` epoch. The CI test correction below creates a later input
epoch. The bounded synthetic checkpoint permits neither app linkage, real-password storage
nor U2.

### CI JSON test portability correction

CI exposed a test that incorrectly treated a balanced 2,000-level JSON array as malformed.
Local Python rejected it at its recursion limit, while CI's decoder accepted the valid JSON.
The test now uses an unclosed array and directly checks the existing `RecursionError`
mapping with a mock. With local Xcode Python 3.9.6, all 61 tests pass in normal and optimized
modes, under both the default recursion limit and an increased limit. These local runs do
not establish CI's interpreter behavior. Parser, verifier and Swift code remain unchanged.

The test file is a bound input, so this correction changes the input epoch. The earlier
Mac/Linux receipts remain evidence for `7972b59`; they are not a new recording of the
corrected test epoch. The current control command requires a fresh matching baseline.
The [U1 record](verification/membership-u1.json) includes the exact test-only transition.
The old-baseline refusal policy is supported by source and a unit test; this transition
does not include a logged CLI invocation against the historical baseline.

### Harness cleanup gate before further feature growth

The verifier and its test module have grown beyond 1,000 lines. Before another harness
feature unit, extract the fixed tables, use one exchange-step table for the live run and
receipt replay, and use one mutation specification for M1–M10 and N1. Preserve canonical
process ownership, exact restoration, strict error attribution and the original codec files.
The cleanup must include fresh Mac/Linux baselines, bidirectional exchange, all controls
and independent review under a new source epoch. Existing receipts cannot prove a refactor.

Also strengthen native masking evidence so compilation is checked mechanically, exercise
the U1 snapshot directly through a directory alias, and bind outer receipts explicitly.
Retain the finite-scan, lexical-custody and writable-controls-alias limitations until their
respective boundaries are actually strengthened. These are open tasks, not completed fixes.

## Multi-platform checkpoint: 21 October 2026

The confirmed product scope includes independent native Linux and macOS hosts, account
signup/login, encrypted cloud sync and discovery-first private login for approved agents.
Broad website grants include submissions, messages, payments, deletion and security changes.
The [selected architecture](design/multiplatform/DESIGN.md) replaces the Mac-relay proposal;
it does not silently broaden existing fixed-action grants or imply those features ship today.

First implementation: isolated `Packages/VaultCore`, AVSEAL01 signed immutable multi-recipient
records using exact Swift Crypto 5.0.3. Sixteen tests pass on native macOS and Linux arm64;
synthetic ciphertext opens across both directions. Compiled plaintext-log and signature-bypass
defects are detected, and original source stays unchanged. Grok 4.7 and Opus 5.5 independently
checked that initial source and evidence. Opus found a latent low-order-X25519 validation
gap, which must be corrected before enrollment supplies any real recipient key. The
correction now passes 21 tests on each platform, bidirectional exchange, 12 compiled
defense-removal controls across both platforms, nine verifier tests and a cleanup-error
regression control. CryptoKit rejected unchecked low-order HPKE natively; the pinned
Linux backend permitted it. The codec now rejects invalid recipient and encapsulated
keys before HPKE use. The [verification record](verification/portable-codec-v1.json) binds
the corrected source/evidence. Opus 5.5 and Grok 4.7 independently accept that bounded
fixture unit with no new blocker. This is not acceptance of a production password manager.

Next units: signed membership/checkpoints and local encrypted storage; native Linux authority
and UI; cloud auth/sync and pairing/recovery; private browser discovery/continuing operation;
headless Linux-to-Linux approval; secure import/migration and actual distribution; explicit
cross-user collections/sharing. Version 1 has no padding or key commitment and remains
fixture-only. A reviewed successor format is required before persistent real-password
storage or sharing; membership work can proceed with synthetic records. Current
app/broker/MCP/root package remain unchanged by the portable codec. No live cloud or Linux
password-manager app is claimed. Existing checkpoints below remain historical evidence.

U0 adds the Linux open-side validation removal control and executable fixture guard.
The membership unit still requires explicit admitted-recipient matching. Broader Ed25519
verification vectors and software-versus-hardware key custody must be resolved before
multiwriter authority and platform adapters. See the [review responses](design/multiplatform/REVIEW-RESPONSES.md).

The [portable membership design](design/multiplatform/MEMBERSHIP.md) is now accepted after
revision and a fresh Opus review. It separates controller signing from reader validation
and uses a signature-independent membership body digest. A native synthetic probe confirms
different valid CryptoKit signatures can cover the same message/key.

Implementation is split into portable membership U0 (guard, unchanged codec baselines and
raw open-side control), U1 (session-local lineage and stateless revision authorization),
then separately reviewed U2 (retained revisions and ancestry/conflicts). The corrected U0
snapshot passes unchanged 21-test codec suites on Mac and Linux, 50 guard tests and 22 runner
tests in each Python mode. Its raw open-side removal produces exactly 14 expected Linux
failures; native masking is recorded separately. Root Swift testing reports 352 tests with
24 existing gated tests skipped; MCP checks pass. Final current-source controls detect
eight guard mutants and five runner regressions in both Python modes: 26 detections and
26 passing targeted restores. Both full suites pass before and after, with no skips.
The owned copies and 164 source inputs remain unchanged.

Both first-round reviewers confirmed the initial runtime evidence. Real local SwiftPM
probes also reproduced Opus's cold-output, pin-enforcement and canonical-source-path findings.
The corrections isolate graph JSON, force pins, inspect dependency compiler inputs by file
identity, honor the cleanup scan flag and include runner tests in CI. Opus 5.5 and Grok 4.7
accept that corrected bounded unit. Opus also accepts the small follow-up that refuses a
missing fixture directory, resolves pins before CI guard queries and records scan policy
explicitly. The exact reviewed follow-up is applied and its current-source runtime checks
pass. No membership feature is claimed. See the [U0 record](verification/membership-u0.json).
Existing codec files, root app source and live credentials remain outside this change.
Real-password storage and sharing still require the successor format and durable
authority/storage gates.

## Current checkpoint: 17 October 2026

| Workstream | Implemented | Remaining verification |
|---|---|---|
| Broker/IPC | Separate daemon/bridge, protected config, code+UID pins, private Keychain, owner lease | Privileged dedicated-UID install, file/process isolation and system-domain lookup |
| Human app | Secure forms, pairing/grants, audit, exact pending approvals, protected-key backend | Provisioned Bite-signed protected key and real fresh user-presence signing |
| Lifecycle | Durable intent/recovery, bounded off-actor I/O, read capacity before approval/budget spend, administration reserve | Installed daemon interruption check |
| Browser | Broker lifecycle, authenticated headless host, fixed recipes, signed connection-bound relay and native raster window | Installed U6 distribution, installed P0–P3 sandbox/egress and P4 live service proof; production disabled |
| Protocol | Shared strict JSON guard, bounded framing, depth/duplicate checks, active-ID and notification limits; XPC limits | Follow-up review and host compatibility |
| Distribution | Dependency inventory, profiled Bite-signed review bundle and guarded Python installer | Privileged installer/runtime proof, notarization and CI for each published head |

Terminal credential enrollment is removed; the development CLI/MCP accepts only synthetic
`demo.status` operations. Real enrollment belongs to native secure forms. Both MCP smoke
modes and the 358-registered-test pre-U5 default suite passed with opt-out skips. The
[authentication protocol](AUTHENTICATION-PROTOCOL.md) states the credential and authority
boundaries without claiming production readiness or 1Password equivalence.

U5's real-host-to-app-model composition and legacy WebKit removal are integrated from
`4a0cf25`/`265debd`. Grok 4.7 accepted development integration at `82d181f` after the bounded
test/evidence corrections. Its follow-up Info about guarding the mutant test is now
covered by an escaped-test regression and a fresh parent rotation experiment. The canary unit and review corrections are integrated as `6966fae`/`f458398`;
the [parent combined verification](verification/credential-boundary-integration.json)
passes all ten checks at `35f33d4`: 347 default registered tests with opt-out skips,
12 real U5/canary tests and 35 real-host tests without skips, both MCP modes, package
boundaries, 11 recorder and 13 cleanup tests, and 33 offline preparation tests in each
Python mode. Source and the selected browser executable stayed unchanged. The subsequent
rotation-driver interruption-safety correction uses the canonical source guard; the
[final Python record](verification/credential-driver-final.json) passes all five selected
checks at `b984e50` with unchanged source. The later [fresh parent rotation proof](verification/secret-rotation-final.json)
at `e967fbe` confirms compiled mutant detection, exact restoration and restored baseline
after tightening the structural guard. This adds no Swift product behavior. The U5 browser mutation
record below passes all 20 deliberate defense removals on `6f4e506` after a passing
baseline and restored build, with unchanged source and selected browser executable. The old U2–U4 record below remains historical evidence.
Offline U6 preparation is integrated as `ac7b71b`/`c3e0f6f`: bounded archive snapshots,
pinned publication descriptors and conservative ancestry/ACL validation address two
Medium review findings. It emits only disabled, noninstallable payloads; it is not runtime
U6 completion. Operator-supplied metadata/report receipts remain unauthenticated evidence.
The matching Bite provisioning profile is now created and validated against the existing
Developer ID certificate, exact app ID and private Keychain access group. The
[profiled review build](verification/profiled-review-bundle-20261017.json) at `97142c6`
has valid strict signatures for all three roles and verified artifact hashes. Protected-key
creation still fails closed with macOS `-25308` (interaction not allowed), both directly and
through Launch Services. The native app is open; its Approval Key result awaits private
user interaction because desktop inspection timed out. AgentVault notarization credentials
and installed runtime proofs remain open. No deployment or real credential enrollment has occurred.

Round seven found no High/Medium issue at `f7ca91c`. The parent reproduced and corrected
its interrupted-wait/output-pipe cleanup findings and cancellation during initial result
collection. The first R7 recording at `0775185` passed seven checks; an independent
recheck found two more interruption gaps, corrected and accepted on bounded review at
`3132eb7`. The refined helper passes twelve checks. U2 `9014be7` and `bf5097a` are now
integrated as `ae16773`/`c10430c`: nonblocking serial writes, a shared auto-attach barrier
and concluded-run tombstones address its three findings on independent source review.
The [normal U2 record](verification/browser-u2-normal.json) proves eight checks at
`39fea8e`: 309 registered Swift tests with explicit storage/browser skips, a separate
27-test real-host run with no skips, both MCP modes, boundaries, twelve process-ownership
checks, eleven recorder checks and all 27 link mutations after a passing baseline. Source
and selected browser executable stayed unchanged. This predates later cleanup and U3/U4.

Fixtures now await independent cleanup through an owned browser-group handle. Review of
`fea724f` found watcher-failure and interrupted-wait gaps; `a7a2a4c` corrects both and
received bounded source acceptance. Watcher failure kills and waits; EINTR retries.
Unconfirmed wait errors disable signals without claiming a reap, potentially leaving a
zombie until host exit. Fault tests inject outcomes around real owned children.

U3/U4 are integrated with signed-open liveness, acknowledged input drain before Finish,
and polling stopped during Finish. The parent reproduced and fixed an additional closed
connection Finish/Cancel admission gap in `9a37625`. Eight focused tests pass, including
the original race regressions and reaper error paths. The native continuation re-review
ended with a provider policy error and supplied no final acceptance. Claude follow-ups
hit an API rate limit; the parent made the last fixes. Production stays disabled.

The [combined U2–U4 record](verification/browser-u2-u4-integration.json) passes all nine
checks at `9390b46`: 358 registered Swift tests with explicit opt-out skip reports, the
separate 31-test real-host run with no skips, both MCP modes, boundaries, thirteen process
ownership/harness checks, eleven recorder checks, all 18 browser mutations and all 32
continuation mutations. Both mutation sets pass their baseline and restored-source build;
compile failures do not count as detection. Source and selected browser executable stayed
unchanged. Raw outputs are private and indexed by hash. These synthetic, same-UID checks
do not establish U5's real host-to-app integration or any installed runtime gate.

The prior source `73cb4d5` passed all nine selected checks in the
[U1 integration record](verification/browser-u1-integration.json): 281 registered Swift
tests in sixteen suites, including two explicit native-storage skips; default and synthetic
native MCP; boundaries; five owned-process checks; ten recorder checks; twenty same-UID
cross-process XPC scenarios; eight XPC guard variants, including two expected redundant
layers; and a passing baseline followed by
all twenty-four web-link mutations being detected. Source remained unchanged. Full mutation
detail logs are retained privately at unique paths with hashes. This proves local synthetic
behavior; the actual headless host, human relay and installed isolation remain open.

The prior source `3c61fbb` passed the five selected checks in the
[R6 response record](verification/recovery-episode-r6.json): 225 registered Swift tests
with two explicit skips, MCP, synthetic native MCP, boundaries and nine recorder tests.
The machine-readable record now includes skip counts and reasons. Both Low findings in
Claude Sonnet's review of `0d944eb` are corrected: recovery-start episodes reset after
ordinary account cleanup, and CLI account-list replies use the shared contract.

The prior source `676d687` passed all eight selected checks in the
[latest record](verification/recovery-audit-ci-r5-retry.json): the Swift runner reports
224 tests in eleven suites with two explicit native-test skips; the separate native
opt-in ran both bodies successfully. MCP, boundaries, 49 installer tests per Python mode
and 15 guard mutations, five release, nine cleanup and eight recorder checks passed.
Source remained unchanged. The earlier interrupted record is preserved. These use local
incremental build caches and synthetic data, and do not establish installed isolation.

Verified baseline `198786e` reported 222 tests in ten suites, plus MCP, boundaries,
48 installer tests in each Python mode with 14 guard mutations, five release tests,
nine cleanup tests, eight recorder tests, two separate native Keychain checks, 20
same-UID XPC scenarios and eight XPC variants, including two expected redundant layers. The
[baseline record](verification/browser-u0-r4-integration.json) includes full source hashes,
cache-reuse limits and durable local raw-log paths/hashes. Logs are ignored and private.

U0 and the round-four recovery/release fixes are integrated. Three independently
reproduced browser Medium defects were corrected and independently retested. Human opens
now bind a preexisting step token. U1 is integrated through `bc67b46` after independent
verification of the original findings and the final task-registration handshake. Host
losses name only affected runs. Core owns start/classify deadlines; a start's deadline is
capped by grant expiry, and credential dispatch rechecks authority after the host probe.
Initial read cancellation tears down its run; admin handlers retain completion semantics.
Claude Sonnet round seven found no High/Medium issue in the combined R6/U1 checkpoint
at `f7ca91c`. That review predates the integrated U2–U4 changes. Production browser
services remain disabled.

The two CI runs at `5b1fb9a` failed synthetic I/O setup and a yield-based browser-start
ordering assertion. The blocked-worker cases are now serialized, unrelated account setup
is synchronous, and the startup test uses an explicit debug-only gate. Full local
verification passes. Both macOS CI jobs passed on `f09f8d8`, including the R6/U1 changes;
their raw logs are retained locally by hash. Production timeout stays five seconds.
A new signed review bundle from clean `5955f50` passed all three hardened
Bite signatures, exact review entitlements, manifest hashes and the signed installer sandbox.
[Its record](verification/signed-review-bundle-r4.json) does not prove later changes,
installed ownership, provisioning, protected-key signing or notarization.

### Earlier verification snapshots

The following notes describe earlier source checkpoints; their records are preserved.

CI on `0553119` failed three watchdog-order checks. The test now arms its cancellable
fallback after the worker starts and proves revocation/snapshots finish while the worker
remains blocked. Focused checks and a full 222-test run passed at `d6461db`;
[the follow-up record](verification/ci-watchdog-r4.json) also verified the recorder's
private log permissions. That correction did not address the later `5b1fb9a` fixture races.

The round-three integrated checkpoint `83971b7` passed 190 tests, including real
WebKit fixtures, native-app flows, bounded stdio, runtime file/lease checks and a real SDK
client exercising all four bridge tools. Native Keychain checks are explicit opt-ins;
their two successful native checks are separate from this default suite. New CI results
are pending; the initial CI runs failed four short test-setup deadlines, whose fixtures
have now been corrected without changing the production five-second limit.

The installer passed 42 tests both normally and with Python optimizations, 12 guard mutations,
and install/verify/retry/uninstall against the signed `fe7f1dc` payload in its non-root
sandbox. Account creation and launchd are simulated there. Three real ad hoc signature
tests exercise entitled and unentitled release checks. The current
[release-check record](verification/release-entitlements-r3.json) hashes all tracked files.
Historical checkpoint records remain in `docs/verification`; each names its own source.

The repeated cross-process check passed 20 scenarios; one of eight guard mutations initially
failed cleanup despite the expected refusal changes. Its failed record is retained. After
adding confirmed-unload waiting and cleanup diagnostics, all 20 scenarios and eight guard
mutations passed, with fixture jobs and directories removed. Two cleanup behavior checks,
the MCP checks, module boundaries, installer checks and release entitlement checks also
passed against unchanged source. [The integration record](verification/integration-r3.json)
contains the commands, results, log hashes and complete tracked-file hashes. These are
same-UID process checks; installed private-UID isolation remains unproven. A fresh Claude
Sonnet follow-up review of the fixes is running.

A fresh Bite Developer ID review bundle was built from clean `1e4a2ea`. All three
hardened signatures and manifest hashes verified, and the installer sandbox passed
against those exact binaries. [The signed-bundle record](verification/signed-review-bundle-r3.json)
is separate from the historical `425c6af` record. This build has no provisioning profile
and is not notarized; no protected-key probe was repeated on it.

The browser lifecycle unit is now integrated with the R3 capacity controls: 218 tests,
MCP verification and module boundaries pass locally. The independent U0 judge reproduced
three Medium issues in the original worker commit; parent fixes enforce the pause deadline
on late replies, end sessions at rotation intent and own cancellable timers per retained
run. Human opens now name a preexisting step ID, preventing a delayed signed open from
authorizing a different challenge. Browser production services remain disabled. The actual
headless host and its installed isolation/network proof are later units.

No existing application, browser profile, host MCP configuration, company evidence or real
service credential has been modified. No dedicated user, daemon or app has been installed.
The complete plan is **not finished** while the runtime and distribution gates below remain open.

## Milestone 1: development core

Implemented in the initial repository:

- [x] Swift domain types and fixed action dispatch.
- [x] Native Keychain storage without plaintext fallback.
- [x] Private TTY enrollment and synthetic demo bootstrap.
- [x] Exact account/action grants, expiry, revocation and persistent attempt budgets.
- [x] Safe metadata files and bounded secret-free audit history.
- [x] Stdio MCP transport using the official Swift SDK.
- [x] Fixed GitHub profile adapter and typed output.
- [x] Local plugin manifests and build/run instructions.
- [x] Functional checks and a three-model code review with documented fixes.

## Milestone 2: authenticated, isolated broker

- Prove a signed native broker and bridge IPC with independently protected enrollment.
- Prototype separate-user Keychain/process ownership and human UI integration on macOS.
- Enforce grant administration outside the agent's permissions.
- Fail closed on unknown peers, signing identities, enrollment and expired sessions.
- Add code-signing/notarization and reproducible release verification.
- Demonstrate that a shell-capable agent cannot read broker files, inspect its process
  memory or invoke privileged policy operations.

Exit gate: measured OS isolation and negative impersonation tests. No production
security claim before this gate.

## Milestone 3: human app and lifecycle

- Private account enrollment, deletion and rotation UI.
- Client pairing and grant editor showing precise permissions and expiry.
- Frozen per-request approval with user-presence verification.
- Safe cancellation, uncertain outcomes and reconciliation for future mutations.
- Audit export, retention and tamper-evidence decisions.

Exit gate: approval cannot be replayed, altered or bypassed by the MCP client.

## Milestone 4: controlled browser

- One synthetic test website and one reviewed read-only real service workflow.
- Broker-owned profile and cookies with no agent CDP access.
- Exact-origin checks, typed extracted data, bounded artifacts and session teardown.
- Protected human continuation for MFA/CAPTCHA.
- Hostile-page, redirect, reflection and session-extraction tests.

Exit gate: an agent can complete the approved workflow but cannot export credentials
or session state, navigate to arbitrary destinations or perform unapproved actions.

## Milestone 5: security review and distribution

- Independent adversarial review and dependency inventory/SBOM.
- Fuzz protocol and adapter parsing; bound concurrency, input size and audit growth.
- CI builds, package validation, signed artifacts and release provenance.
- Compatibility checks in target MCP hosts, without broad permission bypasses.
- Publish documented security guarantees only after their verification.

## Verification record

Verified locally on 13 October 2026 with Apple Swift 6.2.4 and macOS:

- 26 tests passed with native Keychain and live-network opt-in checks enabled.
  The live check sends an invalid synthetic token to the fixed GitHub endpoint;
  no real GitHub credential was used by the adapter.
- Stdio MCP initialization, discovery, approved native-Keychain demo invocation,
  revocation, unknown tools, additional inputs and non-TTY enrollment checks passed.
- Separate CLI processes preserved concurrent metadata updates.
- Private PTY enrollment accepted a synthetic token longer than 128 bytes without
  echo and rejected oversized input.
- Three independent model reviewers found five defects that were corrected and
  one crash-recovery gap retained as explicit lifecycle work. See
  [the review record](SECURITY-REVIEW.md).

The synthetic smoke test deletes its unique temporary Keychain namespace. These
checks do not establish production OS isolation or an independent security audit.
CI is configured for the same offline unit/MCP checks plus a release build;
its result is separate from this local verification record.

CI selects Xcode 26.2 explicitly. The pinned dependency graph requires Swift 6.2;
the default macOS 15 runner's older Xcode does not satisfy that requirement.
