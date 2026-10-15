# Implementation plan

## Current checkpoint: 15 October 2026

| Workstream | Implemented | Remaining verification |
|---|---|---|
| Broker/IPC | Separate daemon/bridge, protected config, code+UID pins, private Keychain, owner lease | Privileged dedicated-UID install, file/process isolation and system-domain lookup |
| Human app | Secure forms, pairing/grants, audit, exact pending approvals, protected-key backend | Provisioned Bite-signed protected key and real fresh user-presence signing |
| Lifecycle | Durable intent/recovery, bounded off-actor I/O, read capacity before approval/budget spend, administration reserve | Installed daemon interruption check |
| Browser | Ephemeral fixed-flow fixtures; broker-owned run lifecycle, closed read statuses and one credential grammar against a scripted host | U1–U6 host link, separate `_agentvaultweb` host, human continuation, installed P0–P3 sandbox/egress and P4 live service proof; production disabled |
| Protocol | Shared strict JSON guard, bounded framing, depth/duplicate checks, active-ID and notification limits; XPC limits | Follow-up review and host compatibility |
| Distribution | Dependency inventory, signed review-bundle builder and guarded Python installer | Privileged installer/runtime proof, provisioning, notarization and CI |

Current source `3c61fbb` passed the five selected checks in the
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
same-UID XPC scenarios and eight XPC mutations. The
[baseline record](verification/browser-u0-r4-integration.json) includes full source hashes,
cache-reuse limits and durable local raw-log paths/hashes. Logs are ignored and private.

U0 and the round-four recovery/release fixes are integrated. Three independently
reproduced browser Medium defects were corrected and independently retested. Human opens
now bind a preexisting step token. U1/U2 and U3/U4 implementation runs separately. Claude Sonnet
round five found no High/Medium issue at `198786e`. Recovery audit retry churn is fixed
at `a494bc7`; the missing Core dispatch deadline is in the separate, unaccepted U1 unit.
Production browser services remain disabled. U1 is not integrated: its submitted fixes
at `0986606` are undergoing independent re-verification before acceptance.

The two CI runs at `5b1fb9a` failed synthetic I/O setup and a yield-based browser-start
ordering assertion. The blocked-worker cases are now serialized, unrelated account setup
is synchronous, and the startup test uses an explicit debug-only gate. Full local
verification passes. Both macOS CI jobs passed on `0d944eb`; the later R6 changes need
their own CI. Production timeout stays five seconds.
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
