# Implementation plan

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
