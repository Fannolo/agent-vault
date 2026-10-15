# Implementation security reviews

## Current follow-up: 15 October 2026

Claude Sonnet 5.5 reviewed `d39b1c2` (documentation at `fe7f1dc`) in an independent,
synthetic scratch export. It reran 181 Swift tests and 40 installer tests in both Python
modes, and wrote its own admission, audit, parser and real-code-signature probes.
The five detailed findings comprise three Medium and two Low issues; its opening count
said two Medium and three Low. No High issue was reported in that bounded review.

| ID | Finding | Response |
|---|---|---|
| R3-1, Medium | Busy secret-read admission consumes budget and approval before any execution | Core fix in progress: reserve capacity before state mutation |
| R3-2, Medium | Successful calls can evict other clients' invocation history | Core fix in progress: fair client retention within the global bound |
| R3-3, Medium | Release builder parses a text entitlement dump as a plist | Explicit XML output; real entitled and unentitled signatures tested |
| R3-4, Low | Installer denylist omits the debugger entitlement | Exact per-role entitlement policy, including refusal of unknown and temporary capabilities |
| R3-5, Low | Agent secret reads can occupy all administration I/O slots | Core fix in progress: reserve administration capacity |

Release/installer response evidence: `deploy/tests/test_release.py` (three real ad hoc
signature tests); 42 installer tests in normal and optimized Python modes; 12 guard
mutations; signed sandbox install/verify/retry/uninstall using the `fe7f1dc` review
payload. Accounts and launchd are simulated in that sandbox. These checks do not prove
that a provisioned app can create its protected key.

Round 2 had identified synchronous Keychain calls blocking the broker actor and denial
floods evicting invocation history. `d39b1c2` moved actual I/O to four bounded workers
with deadlines and retained late-worker bookkeeping, compensated ordinary lifecycle
failures, and coalesced representative denial/approval events. Round 3 confirmed the
responsiveness and lifecycle fixes, but reproduced the remaining successful-call
audit flood and admission defects above. It found no defect in the shared strict JSON
guard after 34 additional parser probes and four timing runs.

The review also flagged evidence limits: the follow-up record hashes Sources and Tests,
but not deployment/build files; historical batch timestamps do not establish command
order; the signed-bundle record still describes the older `425c6af` artifact. Later
records must name their source commit and actual artifact separately. Uncertain
Keychain journals need recovery after workers finish; permanently hung workers need a
broker restart. Provisioning, protected-key signing, installed private-UID isolation,
browser implementation/egress proof, notarization and host compatibility remain open.

The T3 review task is `agent-vault-security-followup-review-v3-20261015`; scratch probes
are under `/tmp/avr3/`. This is model review, not security certification.

## Initial implementation review

Reviewed 13 October 2026 by three independent model reviewers, followed by lead
verification of their call chains. This is a development review, not an external
security audit or production certification.

## Intent

Publish a working development core with native Keychain storage, persistent
account/action grants, expiry, revocation and budgets; a narrow stdio MCP surface;
and a fixed read-only GitHub adapter. The signed broker, independently authenticated
clients, human UI and browser isolation remain planned.

## Reviewers

- Reviewer A: GPT-6-Sol, two storage findings.
- Reviewer B: GPT-6-Luna, one enrollment-lifecycle finding.
- Reviewer C: GPT-6-Astra, three expiry/session/terminal findings.

## Act on

- Expiry sampled before lock acquisition could authorize after a blocking wait.
  Time is now sampled inside mutating transactions and after a read snapshot.
  Regression tests simulate delay before authorization and before completion.
- Delegated GitHub URL sessions were not invalidated. Each operation now cancels
  and invalidates its owned session on every exit path.
- `getpass` silently truncated long terminal input. Enrollment now uses
  `readpassphrase` with hidden TTY input, a 256-byte limit and an overflow sentinel.
  Native PTY verification covers a synthetic token longer than 128 bytes and an
  oversized rejected token.
- Account listing rewrote and fsynced metadata. It now uses a locked read snapshot;
  tests verify that metadata's inode and modification time do not change.
- Unbounded metadata growth could block revocation at the file-size ceiling.
  Record-count limits reserve storage headroom; a full-capacity test proves that
  new grants are refused while client revocation still commits.

Lead verification also added a pre-dispatch check after potentially blocking
Keychain access. Revocation cannot recall an already dispatched provider request.

## Consider

Interrupted enrollment can leave an untracked Keychain item because metadata and
Keychain are separate stores. Error cleanup handles ordinary failure, but a crash
can interrupt it. Crash-safe enrollment/recovery, deletion and rotation are tracked
in the lifecycle milestone. This remains a reason to use only disposable credentials
in this prototype; it is explicitly documented rather than marked fixed.

## Noted

General protocol resource limits, independent audit evidence, authenticated client
identity and OS process isolation are absent planned controls. They are not claimed
by the README or threat model. Native Keychain tests use unique temporary namespaces.

## Dismissed

No concrete MCP route was found to arbitrary destinations, raw credential retrieval
or grant mutation within the implemented surface. This does not establish security
against same-user arbitrary code, which is expressly outside the prototype boundary.

## Agreement map

The reviewers identified different concrete defects and none contradicted another
finding. Each fix was judged against the development milestone; missing production
architecture was retained as open work. Targeted tests establish the behaviors they
exercise, not a blanket absence of credential exposure.

## Integrated review round 1 (13 October 2026)

Claude Sonnet 5.5 independently reviewed source checkpoint `26b41aa` (source identical
at `bcfbc10`) in a synthetic scratch copy. It reported no critical/high defect in its
reviewed scope and three medium findings, plus approval/Keychain design weaknesses and
low issues. This is model review, not independent security certification. The task was
`agent-vault-claude-integrated-review-v1-20261013` in the T3 parent thread.

| Finding | Response at `425c6af` | Evidence |
|---|---|---|
| Read traffic could starve human admin calls and probes | Independent admin handler gate; probe parsed before handler admission | `LoopbackXPCTests` saturation cases |
| Read denials could evict all audit history | Required schema-3 administration ring (256), separate invocation ring (744); unknown account denials omitted | `AdministrationAuditTests` retention cases |
| Enroll/rotate/delete/pair/approve/reject/recover/prune unlogged | Lifecycle stages recorded with state changes | `AdministrationAuditTests` coverage |
| Nonce-only signatures and abbreviated prompts | Digest binds ID, nonce, expiry and operation metadata; app recomputes it; full scope prompts | `ApprovalIntentTests`, `AdminFlowTests` |
| Private Keychain not unlocked after sleep | Explicit unlock before every access; own lock policy unchanged | Native explicit-lock/load test |
| Ordinary failed rotation left account rotating | Compensating transaction; failed compensation keeps journal | Lifecycle failure/crash-image tests |
| Seven-day UI grant exceeds broker maximum | Removed seven-day option | Grant prompt/duration test |
| Suppressed output audited twice | Finish state recorded once | Lifecycle once-only audit test |
| Waiting resume denied; short approval lifetime | Waiting returns same approval request; 120 seconds retained as explicit policy | Waiting-resume/expiry test |
| Claims exceeded runtime proof | Docs distinguish implemented design and measured checks; stale shell-template guidance replaced | README, IPC, native app, plan |

Credential content and credential-content hashes are deliberately excluded from the approval
digest. The frozen actual credential remains private to the broker. The public key is not
hardware attestation; the app explicitly labels its protected Keychain fallback. A compromised
trusted app can choose misleading UI, which a metadata digest alone cannot prevent.

The reviewer also flagged retroactive batch timestamps and weak evidence pointers in the
append-only trail. New rows supersede the weak pointers and record the shared UID principal,
protected fallback, 120-second policy, and changed admission design. Durable sanitized
checkpoint and signed-bundle records now retain commands, observed summaries, log hashes,
code signatures, artifact manifest and actual protected-key probe output. These are local
verification records rather than externally attested results.

Claude implementations integrated into this branch: IPC `9db3330`/`b359db8`, native UI/browser
`3915960`/`a368d41`/`a3503ec`, installer `5fa3cb6`. They ran in separate worktrees. Root
integration and verification used synthetic entries and temporary jobs only. No host plugin,
dedicated account or privileged service was installed.

Open gates: dedicated-UID system bootstrap and file/process isolation; real provisioned
protected key/user presence; isolated GUI browser deployment and live selectors/MFA;
notarization and target-host compatibility.
