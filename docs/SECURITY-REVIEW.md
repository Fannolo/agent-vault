# Implementation security reviews

## Browser lifecycle and round-four follow-up: 15 October 2026

Integration `198786e` passed 222 Swift tests and all ten recorded checks. The
[record](verification/browser-u0-r4-integration.json) retains source hashes and local log
paths/hashes. Raw logs stay in ignored `verification-logs/` with owner-only access; earlier
temporary logs, including the failed cleanup run, have also been retained there.

Claude Sonnet 5.5 round four confirmed the R3 fixes at `83971b7`, finding no High or
Medium defect in that scope. Its Low findings and evidence gaps were addressed as follows:

| Finding | Response | Limit |
|---|---|---|
| R4-1: reads can starve recovery | `520a4dc` closes admission before a bounded async drain; cancellation and failure release the gate | Stuck native workers still need completion or restart |
| R4-2: deprecated extraction and malformed XML | `9a0cabb` shares a supported XML reader between builder/installer, cross-checks XML/plain emptiness and refuses malformed/binary/non-dictionary results | The cross-check compares emptiness, not two parsed dictionaries |
| R4-6/R4-8: volatile logs and incomplete failure/cache evidence | `7f73b0a` retains local logs/JSON by path/hash, records failed starts and JSON errors, and states cache reuse | Records are local observations, not external attestations or clean-build claims |
| R4-7: missing cleanup detail and unchecked harness exit | `198786e` records probe/bootout status, unload latency and removal errors; mutation gates also check the expected exit | The earlier failure's cause remains unknown; not-found status 113 is observed platform behavior |

The round-four reviewer reported 30 temporary GUI-domain jobs despite the brief excluding
live jobs, and reported removing them. That experiment was outside the agreed review
method and is not installed-isolation proof. The next review explicitly forbids repeating it.

Claude Opus 5.5 implemented U0 at `8db3925`, integrated at `8c69601`. An independent
GPT-6.1-Sol judge reproduced three Medium defects before acceptance: late classification
bypassing the human-pause deadline, uncertain rotation retaining an unauthorized context,
and untracked timers accumulating after collection. Parent fixes check the original pause
deadline before applying a host reply, tear down at rotation intent before the save, and
own/cancel/reuse one timer per retained run. The judge independently verified four focused
corrections, including stale signed opens across challenges of the same kind. A preexisting
`HumanStepID` now binds every open to its run and step epoch. The accepted judge snapshot
preceded R4 recovery; the full 222-test integration covers that merge.

CI at `0553119` still failed three fixture-watchdog ordering checks: the one-second release
could fire before the assertion on a loaded runner. The fixtures now arm a cancellable
watchdog after the worker starts and prove revocation/snapshots finish while it remains
blocked. Focused checks pass; new CI is pending. Production timeout remains five seconds.

Round five (`agent-vault-integrated-browser-r4-review-v5-20261015`) reviewed frozen
`198786e`, reporting no High/Medium issue. It reproduced Low recovery-audit churn and
confirmed the known missing Core dispatch deadline. It also flagged silent native-test
skips, duplicate plist keys, status vocabulary drift and harness evidence limits. Corrections
are in progress. It independently matched all tracked-file, log and auxiliary-evidence
hashes in the integration record. It used direct `swiftc` probes rather than a full SwiftPM
test run; WebKit, App UI, XPC server internals, the JSON guard, the broader installer and
the signed bundle were outside this round. Its documentation-lag flag refers to the frozen
source, before the later committed checkpoint records and current top sections.

Parent corrections for R5-5/R5-6 reject duplicate keys at every XML dictionary depth,
including entity-equivalent keys, and derive CLI run replies and bridge-local failures
from the shared contract. The installer adds a mutation for the duplicate-key guard.
R5-8 mutation copies now exclude private verification logs. Cleanup still confirms
launchd unregistration, not process exit; a killed harness may leave registrations behind.
Global SwiftPM cache provenance remains unmeasured. These are verification limits,
not evidence of installed isolation.

R5-7's Unicode grammar observations do not change the credential bytes: the documented
username bound counts Swift characters, and both fields reject Unicode control scalars.
U+2028 is a separator and remains accepted within the byte limit. R5-9's last-opener-wins
behavior is intentional: a fresh signed open for the same step replaces its old lease,
so only the current connection can conclude it.

Clean `5955f50` was rebuilt and verified with Bite Developer ID. The
[artifact record](verification/signed-review-bundle-r4.json) includes all three hardened
signatures, exact review entitlements, file hashes and a signed installer sandbox pass.
It has no provisioning profile, notarization or new protected-key probe.

U1 must qualify host-loss events by connection/affected
runs and fit host deadlines within the read transport budget. Actual host, human frame/input
relay, independent OS egress, private-UID/daemon proof, protected-key signing, notarization
and target-host compatibility remain open. Production browser services stay disabled.
These are bounded model reviews, not security certification.

## Round three: 15 October 2026

Claude Sonnet 5.5 reviewed `d39b1c2` (documentation at `fe7f1dc`) in an independent,
synthetic scratch export. It reran 181 Swift tests and 40 installer tests in both Python
modes, and wrote its own admission, audit, parser and real-code-signature probes.
The five detailed findings comprise three Medium and two Low issues; its opening count
said two Medium and three Low. No High issue was reported in that bounded review.

| ID | Finding | Response |
|---|---|---|
| R3-1, Medium | Busy secret-read admission consumes budget and approval before any execution | Read reservation precedes approval/budget mutation; failed persistence releases unused reservations |
| R3-2, Medium | Successful calls can evict other clients' invocation history | Fair eviction within 744 entries; latest five protected per registered client under stable membership |
| R3-3, Medium | Release builder parses a text entitlement dump as a plist | Explicit XML output; real entitled and unentitled signatures tested |
| R3-4, Low | Installer denylist omits the debugger entitlement | Exact per-role entitlement policy, including refusal of unknown and temporary capabilities |
| R3-5, Low | Agent secret reads can occupy all administration I/O slots | Reads use at most three of four actual slots; timed-out workers retain capacity |

Release/installer response evidence: `deploy/tests/test_release.py` (three real ad hoc
signature tests); 42 installer tests in normal and optimized Python modes; 12 guard
mutations; signed sandbox install/verify/retry/uninstall using the `fe7f1dc` review
payload. Accounts and launchd are simulated in that sandbox. These checks do not prove
that a provisioned app can create its protected key.

The core response (`060e9ce`, originally worker commit `d7c4341`) passed 190 tests, MCP
verification and boundary verification in the isolated worker worktree. Tests cover retry
with the same human approval after busy admission, failed state persistence without a
reservation leak, four actual workers, administration under stalled reads, successful-call
floods and 128-client retention. The initial GitHub runs failed four short-deadline fixtures
during setup. Fixtures now seed their synchronous fake before constructing the broker,
wait for actual worker starts and use two-second stall deadlines; production stays at five
seconds. The fresh root integration run at `83971b7` also passed 190 tests; new CI is pending.

The new clean-source recorder hashes all tracked files, including deploy, scripts, package
metadata and docs. [Release-check evidence](verification/release-entitlements-r3.json)
names its source commit. The first repeated cross-process run passed 20 scenarios, while
one of eight defense mutations failed its cleanup predicate despite the expected scenario
failures. [That failed run is retained](verification/xpc-json-guard-r3.json). No fixture jobs
remained loaded on inspection. Cleanup now waits a bounded time for unload, preserves files
if a job remains and records each mutation's cleanup details. The rerun passed all 20
scenarios and eight mutations with confirmed cleanup. The
[integration record](verification/integration-r3.json) includes those details and all nine
successful check exits (including two separate native Keychain opt-ins). A new Claude
Sonnet review, `agent-vault-security-followup-review-v4-20261015`, is running against the
fixes and evidence trail; it has not yet returned a verdict.

After that review started, clean `1e4a2ea` was rebuilt with Bite Developer ID. The
[new signed-bundle record](verification/signed-review-bundle-r3.json) verifies all three
signatures, exact empty review entitlements, manifest file hashes and installer sandbox
against the new binaries. It records no fresh protected-key probe, provisioning or
notarization; the older `425c6af` probe remains historical evidence only.

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
