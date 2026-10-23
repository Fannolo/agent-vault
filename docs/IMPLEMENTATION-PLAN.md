# Implementation plan

## Headless delivery work: 23 October 2026

The standalone `Packages/VaultPersistence` kernel now implements SQLite commit/recovery
with an external custody-pin port. Native proof for package commit `7e0d18e` reports
32 tests, five process-kill crash cuts, six abort/retry replay cases, a four-process
lease race, COMMIT-time EFBIG refusal and 15 restored omission controls. A protected
pin must identify the complete logical image, including object inventory: frame hash
alone, then frame hash plus generation, both admitted demonstrated rollback scenarios.
The current image hash and test-only AVTPIN03 address that premise. Independent
package and root-source reviews accept the bounded unit; platform CI remains pending. Observed SQLite read corruption blocks the owner. Descriptor ACL checks
reject private ACLs and unsafe ancestor grants. System SQLite is measured as 3.43.2
on native macOS, distinct from SDK headers 3.51.0; no exact-source SQLite pin is claimed.

This package is quarantined from root products alongside VaultCore. Separate macOS
and Linux CI jobs run its crash/control verifier and retain synthetic evidence. Linux
uses a derivative of the pinned Swift image with system SQLite headers; the verifier
records actual runtime settings and versions. Those new CI jobs have not yet run.
The test-only file pin does not implement protected, nonrollback installed custody.
Process kill is not power loss. Actual ENOSPC, SQLite disk-fsync failure, installed
UID/custody, history authority, collection capacity/retention, broker/effect-journal
integration and production acceptance remain open.


The trusted `AgentVaultCloud` client now implements the fixed ciphertext transport routes,
bounded streaming replies, digest/cursor validation and explicit unconfirmed-write results.
After independent review, the access token's reveal moved to its own `CloudTokenUse` SPI.
Only the fixed adapter may import that SPI; the browser roles' `CredentialUse` import cannot
reveal the token (compiler probe). The cloud target graph is now an allowlist: only the
broker daemon may reach the transport, and the CLI's MCP process, Core and new targets are
refused. Vault creation confirms ownership of an existing id instead of reporting another
account's id as created. The endpoint origin is canonical. Fifteen native client tests,
the native root suite (opt-ins skipped), guard tests, 13 compiler probes, MCP checks and 21 marker-checked mutants
pass in `scripts/verify-cloud-client.py`. The head-conflict client expects HTTP 409 from a
`PT409` server raise; the merged migration and native SQL assertion now use that code. Linux runtime and live
PostgREST remain unmeasured. This module is not composed into production. Signup, token
refresh/custody, pairing and durable verified sync remain unfinished; see
[CLOUD-TRANSPORT.md](CLOUD-TRANSPORT.md).

The first opaque cloud transport migration is implemented under `supabase/`. Native
PostgreSQL 17.11 checks pass in an invocation-owned private cluster with TCP disabled:
owner/cross-user/anonymous rules, immutable objects, size and quota limits, exact retry,
conditional-head races and commit-ordered cursors. Removing the vault owner-read predicate
makes the real SQL assertion fail; restoring it passes. This is database behavior only.
The SQL auth functions are synthetic test stubs, not a test of hosted JWT validation or
PostgREST. No hosted project, signup, pairing mailbox, token custody or client sync engine
exists yet. The bounded database source review is accepted; native PostgreSQL 16.15 Linux
CI and 17.11 macOS checks passed for that component. These are not hosted auth tests. See
[`supabase/README.md`](../supabase/README.md) for the transport contract and deployment gates.

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
[IPC](IPC.md#unix-socket-transport). A source review of `4d84080` found five defects, each
reproduced by a regression that failed on that code before its fix: an unbounded reply queue,
stop and deadline checks that a busy peer could skip, concurrent starts that could unlink
each other's sockets, admin slots released before broker cleanup, and a test peer that could
close a reused descriptor. A follow-up found that a request ID left flight when its handler
returned, so a duplicate could run again while the reply was unwritten; that is fixed the same
way. Commit `be621d9`, on macOS 15 with Swift 6.2.4, through
`scripts/verify-socket-transport.py --full --stress 5 --mutations`: 32 socket tests pass,
the same suite passes 5 more times in the same run, the root suite reports 394 passing tests
with existing opt-ins skipped, and `verify-mcp.py` and `verify-boundaries.py` pass. All 19
transport mutations fail every named test, and after each one the restored file rebuilds and
the same tests pass. The synthetic canary scan of 86 logs is clean, and `MANIFEST.txt` records
each log's SHA-256 with the source hashes. Tests run every role under one UID; denied UIDs are
simulated by configuration. Linux CI run 39884964104 of `4d84080` showed that Linux resets a
refused peer that had already written; the test now accepts that and still requires that no
reply is sent. The integrated source at `f3d3b4f` received bounded source acceptance. Its
macOS and cloud-database CI jobs passed; Linux compiled the broker and MCP bridge but failed
one of 192 tests: `unwrittenRepliesKeepTheirServiceCapacity` failed its recovery assertion after 48 rapid attempts. Suspected cause: retries outran
asynchronous writer cleanup. A private macOS experiment with a one-second writer-cleanup
delay reproduces this failure mode. A bounded recovery wait passes with the delay
and still fails when reply completion never releases capacity. Production socket code is
unchanged by this test correction. Corrected head `5dbc4dd` passed all three CI jobs in
run [39892014230](https://github.com/Fannolo/agent-vault/actions/runs/39892014230): Linux
reported 55 codec tests, 7 secret-buffer tests and 192 root tests passing. PR #14 merged
as `cfcd221`. This proves portability and synthetic socket behavior, not installed custody.

The Linux MCP bridge now builds with portable bounded stdio and the kernel-authenticated
read socket client. It retains the same four tools and fixed installed configuration. The
broker exits `custody_unavailable` until vault key custody exists. Dedicated accounts,
systemd units and an installed host remain unproven.

Password-ready storage design now selects one SQLite authority, signature-excluding body
identities, an independently retained pending/stable pin and one journaled credential-use
path. Both design candidates chose SQLite over immutable files with a manifest. The first
executable unit is an isolated committed, canonically padded record codec; it remains blocked
from every root product. The complete AWS 0x0478 inner profile and custom outer signature/HPKE
binding passed focused design analysis, with explicit dependence on independently trusted
writer authority. The closed GitHub token tag and common pinned Ed25519 verifier profile
now have design acceptance. Actual effective signature outcomes on both platforms must
still be measured before format freeze. The isolated implementation now has native evidence: 58 declarations pass with all
three exchange/reference tests enabled; nine cases read the retained native fixture, and
20 newly generated cases pass AWS reference decryption. Source review required rejecting
WHATWG numeric-ending hosts in the DNS-only origin profile. Before the fix, six constructor
cases and six authenticated payloads were accepted (18 recorded issues); after the fix,
constructor refusal and zero-callback payload refusal pass. Callback documentation now
states that trusted callers may retain content. The 19 X25519 field-alias cases cover
unaffected readers, not the selected holder; selected low-order coverage remains separate.
The original 14 native removal controls are retained pre-fix evidence. Current-source
review and native/Linux exchange were accepted for the isolated codec merged in PR #15;
that acceptance did not freeze the format. Two additional complete-record fixtures now
exercise a mixed-order author and mixed-order signature nonces. Independent affine and
RFC 8032 arithmetic establish an accepted exact reduced-challenge equation and a rejected
cofactored-only equation over the same authenticated body. Native worker evidence records
60 tests with all exchange/reference cases enabled, exact payload callbacks for three
holders in the accepted case, and `badSignature` with zero callbacks in the rejected case.
Independent Linux execution of these new fixtures remains pending. This pair covers one
author, two nonces and one login body; no general subgroup or enrollment claim follows.
No format freeze or product approval is claimed. The collection
protocol still must resolve at least 4,096-item capacity and append-only lifetime quotas;
the draft 512-item snapshot limit is not accepted as the final product limit. Neither a
database MAC nor paths for custody establish protection against whole-machine rollback.

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

A continuing-site host slice adds a separate entry beside fixed workflows: `openSite`,
`siteObserve`, `siteLogin`, `siteOperate`, `siteTakeover` and `siteRelease` on the existing
authenticated host wire. A closed `HostSite` names a compiled `SitePolicy`; a `HostWorkflow`
grant cannot name one. Navigation, credential, authentication and passive-resource origins
are separate; there is no cross-origin GET allowance. The host creates the context and
loads the policy's own entry page. The password is filled only when the main-frame origin
the host reads from the browser is a credential origin and the single login form posts to
one; a caller URL only requests navigation. Observations are typed and bounded and omit
password values. Targets bind a host-wide document epoch, the control epoch and an element
row held in an isolated world; the element is rechecked and acted on in one recipe call.
Operations are navigate, click, plain-text typing, select, named keys and scroll, one at a
time per session. Takeover fences agent observation and input; end, lifetime and teardown
dispose the context. Operation IDs return the first reply on retry and refuse reuse for
another command; a login ID is bound to the broker's credential item and version.

Synthetic acceptance on the loopback fixture and Chromium 149.0.7827.55: private login, then
navigation, typing, selection and an authenticated form submission in the same context,
whose result the next observation shows. Negative tests cover stale, cross-session and
pre-takeover targets, partner/redirected credential origins, off-policy navigation and form
posts, duplicate submission, operation-ID conflicts, unsupported login forms, one-time-code
handover, lifetime, end, teardown and run/session command separation. The fixed workflow
browser tests still pass.

An independent source review of that slice (c4bdb69) found eight defects. Each was first
reproduced against c4bdb69 behaviour on the synthetic fixture with Chromium 149.0.7827.55,
using a debug-only checkpoint seam for the races, and then fixed:

- A login submit button's `formaction`/`formmethod`, or a submit listener, sent the filled
  password as a GET to the navigation-only partner. The recipes now check the submitter's
  overrides, and until the filled form's own POST to a credential origin is allowed, the
  gate admits no other document, no frame and no non-read-only request to another origin.
  Named-frame variants produced no request in this browser either way; the cause is not
  established and the gate rule is covered by unit tests.
- Click and typing checked the element, then sent CDP input separately; a page timer could
  move focus to a password field or swap the button. They now run as DOM actions (`click()`,
  the value setter, input/change events) in the checking call. Those events are untrusted
  (`isTrusted` false); sites that require trusted input will not react.
- Login and observation checked control only before suspending; a takeover and release could
  let a login submit, and a takeover could release page contents. Operations now hold a
  control generation, rechecked after every suspension and before every recipe call.
- After dispatch, a session end or later failure returned `rejected`/`failed` although the
  site had committed. Any error after dispatch is now `siteUnknown`.
- Observation text was bounded per string only; a page with over 16 MiB of option text broke
  the shared 8 MiB pipe and ended every session. The recipe cuts all strings from one budget.
- A reused login operation ID returned the first credential's reply for another credential.
- A page without a password field counted as signed in (CAPTCHA, error page), and the claim
  outlived a return to the login form. Signed in now needs a policy-named signed-in page;
  otherwise the new `unknown` state is reported.
- observe/takeover/release could answer `failed`, which the wire contract refused. observe may
  now fail; takeover and release always report the change of control.

A second independent source review (34ceaa9) found three more defects. Each was reproduced
against 34ceaa9 behaviour on new hostile fixture pages, then fixed:

- The login fill fires input and change events, and a page listener can submit the form. A
  submission whose response replaced the page returned `rejected(staleTarget)`; a fill that
  threw after the page had submitted returned `rejected(unsupportedLogin)`. Only refusals from
  before the first value is set now mean nothing was done. After the fill, a login answers
  with an observation or `siteUnknown`, including a takeover after the fill. If the host sees
  that the page already sent the form (the gate allowed its POST), the host does not submit it
  again and reports where that led. A page that submits after that check is the timer limit
  below.
- After a takeover interrupted a login, the login cleared the host-filled password field with
  no control check, erasing what the person typed after the takeover was acknowledged. The
  login now clears only while it holds control. A handover (takeover, or a one-time-code page)
  clears a pending fill, and waits for any clear already started, before it answers. The host
  does not touch the field after that.
- Observation, typing and selection read an element's own `disabled`, which stays false
  inside a disabled fieldset or for an option in a disabled optgroup. They now use the
  effective `:disabled` state, so such controls are not offered and no event fires.

A third independent source review (49c6d92) found one more defect. A takeover could answer
before an agent call that had already passed its control check reached the page.
`ChromiumPipe.call` is a nonisolated async function, so the session actor is free again
before the command is queued for the browser. Every earlier fence assumed that the check and
the queueing were one step. The second review had not accepted this window, and this plan
had described it only as unreproduced. A debug-only seam in that gap reproduced it against
49c6d92 behaviour for every agent effect. After takeover answered, the click's form POST and
the login submit's POST reached the site, and the navigation was requested. Typing,
selection, a named key and a wheel event reached the page. The login fill put the password
into a field the person then controlled.

Each call sent under an agent hold is now admitted on the session actor, in the same step
as its control check. The pipe queues it only if it was not withdrawn, and checks that in
the same step that queues it. A handover withdraws admitted calls that are not yet queued,
and they are never sent. It waits for queued calls to be answered, bounded by each call's
own deadline (10 s for a recipe, 5 s for navigation, 2 s per input event). Only then does it
clear a pending fill and answer. A lost answer (timeout or closed pipe) does not count as
drained: the takeover refuses with `unknownRun`, and the session ends and its context is
disposed, as for `end`. Every later handover of a session with a lost answer ends it the
same way. Tests cover all eight effect kinds (click, typing, selection, navigation, named
key, scroll, login fill and login submit), a takeover that waits for a queued call, a busy
page whose answer is lost, and a second takeover that waits for the clear the first started.

A fourth independent source review (84ef816) found that this handover was still not
exclusive. Each fix had assumed that switching the mode to human, taking one snapshot of the
admitted calls and waiting for the clear task made the handover exclusive. That assumption
fails three ways, each first reproduced against 84ef816 behaviour with Chromium
149.0.7827.55, using a debug-only pipe seam between claiming a call for queueing and handing
it to the writer:

- The handover's own clear did not count a lost answer. On a page busy for 22 seconds after
  the fill, the clear timed out, the page read timed out, and takeover still answered human.
  The clear then ran after the answer.
- A release during a takeover gave the agent control back while that takeover was still
  waiting for an agent call. A key the agent sent after the release reached the page after
  the first takeover had answered human.
- The handover started its clear before it waited for admitted calls. A fill the pipe had
  claimed but not yet written was overtaken by the clear. Both takeovers then answered with
  the host's password still in the field.

A handover is now one transition that the session owns: agent, handing over, human. The step
that enters it closes admission and bumps the control epoch. Every takeover meanwhile joins
the same transition, and a release waits for it to finish. The transition first withdraws
or waits for every admitted call, and only then clears the host's fill. Only a clear the
browser answered counts. A lost answer, either from an agent call or from the clear, ends
the session and disposes its context. Takeover then refuses with `unknownRun`, and no
reply says a person has control. Takeover and release replies wait for any handover under
way, and read the page again if control moved while they read it. Tests cover the lost
clear (the session ends, the other session continues and the host stays healthy), the
release overlapping a takeover, a fill held before the writer, and a release reply that
overlaps a later takeover.

A fifth independent review (da4f099) closed those three handover findings and identified
one terminal-reply error: ending a session during the control reply's frame-tree read
could still produce a successful cached human/agent identity. A deterministic test ends
the session at that read for takeover and release; both fail against da4f099 behavior.
Control replies now recheck termination after observation and before identity fallback,
returning `unknownRun` for an ended session while retaining fallback for a live unreadable
page. The frame-read scheduling hook is DEBUG-only. Current-source proof is recorded
separately from the earlier 390-test and split mutation results.

After it acknowledges a person's control, the host sends no call under the agent's hold,
and no handover clear can still arrive. It does not stop what the page or site does on its
own, or the consequences of calls answered before the acknowledgement, such as a form
submission a click started.

Remaining limits noticed while fixing, from source reading and not reproduced: a document
response near the 8 MiB document cap can exceed the 8 MiB pipe message cap once escaped or
base64-encoded in `Fetch.getResponseBody`, which would end the browser (shared with fixed
workflows, not changed here); named keys still go to whatever element the page focused; a
credential-origin page's own script can read the filled password and send it to a navigation
origin, except non-read-only requests during the pre-submission window. A page timer that
submits the filled form between the host's check and its own submit can produce a second
login POST to the credential origin; the login still answers with an observation or
`siteUnknown`. A page that keeps the renderer busy past an agent call's deadline, or past
the handover clear's deadline, makes that answer lost, and the session then ends at its next
handover instead of passing to a person. A handover can take as long as the latest admitted
call's deadline, plus the deadlines of preparing and sending the clear. While a handover is
under way, agent replies already report human mode.

Limits: `HostPolicy.production.sites` is empty, and neither Core, the host link nor MCP can
send site commands. The operation journal is volatile host memory, bounded per session and
lost with the host; durable broker journaling before dispatch must be integrated before any
production external effect. A person in control has no raster relay for sessions yet.
Uploads, downloads, popups, extra tabs, history, coordinates, iframe and multi-step logins
are unsupported. Input sent just before a takeover is not recalled, and a receiving site can
still reflect a password it was given.

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

## Native Linux MCP bridge (development)

The bridge now selects the kernel-peer-authenticated Unix read socket on Linux and XPC
on macOS. Linux uses only `/etc/agent-vault/sockets.json`, refuses development policy,
and validates its configured agent UID and the broker peer UID before sending requests.
It exposes the same four narrow tools; it has no credential store or admin client.

The bounded stdio transport uses nonblocking descriptors on both platforms. Darwin keeps
`F_SETNOSIGPIPE`; Linux blocks SIGPIPE only around each write on the writer thread,
consumes a newly generated broken-pipe signal, and restores the thread mask. It does not
change the process-wide signal disposition or consume an earlier pending SIGPIPE.

Native macOS checks: 15 transport/bridge tests and all 381 root tests pass (existing
opt-ins skipped); boundary and synthetic MCP verifiers pass. A standalone C broken-pipe
check passes with the default signal disposition. Linux compilation, the Linux-specific
pending-signal case and installed end-to-end MCP/socket identity remain pending CI and
installed-host checks. The Linux broker still refuses to serve without real key custody.
This change does not provide cloud login, browser site dispatch, an installer or a GUI.

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
