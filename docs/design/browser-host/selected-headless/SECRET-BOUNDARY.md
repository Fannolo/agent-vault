# Synthetic credential exposure boundary

Run `python3 scripts/verify-secret-boundary.py` in this worktree. It accepts no
credential arguments and requires the exact designated local headless shell. It
clears inherited environment without enumerating it, supplies private HOME/TMPDIR,
uses bounded `run_owned` build/test process groups and writes private ignored logs.
No real credential, Keychain entry, website, browser profile or installed service
is read. Canary strings are generated inside Swift test memory and never supplied
through shell input, argv or environment. Do not publish raw test logs.
Add `--prove-rotation` to build a deliberate no-op rotation mutant, require the
decoded POST assertion to fail, restore exact source bytes, rebuild and rerun baseline.

## Observations

`SecretBoundaryTests` composes the existing real HeadlessStack. It enrolls fresh
password A, then the native AppModel rotates it to distinct fresh password B through
signed admin XPC into Core's test memory SecretStore. Only B is accepted by the
DEBUG synthetic FixtureSite initializer. A decoded actual login POST must contain B
and differ from A; the deliberate no-op rotation control must fail this assertion.
Both canaries and their credential envelopes are scanned. Other fixture users keep
the original fixed password. Production host adapters gain no API or configuration
switch. The real authenticated host link uses B at the fixed loopback login recipe,
pauses for MFA and accepts a separate fresh long human-input canary from the
HumanStepModel. A boolean check proves the latter reaches the fixture POST too. The synthetic fixture
accepts any completed MFA input; this does not test real OTP validation.

The probe scans serialized read XPC replies (pause, completion and denied repeat),
admin XPC snapshots, AppModel snapshot/audit/notice, a real AppModel audit export,
Core state metadata, MCP tool catalogue/account replies and closed-error replies,
and regular files/names under the owned browser directory after browser reap.
MCP uses the actual BridgeServer and SDK in-memory transport over real read XPC;
the actual collected typed profile is also replayed through its response serializer.
A canary-bearing internal exception must become a closed broker-unavailable error;
it does not test the executable's stdio framing here. Only the test target links
MCP, app, Core and host together. Product dependency boundaries remain unchanged.

The same workflow probe observes `KERN_PROCARGS2` for its actual browser child,
while the DEBUG-only ChromiumPipe.withOwnedChild / OwnedGroup.withPinnedChild seam
holds the existing reaper/signaller ownership lock. The read is refused after
ownership ends; the child cannot be reaped or PID-reused during the observation.
No PID or process is found by name. The full executable and argv must equal the
fixed binary, exact owned user-data-dir argument and ChromiumPipe.arguments; the
environment must contain exactly the expected HOME, TMPDIR and PATH values, without
duplicates. Controls reject an extra debug switch, a canary in an allowed environment
value and a wrong safe environment value. The full workflow's A/B/MFA probe scans
the actual captured values; no unrelated fresh launch-only probe substitutes for it.

ChromiumPipe's real OwnedGroup handles termination. HeadlessStack closes all models,
connections/listeners and the fixture even if reap is uncertain, then throws and
preserves its directory unless confirmed reap permits deletion. A deterministic
regression drives the shared test-owned cleanup gate with uncertain ownership and
proves services close while evidence survives; confirmed reap then permits deletion.
The former standalone launch test with unconditional directory deletion is removed.
The workflow retains its independent owned-browser watchdog.

The detector scans both passwords, their complete username/LF/password credential envelopes,
and human input. The finite catalogue covers full raw UTF-8, padded/unpadded base64 and base64url, lower/upper hex, all-byte percent escapes in lower/upper case, URL form
escaping, JSON string escaping with both escaped/unescaped slashes (with/without
surrounding quotes), lower/upper
Unicode JSON escapes, and UTF-16 little/big endian. It does not detect arbitrary
transforms, partial strings, encryption or hashes. Negative controls deliberately
inject every enumerated encoding in memory and require rejection. A separate control
deliberately sends a canary-bearing decoded result through the real MCP serializer
and requires detector rejection of the resulting tool text. Missing required
channels also fail: an empty or unobserved surface cannot pass. Reports contain
only closed channel names, observation/leak counts, policy-match booleans and argv counts. Assertions receive
booleans/statuses, never canary-bearing operands.

## Limits

These are synthetic bounded observations, not absolute noninterference. Intended
credential-bearing native input, admin enrollment/rotation requests, broker secret
memory, authenticated host credential wire, CDP and trusted loopback login/MFA
request bodies are deliberately outside agent-facing scans: those components must
use the secret internally. The probe does not log those payloads. Browser stdout
and stderr go to /dev/null in the production launcher; this unit does not capture
or claim to scan them. Terminal shell history, bridge executable stdio, native GUI
password-field behavior, actual Keychain, installed deployment and separate-UID
isolation are not established here. AppModel state is exercised, not a visible
native window.

The fixture's trusted service necessarily sees credentials. This is not protection
against a malicious trusted service reflecting or encoding them into permitted
result fields, root/debugger/memory compromise, crash reporting, OS clipboard or
screen capture. Artifact byte scanning is not OCR and makes no claim about JPEG
pixels, screenshots or screen confidentiality. No generic evaluation, destination,
raw-secret retrieval or hash-output interface is added.

## Initial verification before corrective review

The initial bounded clean-environment driver passed its build and all four boundary tests
(two detector controls, one real workflow and one actual owned-launch observation).
The package dependency-boundary check passed. The default suite passed with 346
registered tests in 28 suites and explicit Chromium/native-Keychain opt-out skips.
The real U5 plus boundary selection passed all 11 registered tests in three suites,
with no skips. Raw logs are retained locally under ignored `verification-logs/`.

The deliberate MCP serializer leak control initially exposed a nested-JSON blind
spot in the probe: encoding SDK Tool.Content escaped its JSON text a second time.
The probe now scans the actual text payload as well as the encoded content/metadata;
the deliberate leak is rejected. This control proves detection, not that the bridge
can prevent a malicious trusted broker/target from reflecting arbitrary secret data.

## Original U5 evidence location

Historical U5 log references in U5-E2E.md resolve against the original local
worktree `/Users/alessandro/.t3/projects/agent-vault-worktrees/browser-e2e/verification-logs/`.
Its `u5-unit-a-kr93rx1r`, `u5-reopen-mutations-qhq8l2nh`,
`u5-unit-b-algvn96f` and `u5-context-mutation-vbsm8iq7` directories remain there;
they are not missing evidence merely because another worktree does not contain them.
Secret-boundary driver logs remain in this unit's own ignored verification-logs.

## Corrective verification

After review, the bounded `--prove-rotation` driver passed the five-test baseline,
built the deliberate no-op rotation mutant successfully, detected its expected
decoded-login-POST failure, restored exact source bytes, rebuilt and passed the
five-test baseline again. Every enumerated encoding is injected by the detector
controls; the password grammar includes a slash and a length requiring base64
padding so these added variants are exercised independently.

The final normal driver build and all five tests passed. The default suite passed
with 347 registered tests in 28 suites and explicit Chromium/native-Keychain opt-out
skips. The real U5/boundary/OwnedGroup selection passed all 16 registered tests in
four suites without skips. It includes refusal to observe a child after confirmed
reap or uncertain ownership. Package boundaries and diff checks passed. These
private logs remain under this worktree's ignored `verification-logs/`.
