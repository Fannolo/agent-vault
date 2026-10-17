# Synthetic credential exposure boundary

Run `python3 scripts/verify-secret-boundary.py` in this worktree. It accepts no
credential arguments and requires the exact designated local headless shell. It
clears inherited environment without enumerating it, supplies private HOME/TMPDIR,
uses bounded `run_owned` build/test process groups and writes private ignored logs.
No real credential, Keychain entry, website, browser profile or installed service
is read. Canary strings are generated inside Swift test memory and never supplied
through shell input, argv or environment. Do not publish raw test logs.

## Observations

`SecretBoundaryTests` composes the existing real HeadlessStack. A fresh password
is accepted only by the DEBUG synthetic FixtureSite initializer. All other fixture
users keep the original fixed password. Production host adapters gain no API or
configuration switch. A native AppModel rotation sends the password through the
signed admin XPC request into Core's test memory SecretStore. The real authenticated
host link uses it at the fixed loopback login recipe, pauses for MFA and accepts a
separate fresh long human-input canary from the HumanStepModel. Successful typed
profile collection confirms the password was actually used. The synthetic fixture
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

A separate real ChromiumPipe spawn observes `KERN_PROCARGS2` only for the exact PID
returned to its existing makeGroup callback, before the reaper starts. The child
cannot be PID-reused at that point. It scans actual argv/environment and requires
exactly HOME, TMPDIR and PATH in the browser environment. No other process is
queried or signalled. ChromiumPipe's real OwnedGroup handles termination and the
test awaits reap before directory removal. The workflow stack retains its existing
independent watchdog and awaited cleanup.

The detector scans the password, complete username/LF/password credential envelope,
and human input. The finite catalogue covers full raw UTF-8, padded/unpadded base64, unpadded
base64url, lower/upper hex, all-byte percent escapes in lower/upper case, URL form
escaping, JSON string escaping (with/without surrounding quotes), lower/upper
Unicode JSON escapes, and UTF-16 little/big endian. It does not detect arbitrary
transforms, partial strings, encryption or hashes. Negative controls deliberately
inject every enumerated encoding in memory and require rejection. A separate control
deliberately sends a canary-bearing decoded result through the real MCP serializer
and requires detector rejection of the resulting tool text. Missing required
channels also fail: an empty or unobserved surface cannot pass. Reports contain
only closed channel names, observation counts and leak counts. Assertions receive
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

## Verification on this unit

The bounded clean-environment driver passed its build and all four boundary tests
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
