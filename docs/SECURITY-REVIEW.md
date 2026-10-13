# Initial implementation review

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
