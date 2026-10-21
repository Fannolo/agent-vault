# Approved-site operation: synthesized design proposal

18 October 2026. Planning only. No runtime feature is enabled by this proposal.
The user confirmed general operation of approved websites, including submissions,
messages, payments, deletion and account-security changes. The first live provider and
the final deployment boundary remain undecided.

## Product and experience

Agent Vault is a free, open-source authentication and private browser service for agents,
with an open protocol and an initial macOS reference app. A person connects an account
privately, pairs a client installation, approves website scope and duration, and lets the
agent navigate and interact. The person can inspect activity, take exclusive control,
return control or revoke access. Suggested main screens are Sites, Approved Clients and
Activity; key-management details belong in advanced settings.

Reusable service credentials, cookies, profiles and debugging channels stay inside the
trusted service. The model receives permitted page observations and bounded controls.
Private passwords, MFA, SPID and passkey ceremonies remain in trusted human UI. Provider
requirements are respected; unsupported authentication is reported honestly.

Generic interaction carries broad account powers. On 18 October 2026 the user explicitly
selected broad access including submissions, messages, payments, deletion and security
changes. Grant approval must explain this authority clearly. No generic per-action
confirmation or classifier-based sensitive-action exclusion is promised. Client, account,
destination, time and revocation boundaries still apply; narrower provider roles may be
used when expressly selected. This product decision is not a live account grant or an
instruction to the development agent to perform any of those external actions.

## Recommended architecture

Use candidate A's dedicated private browser process tree for each active grant. A broker
owns accounts, grants, caller binding, revocation, deadlines and operation status. Each
browser instance owns only its grant's temporary profile and control channel. One session
has one controller. Authentication success transitions to agent operation instead of
immediate teardown. General navigation and input replace compiled business-task recipes;
provider-specific authentication support may still be needed.

This is a recommendation, not a demonstrated isolation boundary. Separate processes with
the same UID do not establish cross-grant protection. The installed design must prove
private service identity, per-grant filesystem/process restrictions, authenticated IPC,
denied debugging and whole-process network containment. The sandbox and origin-aware
network mechanism are unresolved engineering choices. Do not supply real credentials
until synthetic installed-boundary checks pass. A VM is an alternative if the agreed
process boundary cannot be achieved; a shared host is a distinct weaker choice, never
an automatic fallback hidden behind the same claim.

Separate policies identify credential recipients, agent-visible and navigable origins,
human-only identity providers and passive resources. Redirects, history, frames and
background channels must obey their respective policies. Cookie domain/site scope must
be designed explicitly; an exact navigation-origin list alone is insufficient. Browser
interception and CSP supplement containment and do not prove a process-wide firewall.

## Small public interface

Unimplemented domain sketch; no wire compatibility or enabled capability is implied:

```text
openSite(account, proposedScope) -> Waiting(RequestRef) | Ready(SessionRef, Observation)
status(RequestRef) -> Waiting | Ready | Ended
operate(SessionRef, OperationID, Command) -> Observation | Waiting | Refused | Unknown
close(SessionRef) -> Ended                         // idempotent

Command = Observe | Navigate(permittedURL) | Click(currentTarget)
        | Type(currentTarget, taskText) | Select(currentTarget, option)
        | Scroll | OrdinaryKey
```

References resolve only under an authenticated caller. A model/chat name is a label,
not authentication; today's signed bridge and paired OS user define installation-wide
authority. Two processes able to invoke that principal are not isolated agents.
Pre-session requests and operating sessions use distinct reference types. Target references
bind session, document and control epochs; stale or cross-session references fail.
No raw CDP, JavaScript evaluation, HTTP, cookies, storage or profile export is exposed.

Initial enabled controls should omit coordinate clicks, unchecked history navigation,
uploads, downloads, clipboard, extra tabs and popups. Their secure handoff and permission
contracts need separate units; this is sequencing, not a permanent ban on useful files.
Accessibility-poor pages initially require human control. The first complete live workflow
must include any file-transfer capability it actually needs before being called supported.

## Authority and recovery

States distinguish awaiting approval, private authentication, agent operation, human
control, reauthentication, closing and ended. The broker checks authority before dispatch
and before releasing results. Takeover withdraws agent control, invalidates queued work and
epochs, and fences background activity before exposing private interaction. Do not claim
that stopping input freezes already dispatched website requests.

Revocation withdraws future authority and network access, then destroys the owned browser
tree/profile. Report withdrawal separately from teardown completion. Expiry uses monotonic
deadlines; browser/network leases terminate when authority is lost. Crash recovery fences
orphaned instances and requires new private authentication rather than restoring live
authority from a client-supplied reference. Cross-grant login persistence remains open.

Bind OperationID to caller, session and command digest. Journal admission before dispatch;
an ambiguous timeout returns Unknown and never silently resubmits. This is bounded broker
deduplication, not exactly-once remote effects. The durable journal contains status,
digests and uncertainty, never page bodies, screenshots, credentials or replayable results.
Revocation cannot reverse a submission already accepted by the website.

## Honest security contract

Prevent direct extraction through agent tools, terminal arguments/environment, logs,
profiles and debugging interfaces. Prove each claim on the installed artifact.
A receiving website can reflect or encode a password into later text, images or files;
arbitrary page output cannot support a universal no-leak guarantee. Prompt injection can
also induce misuse of permitted account authority without revealing any password.
Trusted-site assumptions, local-process privileges, broker/browser compromise and OS/root
exclusions must be explicit. AI review and notarization are not security certification.

## Delivery and verification

1. Specify the confirmed broad-access grant, then agree the first workflow, identity
   meaning and threat assumptions.
2. Design and prove a synthetic per-grant process/network boundary on installed identities.
3. Introduce continuing-session authority, exclusive takeover and private reauthentication.
4. Add minimal generic browser controls and observations, then separately scoped artifacts.
5. Migrate callers and remove superseded browser paths. Existing fixed grants retain their
   restricted engine until removed; they never silently become interactive grants.
6. Verify the complete authorized live workflow, recovery and actual signed/notarized
   distribution. Record unsupported providers and remaining limitations.

For every frozen unit, a different AI reviews the exact design/diff; findings are
reproduced, fixed and retested, then the changed revision receives fresh review. Retain
revision/artifact hashes, private evidence and unresolved disagreements. Include planted
defects proving checks detect credential exposure, stale input, duplicate submission,
cross-client replay, teardown failure and network escape. Verify allowed behavior too,
so total failure cannot masquerade as containment. Runtime authorization and revocation
must work without an AI provider. Human security assessment precedes strong assurance
claims. This is a required development workflow, not an already automated review service.

## Synthesis and review record

Independent candidates: GPT-6-Astra (A) and GPT-6-Sol (B). Cross-judge: Grok 4.7.
Root scored A 19/20 and B 19/20, provisionally preferring A for lifetime ownership;
Grok scored A 18/20 and B 16/20 and also preferred A. These are design rubric judgments,
not measured security scores. The judge correctly reduced both boundary scores because
the OS and network mechanisms are not yet specified; that objection is retained.

Base: A. Adopt B's smaller initial surface, distinct request/session references, explicit
broad-authority approval wording and journal privacy. Preserve A's independent teardown,
uncertain-effect semantics and isolation-before-real-credentials delivery order. Reject
raw coordinate access and unchecked history, and avoid mixing shared and dedicated hosts.
The candidates converge on private custody and generic site operation; they disagree
on the cost and value of cross-grant process ownership. No implementation reconciliation
is needed because this round changed documentation only.

Private frozen candidates, hashes, root assessment and complete judge report are in
`verification-logs/design-reset/`. Grounded current behavior is in `GROUNDING.md`.
Open decisions remain in `../../PRODUCT-GOAL.md`. The cross-review predates the user's
broad-access answer; retain its original findings as history. The explicit user answer
resolves sensitive-action product scope, not the outstanding technical evidence gates.
