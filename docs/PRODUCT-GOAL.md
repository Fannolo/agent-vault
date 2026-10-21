# Agent Vault product goal — multi-platform scope, 21 October 2026

Status: multi-platform design and implementation begins in an isolated branch. This
document does not enable unfinished capabilities or replace measured runtime evidence.

## Confirmed direction

Build a free, open-source way for AI agents to use accounts on approved websites while a
trusted service retains reusable authentication secrets. Provide an open protocol and a
usable native reference applications on macOS and Linux. Linux runs its own vault and
private browser; it does not depend on a Mac. Provide signup/login and client-side encrypted
cloud synchronization of approved stored credentials across enrolled devices. The cloud
service must not receive vault decryption keys or plaintext stored passwords. Account
authentication and vault unlocking are distinct boundaries. Sharing with other people is
a separate permission/key-management capability from syncing a user's own devices.

The user explicitly chose: **“Let agents operate approved websites.”** Agents should be
able to navigate, observe and interact with those websites after private authentication;
support must not depend on implementing a separate fixed action for every business task.

On 18 October 2026 the user explicitly chose **“Broad access, including these actions”**
when asked about form submissions, messages, payments, deletion and account-security
changes. An interactive website grant may include all these actions within the approved
account and website scope. The approval UI must state that breadth clearly; no universal
per-action confirmation or semantic sensitive-action blocker is part of this chosen model.
A grant remains bound to its client, account, destinations, duration and revocation state.
This product decision does not itself create a live grant or instruct the development
agent to make a payment, send a message, delete data or change an existing account.

Real passwords, PINs and authentication material must not be supplied to the AI model,
chat, terminal prompts, command arguments, environment variables or ordinary logs. Human
entry and human-only challenges belong in trusted native/private authentication UI.
MFA, SPID, passkey and provider requirements must be respected, not bypassed.

Use independent AI perspectives throughout design and implementation. An implementation
author's claim or a second model's approval is not evidence that a feature works securely.

## Concrete caller journey confirmed by user

The person asks the agent to use Amazon. The agent notices the browser is logged out,
asks the local password manager whether it may use an Amazon account, and requests private
login if authorized. The trusted credential/browser boundary completes authentication;
the agent observes the result and continues normal approved website work. This discovery-
first workflow must work equally on Linux and macOS. A denied or unapproved account gives
an approval/denial result, never a raw password. Reuse the current trusted browser context
where its custody boundary supports it; an arbitrary agent-controlled CDP endpoint is not
a trusted credential recipient. Define the browser integration rather than promising
private filling into every unrestricted third-party browser.

## What the current application does

The current design grants fixed operations and returns narrowly typed results. Its browser
logs in privately, performs a compiled workflow and closes the context. It does not yet
offer the agent an ongoing authenticated browser to operate.

Useful foundations include private enrollment, protected human approvals, broker-owned
grants/revocation, authenticated IPC, bounded transports, private browser process control
and synthetic hostile-site verification. The new goal needs a new browser capability and
session lifecycle, not merely more fixed recipes or access to the human challenge relay.

## Proposed user experience — for discussion

1. Connect a website/account privately in Agent Vault.
2. Pair the agent client and approve its website access with a duration and permission scope.
3. The vault authenticates privately, involving the human when the provider requires it.
4. The agent works on the site through a controlled browser interface.
5. The human can inspect access, take control and revoke it. Expiry/revocation ends future
   browser authority; it cannot reverse a request the website already accepted.

The agent must not receive a portable cookie jar, browser profile, raw debugging endpoint,
network authorization headers or reusable service token. A broker-bound session reference
is conceptually different from exporting the website's login session; its caller binding,
permissions and expiry still need specification.

## Engineering choices still to specify

- Who is authenticated: a host app, OS user, agent installation, or a separately isolated
  agent principal? A caller-supplied model or agent name is not authentication.
- Which origins are approved for navigation, credentials, identity-provider challenges,
  subresources and agent observation? These are different permissions.
- Which browser observations and controls are exposed, and how private authentication
  phases switch into agent operation and back into human control.
- Upload/download authority, artifact handoff, tabs/popups, external links, redirects,
  persistent login, reauthentication and concurrent sessions.
- Final acceptance of the recommended per-grant private browser process design; its OS
  sandbox, cookie scope and whole-process network mechanism still need specification.
  See `design/approved-site-browser/DESIGN.md` for the independently reviewed proposal.
- First supported end-to-end workflow and acceptance criteria. The tax-portal use case
  motivated the project; its exact authentication/support scope remains to be agreed.

## Claims we must earn

Keeping stored credentials and raw browser internals outside agent tools is a concrete
boundary. Promising that arbitrary website content can never reveal a secret is stronger:
a receiving website can reflect or encode it into text, images, URLs or other output.
Password-field redaction and finite canary scans do not prove universal prevention.

The threat model must name trusted sites, untrusted page content, prompt injection, malicious
agent clients, local OS/process access and network exfiltration separately. Agents can abuse
account authority without knowing a password. Website approval is therefore a permission
decision, not only a credential-storage decision.

1Password-level assurance is an ambition, not a current equivalence claim. Notarization,
synthetic tests and AI review each establish different, limited facts. Actual installed
isolation, authentication, recovery and adversarial runtime checks remain required.

## Continuous verification — required development workflow

For each small implementation unit: freeze an exact source revision; have a different AI
review the design/diff independently; reproduce accepted findings; run behavior and hostile
failure tests, including controls proving the detector catches a deliberate defect; retain
source/artifact hashes, private logs and unresolved findings; request a fresh review round
after material corrections. Do not change code during its verification recording.

Bind verdicts to the exact version and evidence. Keep product decisions, implementation
status and production-release evidence distinct. Public issues/reviews must contain no
credentials or private account evidence. Human security assessment is still needed for
strong assurance claims. Review automation is a planned workflow, not an already running
continuous service.
