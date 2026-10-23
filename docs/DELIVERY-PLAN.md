# Agent Vault: usable desktop and headless delivery

23 October 2026. Implementation work authorized by the user. This document records the
remaining product work; it does not mark any unverified feature as complete. The starting
point is merged main `2f93b878c796ff4c93ba5fa8be853822b09e8512`.

## Outcome and acceptance

On a freshly installed macOS machine and an independent Linux service host, a user can
create a cloud account, enroll the device, import an approved login, grant an agent access
to an approved website, and have that agent log in and continue browser work through MCP.
Passwords, PINs, cookies and browser control connections are not returned to the agent.
After restart, a headless service resumes only within its saved, unexpired authorization.
No desktop session, Mac relay or manual terminal password is required for normal operation.

Acceptance requires actual installed end-to-end runs, not only passing library tests:

- Cloud signup, verification, login, logout and account recovery work. Vault recovery is
  separate; resetting a cloud account cannot decrypt a vault or enroll a device.
- An enrolled second device syncs ciphertext and opens an approved item. An unapproved
  device, stale history and a substituted recipient key are refused.
- An authenticated agent discovers an eligible account for a broker-owned tab, privately
  logs in, performs a subsequent page interaction, and closes the session. Expired or
  revoked grants stop new work. External effects are never blindly retried.
- A Linux service starts without a graphical session and survives restart. Another OS user
  cannot read its vault, impersonate its client or gain a grant by supplying an identity.
- Import preview, selection, deduplication and commit operate through a trusted human
  channel. Encrypted export/import round-trips without putting secrets in agent output,
  shell arguments, environment variables or logs.
- Installed macOS approval signing verifies after user presence. Signed/notarized packages,
  upgrade, recovery and uninstall are exercised; Linux packages enforce service identity.

Sites may require MFA, CAPTCHA or explicit confirmation again. Those states need a trusted
paired human channel. Saved approval cannot bypass a site's authentication requirements.
Root/kernel, compromised trusted code and malicious receiving websites remain limits.

## Delivery order

1. **Verifier cleanup.** Move fixed tables out of the large membership driver; share one
   exchange-step table between live recording and receipt replay; use one mutation
   specification for M1–M10 and N1. Preserve process ownership and exact restoration.
   Re-record both platforms and controls under the new epoch; obtain independent review.
2. **Password-ready vault.** Review and implement a versioned padded/committed successor
   format, scoped secret access, durable membership/checkpoints, atomic encrypted storage,
   tombstones and explicit conflict handling. Synthetic version 1 stays unchanged.
3. **Native/headless authority.** Add Linux peer-authenticated daemon and installation,
   enrollment/unlock/revocation and a paired trusted approval channel. Preserve separate
   agent and administrative capabilities. Decide restart/unlock policy explicitly.
   Started: the Unix-socket transport (kernel peer UID, separate read/admin sockets) serves
   the existing broker composition in tests. Custody, the serving daemon, systemd units,
   the Linux bridge and installed-host checks remain.
4. **Cloud accounts and sync.** Use maintained authentication components. Implement an
   authenticated ciphertext-only sync service, transcript-bound device pairing and vault
   recovery. Self-hosted local integration precedes isolated hosted deployment.
5. **Private login and continued browser work.** Reuse the private host where appropriate.
   Add typed tab/session operations, origin-bound account discovery/fill, continuing agent
   control, challenge takeover, navigation limits, file transfer and lifecycle cleanup.
   Existing browser skills need an explicit adapter; arbitrary debugging endpoints remain
   ineligible for password filling.
6. **Import/export.** Investigate supported macOS credential access. Implement a trusted
   selection/import path when available, plus interoperable selected-file import and
   encrypted export. Do not promise silent access to Apple Passwords/iCloud data.
7. **Installed release.** Verify dedicated identities, filesystem/process/network boundaries
   and protected-key signing. Complete Bite-signed notarized macOS distribution and Linux
   packages. Retain failure/recovery evidence; do not label an unsigned fixture a release.
8. **Unattended acceptance.** Run the complete workflow on clean installed hosts, including
   restart, expiry, revoked device, offline sync, failed import, provider challenge and
   interrupted external action. Merge reviewed units rather than accumulate draft PRs.

These are eight substantial integration units. Crypto, browser operation, cloud transport
and installed OS identity have separate failure boundaries. Reviews and runtime checks
apply to each unit; agreement among models is not external security certification.

## Parallel work and current limits

The existing selected architecture is retained unless a concrete product requirement
invalidates it. Two read-only candidates examine the browser/headless/cloud boundary while
the sole source writer completes the cleanup dependency. Source workers do not share files.
Frozen historical receipts remain historical; changing a recorder or bound input requires
new evidence, not relabeling an old result.

Hosted deployment needs an actual isolated host/domain and privately entered deployment
credentials. Apple notarization needs an authorized credential/profile through a private
channel. Missing external access does not block local implementation, and local success
does not establish hosted or notarized success. Existing unrelated apps and personal
credentials must remain untouched during development tests.

The decision trail is `docs/DELIVERY-DECISIONS.tsv`. Exact test logs and task receipts remain
under ignored `verification-logs/`; only synthetic, non-sensitive evidence summaries belong
in the public repository.

## Current deployment constraints

The user selected Bite hosting and explicitly requested that OrbStack stay stopped.
Linux portability checks are therefore configured for disposable CI containers; the local full Docker-based
recording remains pending rather than being weakened to a passing label. The Bite Supabase
connection exposes one Bite organization. A dedicated `agent-vault` project is proposed at
the connector's quoted $10/month; the user declined paid provisioning. Do not create it.
Existing `prod`, `stage` and
`meeting-copilot` projects are not deployment targets.

The managed-host review accepted a dedicated Supabase project as the hosted reference,
subject to implementation and deployment checks and an approved hosting option. If provisioned,
it replaces hosted Keycloak/Vapor;
the sync contract stays independent of that choice for future self-hosting. The
private-browser, client-side encryption, paired approval and explicit restart boundaries
remain unchanged. No cloud project has been created and no cloud feature is complete.

### Managed cloud implementation constraints

Only the trusted broker/daemon may hold cloud sessions. Each device obtains its own
session; refresh is serialized and the replacement token is saved atomically. Neither
the MCP bridge nor the browser host may receive cloud tokens. Account recovery restores
transport access, not vault keys or device enrollment. Transport session revocation is
coarse and must be described separately from cryptographic device revocation.

Native controller login uses PKCE. Headless login uses an authenticated encrypted pairing
channel: the headless daemon retains the verifier, the controller initiates the email
flow with its challenge, and the callback code is relayed encrypted to that daemon.
There is no terminal OTP fallback. The complete callback, pairing and token-custody path
must be tested before claiming headless login. Supabase's OAuth server is not assumed to
provide a device authorization grant.

The server stores bounded opaque immutable ciphertext objects and a conditional head.
Clients verify digests, signatures, membership and pinned checkpoints. Database cursors,
timestamps and conditional updates are not cryptographic freshness or enrollment evidence.
The transport object cap must accommodate the reviewed successor format; the review's
suggested 64 KiB cap is too small for the existing synthetic codec's maximum record.

Database ownership comes from `auth.uid()`, never editable user metadata. Anonymous
sign-ins stay disabled. Every exposed table needs least-privilege grants and RLS;
administrative keys never ship in clients or CI. Direct head writes must be unavailable:
implement conditional writes with a narrowly granted RPC and explicit owner checks.
If its private implementation needs definer rights, pin its search path, revoke default
execution and validate ownership inside that function before touching private counters.
Quota and sequence allocation must serialize per vault without allowing committed rows
to be skipped by a cursor. Pairing relay rows require separate bounded expiry and abuse
controls; possession of a slot identifier is not device authentication.

Public signup requires a configured SMTP sender. The default email service is not public
signup acceptance. Initial hosted work keeps signup closed while two-user/anonymous RLS,
immutable retry, conditional-head races, quota and cursor-order tests run against that
dedicated project if provisioned. Existing Bite projects remain untouched. Free or existing approved
hosting and SMTP configuration are distinct deployment dependencies; neither blocks
reversible source work.
