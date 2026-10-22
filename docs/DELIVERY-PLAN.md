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
Linux portability checks therefore run in isolated CI runners; the local full Docker-based
recording remains pending rather than being weakened to a passing label. The Bite Supabase
connection exposes one Bite organization. A dedicated `agent-vault` project is proposed at
the connector's quoted $10/month; cost acceptance is pending. Existing `prod`, `stage` and
`meeting-copilot` projects are not deployment targets.

This concrete managed-host option triggers a narrow review of Supabase Auth plus protected
ciphertext APIs as an alternative to operating Keycloak/Vapor. The private-browser,
client-side encryption, paired approval and explicit restart boundaries remain unchanged.
