# Native human app

`AgentVaultApp` is a SwiftUI/AppKit app (bundle id `dev.agentvault.app`). It links
`AgentVaultContracts`, `AgentVaultIPC` and `AgentVaultRuntime`: never `AgentVaultCore`, never the browser component, and it stores no
provider credential, token or cookie. Enrollment and rotation use `SecureField`; the entered
value goes into one admin request and the form state is cleared before the request is sent
(Swift strings cannot be zeroed, so this is best effort).

## Screens

Accounts (add, replace, delete), Clients (pair by UID, revoke), Grants (client + account,
expiry, call budget, per-call approval toggle, revoke), Requests (waiting or approved; only
`waiting` has Approve/Reject), Audit (metadata table and JSON export, mode 0600) and Approval Key
(protection level and public key to register).

## Admin protocol

Every mutation is `begin` (broker freezes the request, returns a single-use challenge), a
fresh user-presence prompt that names the action, an ECDSA P-256/SHA-256 DER signature over
`challenge.payload`, then `authorize`. The app builds the prompt text from its own request, never
from the challenge. Payload, password and signature are never logged (a source test bans
`print`, `NSLog`, `os_log`, `Logger`, `dump`).

`VaultAdminTransport` is the only broker dependency: `snapshot`, `begin`, `authorize`. Audit
arrives in `AdminSnapshot.audit`. `AppComposition` loads protected installed configuration and
uses `XPCAdminTransport`. Missing configuration or failed authentication uses a transport that
fails closed.

## Approval key

`HumanApprovalSigner` tries a Secure Enclave key (`privateKeyUsage` + `userPresence`), then a
data-protection Keychain P-256 key (`userPresence`, `kSecAttrIsExtractable = false`). There is no
unprotected production fallback. Details:

- Stored keys are re-read and their attributes checked (exact expected user-presence access control, tokenID, and
  non-extractability for the software key); a key that does not prove this is refused. This is
  what the Keychain reports, **not hardware attestation**, and the broker cannot learn from the
  public key where the key lives. Installer registration is a trusted human ceremony.
- Only a definite `errSecItemNotFound` in every backend allows creation. A locked Keychain,
  `errSecInteractionNotAllowed`, authentication failure or duplicate items throw
  `keyLookupFailed(status)` and create nothing, so the public key cannot silently change.
- Signing needs a new `LAContext` evaluation each call (`deviceOwnerAuthentication`, no reuse);
  without Touch ID or a device password it fails closed.
- `AgentVault --print-approval-public-key` prints the public key as JSON (X9.63 and SPKI base64,
  SHA-256 fingerprint) and creates the key if none exists. Exit codes: 64 usage, 70 unavailable or
  unprotected, 73 creation failed, 74 lookup failed, 75 no user presence, 76 key not protected.
- Not defended: two processes creating the key concurrently (the lock is per process).

## Verification record (13 October 2026, Apple Swift 6.2.4, Xcode 26.3, macOS 15)

- Tests cover the full admin lifecycle against an in-memory broker that verifies signatures, rejects
  replays, expiry, cross-challenge signatures and foreign keys; signer flow and lookup-failure
  handling with scripted backends; key attributes; export; and structural invariants.
- **Real protected keys could not be created.** An ad hoc signed binary gets `errSecMissingEntitlement`
  (-34018) from `SecKeyCreateRandomKey` for Secure Enclave and for software Keychain keys with
  user presence, with and without the data-protection keychain (probe run on this Mac). So the app
  fails closed here, the real signing path was **not** exercised with a hardware or Keychain key,
  and no real Touch ID prompt was shown. Verifying it needs a build signed with a team identity
  and keychain entitlements, which this task did not use or install.
- `scripts/build-mac-app.sh [debug|release]` builds `.build/app/AgentVault.app`, ad hoc signed,
  installs nothing. A DEBUG-only preview (`AGENT_VAULT_UI_PREVIEW=1`, software key and in-memory
  broker, compiled out of release) and screenshot tour (`AGENT_VAULT_UI_SCREENSHOTS=<dir>`, renders
  the app's own window in-process, no screen-recording permission) were used for GUI checks.
