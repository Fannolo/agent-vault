# Agent authentication protocol: development draft

Agent Vault delegates an approved operation, not possession of a credential. This
document describes the intended security contract and identifies current gaps. It
is not a claim of production readiness or equivalence to an audited password manager.

## Credential entry and storage

Only a human-facing native secure form accepts a real service credential. Agents,
terminal prompts, command arguments, environment variables and MCP requests must
not carry it. The legacy development CLI accepts only generated synthetic demo
credentials and advertises only `demo.status`; terminal enrollment is refused even
with a controlling TTY. This restriction does not remove the production bridge's
closed, grant-controlled service operations.

The native form necessarily holds the credential briefly in app memory and sends
it to the authenticated broker over the administrative XPC connection. It clears
the form after submission. The broker's private encrypted file Keychain stores
explicitly enrolled credentials. It does not import the user's existing Apple
Passwords collection. The production design requires a separate broker UID and
restrictive filesystem ownership; installation under that UID remains unverified.

The private Keychain's random unlock seed is a broker-owned file. Consequently,
filesystem/process isolation is part of the security boundary: encryption alone
does not protect against an actor able to read both the database and its seed.
Root, a compromised OS or compromised trusted broker is outside that boundary.

The human app's approval signing key is separate from service credentials. Release
code requires user presence and a protected, nonextractable key. A matching Apple
provisioning profile and an actual signed protected-key test are still required.
Agent Vault does not learn or store the Mac unlock password. The signer first tries
a Secure Enclave approval key, then a nonextractable, user-presence-protected Keychain
key. It fails closed if neither backend works. Actual selected-backend verification
is still required; arbitrary stored service passwords are not held inside the enclave.

Human continuation can transiently relay an MFA code to its bound browser challenge.
That is not a persistent OTP vault. General TOTP generation, passkey-provider
integration and arbitrary website/PIN support are not implemented.

## Agent authority and responses

An authenticated client may request only a closed action for an account authorized
by a current grant. The broker owns expiry, revocation, budgets and audit state.
Agents cannot select an arbitrary destination, execute scripts, evaluate JavaScript,
retrieve passwords, read cookies/storage or export an authenticated session.

Browser credentials pass only to the authenticated fixed host after a fresh
authority check. Human challenges bind a connection, run, step epoch and frame;
stale input is refused. Ending or losing authority closes the owned context.
Production browser composition remains disabled pending deployment and egress proof.

Agent-visible results use closed schemas and sanitized failure codes. Audit events
record identifiers and decisions, not credential contents or credential hashes.
Typed schemas alone cannot prevent a malicious trusted service from reflecting a
secret into an otherwise allowed result. The service adapter and approved origin
remain trusted, and their output needs dedicated adversarial validation.

## Evidence required before release

Synthetic canaries must traverse actual broker, XPC, host and MCP boundaries. Checks
must name every observed channel, fail if required observations are absent, and
demonstrate detection with deliberate leak controls. A passing string scan is
bounded evidence, not proof against every encoding, memory disclosure or side channel.
Use generated synthetic credentials only; never test with a real account password.

Release additionally requires actual protected-key/user-presence signing, installed
dedicated-UID isolation, signed browser topology and whole-process egress tests,
service-specific validation, recovery/upgrade verification and notarization. Apple
notarization checks signing and malicious content; it is not an independent security
audit. Independent assessment and a vulnerability reporting process are needed before
making assurance claims comparable to established password managers.

OAuth with narrowly scoped tokens and hardware-backed/passkey assertions are future
directions. They must preserve the same operation-only contract; exposing a reusable
token or session to an agent would weaken it.
