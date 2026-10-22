# Native multi-platform vault: grounding, 21 October 2026

Current implementation base: `2d393f6`, Swift 6.2, macOS 14+. The current app and broker
use Apple Security, AppKit/SwiftUI, XPC, code-signing/UID peer authentication and an
explicit separate file Keychain. It is a signed development review bundle, not notarized
or an installed production boundary. Core is not Linux-ready just because it is Swift:
its platform frameworks and process identity assumptions require adaptation.

Current MCP exposes fixed actions only. Browser code privately owns Chromium/CDP and
human challenges but terminates after a fixed operation; production BrokerMain composes
no web host. The accepted future direction is generic approved-site operation, broad
account effects included, with private authentication and no raw service secret returns.
See ../approved-site-browser/GROUNDING.md and DESIGN.md for source anchors and reviewed
future browser ownership. That review did not assess cloud synchronization or Linux.

New explicit user requirement: native equivalent functionality on Linux and macOS;
each device runs its own vault and authentication/browser host. It must not require a
Mac to relay a Linux agent. Cloud signup/login and secure password synchronization or
sharing connect devices. User emphasis: cloud handling must be secure, passwords must
not appear in model/chat/terminal/argv/env/logs; free/open-source multi-platform manager
usable by agents. Cross-user sharing can be staged distinctly from own-device sync.

Cloud authentication is not vault decryption. A server account session must not authorize
raw plaintext extraction. Server compromise, malicious account recovery, device additions,
revocation and compromised endpoints need explicit limits and independent tests. Do not
invent a claim that password changes or remote revocation erase previously decrypted data.
Do not build custom cryptographic primitives or claim 1Password parity from AI review.

Repository integration: keep the existing macOS implementation unchanged while introducing
one portable core/protocol in an isolated unit. Define the migration rather than quietly
shipping two conflicting vault formats. Existing Apple Keychain entries are not queried.
No real secrets or production accounts are needed for synthetic tests. Docker is available
and reports Linux aarch64; native Rust toolchain is absent, Swift and Node are available.
Use actual Linux execution for portability claims, not compilation alone.

## Acceptance journey and forbidden shortcuts

1. Enroll account and trusted devices in native UI. Cloud signup/login is separate from
   giving a device vault keys. A newly logged-in device cannot self-authorize decryption.
2. Synchronize encrypted records from one enrolled macOS client to an enrolled Linux
   client. Demonstrate each can run independently; no Mac relay and no plaintext server log.
3. Agent sees an owned Amazon-like fixture tab logged out, discovers only account metadata
   it may see, asks permission, receives a deny/pending/authorized outcome, and requests
   private authentication bound to that exact browser/origin/document. Agent gets result,
   not password bytes. A different tab/origin/client cannot replay the authorization.
4. Native human challenge completes privately. Agent resumes permitted website operation.
   Lack of a human presence/approval path on headless Linux must fail closed, not read a
   password from terminal/env or assume a standard desktop keyring protects from same UID.
5. Kill or revoke the device/session. Stop new authority, report uncertain remote effects,
   and explain old decrypted/cached data cannot be remotely erased by key revocation.

Synthetic negative tests must cover modified ciphertext/AAD, copied records between users,
wrong key, revoked or unapproved device, stale membership, cloud key substitution, oversized
or malformed records, retry conflicts, and absence of plaintext in server-visible bytes or
public debug/error formatting. The exact replay/rollback claim must distinguish a pinned
existing device from a fresh/recovered device without prior trusted state. Evidence must
name what is not implemented; a crypto-library test is not signup/UI/cloud deployment proof.
