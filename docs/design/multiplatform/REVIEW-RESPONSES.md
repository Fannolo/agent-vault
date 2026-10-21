# Portable codec review responses

21 October 2026. Scope: the standalone synthetic AVSEAL01 codec and its verification
drivers. Initial reviewed package digest: `476cd5dbc83817e8b8df0476a03957498b313d83482f21f87412b8f21ee5e1c6`.
This is a development review record, not production approval or security certification.

## Intent and reviewers

Provide the first portable encrypted-record component for native macOS and Linux password
managers. Future enrolled clients decrypt locally; agents and cloud storage must not gain
password retrieval APIs. This unit implements no enrollment, cloud service or agent bridge.

Grok 4.7 reviewed the first codec and actual Mac/Linux evidence. It found no codec blocker
and two Low issues. Opus 5.5 independently reviewed that source, evidence and the existing
Mac app integration. It found one latent Medium recipient-key validation gap, further
hardening/test gaps and explicit future-product blockers. Both verified the bounded codec
claims; neither accepted the complete product for production.

## Act on in the correction unit

| Finding | Reviewer | Response |
|---|---|---|
| Low-order X25519 recipient/encapsulation keys | Opus F1 | Reject invalid agreement keys at the typed boundary and before HPKE open. Both have regressions on both platforms. The executed removal control covers the recipient initializer; open-side removal remains a follow-up on Linux. |
| Ed25519 S+L rejection not tested | Opus F2 | Add rejected-open/rejected-log regression on both cryptographic backends. |
| Caller Data slice retained by log | Grok Low 1; Opus test gap | Copy accepted record bytes; test nonzero-start slices for open, insert, duplicate and conflict. |
| UTF-8/BOM roundtrip untested | Opus F6 | Preserve exact UTF-8 bytes and add BOM regression on both platforms. |
| Persistent Data copy of the data key | Opus F5 | Seal each envelope inside the symmetric key's scoped byte closure. No memory-erasure guarantee. |
| Original Docker error overwritten by cleanup | Grok Low 2 | Keep primary failure; report cleanup and source-check failures separately, including cleanup exceptions. Regression tests cover failed create, failed cleanup and wrong corrupt-record failure. |
| Corrupt exchange accepted on any nonzero exit | Opus verifier gap | Require the signature-error marker from the named fixture test; unrelated build failures cannot satisfy the check. |
| Weak control placement and missing controls | Opus evidence gap | Plant plaintext logging inside library open; add context, role binding, order and low-order-check removals; run unmutated targeted baselines and compiled mutants on Mac and Linux. |
| Runtime versions entered by hand | Opus evidence gap | Capture Swift, OS, architecture and pinned image metadata in the runner. |
| Synthetic fixture permissions | Opus evidence gap | Restrict exchanged fixture files to mode 0600 inside private evidence directories. |

Correction source digest: `8d2470defaadd67e255535186c35d876fc80f932a647e4eb83a449f8cf29f076`.
Fresh execution passes 21 tests on each platform, both directions of ciphertext exchange,
12 compiled defense-removal controls, nine verifier tests and a deliberately reintroduced
cleanup-overwrites-primary regression. Original package source stayed unchanged, owned
containers were removed and owned mutation copies were restored. The updated
[verification record](../../verification/portable-codec-v1.json) retains initial evidence
as history. Opus 5.5 and Grok 4.7 independently accepted this exact corrected package and
the recorded evidence, with no new blocker for the bounded fixture-only unit.

The correction's native experiment resolved the platform uncertainty: CryptoKit rejected
unchecked HPKE with a low-order recipient (`underlyingCoreCryptoError -7`). The pinned
Linux implementation permits the unchecked primitive. The Mac witness therefore models
unchecked zero-DH wrapping explicitly; the Linux witness uses the actual pinned HPKE
sender. The deliberate-removal control removes the typed recipient initializer check,
so native backend rejection cannot conceal loss of that boundary validation.

## Explicit format and scope decisions

Opus F3/F4: defer explicit data-key commitment and padding to a reviewed successor format.
Version 1 remains fixture-only. Real-password persistent storage and cross-user sharing
are blocked on that format gate. Length and public-metadata leakage are now documented.
A commitment does not stop an authorized writer refusing a recipient a working wrap.

Opus F5: a public plaintext password property is currently part of a trusted-service library,
not a public agent API. Defer a redacted secret wrapper/scoped-access interface to service
integration, and make it a gate before exposing the library to adapters. A wrapper alone
does not prevent trusted code reading bytes or guarantee erasure.

Define parents as SHA256 of full canonical encoded parent records, including signatures.
Defer the digest API and actual parent/membership/checkpoint validation to the next unit.
Add authenticated deletion/tombstones there. Assign cross-user sharing its own delivery
unit, separate from syncing one user's enrolled devices.

## Retained limitations

Follow-up review notes: add the Linux-only open-side validation removal control and an
executable fixture-only dependency guard before the membership unit. That unit must match
every envelope key to admitted validated members. Before multiwriter use, compare broader
Ed25519 edge-case vectors across backends. Platform design must distinguish software
Curve25519 keys from hardware-backed approval keys. Tighten the corrupt-record error marker
and bind the Python regression's exact verifier/test/log hashes in the next harness update.
The old package/control copies beside that Python-only regression are not its source proof.

The Linux build uses the pinned official image and pinned source revisions, but permits
dependency downloads; it is not a hermetic build. Output scanning checks specified synthetic
values in raw ASCII/hex/base64 representations. The owned runner decodes process output
as UTF-8 with replacement, so this is not a detector for arbitrary binary secrets or an
information-flow proof. Installed isolation, native Linux services/UI, membership, cloud
signup/sync, pairing/recovery, revocation, browser custody and external human assessment
remain separate unfinished units.
