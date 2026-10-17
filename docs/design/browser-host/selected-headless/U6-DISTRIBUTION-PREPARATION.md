# U6 distribution preparation

Status: preparation only, 15 October 2026. This unit does not complete U6 or any P0–P4 gate.
It changes no production composition, enrollment flag, installed configuration, existing
release bundle format or default installer role list. It downloads, signs, installs and
launches nothing. The checked-in browser pin is deliberately **unconfigured**.

## Concrete unit and ordering

`scripts/prepare-webhost-release.py` stages explicitly supplied local artifacts into a new,
private, **noninstallable** review directory. Its `verify` command rechecks that directory
against a manifest SHA-256 retained outside it. Both refuse root. Only the existing
installer's read-only `CodeInspector`, requirement builder and descriptor-based file/rename
primitives are reused; no account or launchd adapter is constructed.

The ordering dependencies remain:

1. U5 joins the real host, broker and human continuation, with the legacy path removed.
2. A separately authorized P0 VM run determines the exact workable signed browser/host
   entitlement policy and topology. This unit chooses no entitlements and contains no
   re-sign command. Review the source acquisition and signing transformation before pinning
   the resulting tree. A mere downloaded CfT shell or a cached test executable is insufficient.
3. The operator supplies the reviewed inputs below. The preparation tool validates their
   consistency and actual signatures; it does not authenticate their historical claims.
4. Future U6 work implements reviewed account allocation, protected deployment and retryable
   host installation/removal, upgrades and recovery. The current installer remains unchanged.
5. Installed P0–P3, whole-process egress confinement and protected human signing must pass
   before browser composition is enabled. P4 and a separate user instruction gate live GitHub.
   Notarization, distribution provenance and target-host compatibility remain separate gates.

## Inputs and what is checked

All inputs are explicit paths; there is no cache discovery, network client, automatic pin
refresh, signing identity lookup or implicit use of the user's Chrome installation.

| Input | Validation |
|---|---|
| `--host`, `--host-sha256` | Copy through an opened, non-following descriptor. Inspect the staged bytes, requiring exact `dev.agentvault.webhost`, Bite team `3JWAQ92CB4`, hardened runtime, a valid pinned Developer ID requirement, no debugger access and the supplied exact entitlement dictionary. Require an executable file and the separately supplied full SHA-256. |
| `--browser` | Copy a complete signed tree through descriptors. Refuse links, FIFOs, special files, hardlinks and excessive bytes/entries/depth. Normalize regular modes to 0644/0755. Compare every file's digest and executable bit to the reviewed pin. Detect every Mach-O file, including nonexecutable dylibs, and require the exact code inventory. Refuse executable non-Mach-O files. Inspect every native code file with the existing CodeInspector; main ID is `dev.agentvault.chromium`, helper IDs belong to that separate prefix. An ad hoc signature cannot satisfy the Bite requirement. |
| `--archive` | Copy the bounded original ZIP into an anonymous private snapshot, then hash and parse that exact snapshot against the pin. Bound expanded sizes and entries; reject duplicate, unsafe, outside-root, encrypted and special entries. Require the same resource/code paths apart from generated `_CodeSignature` records, and unchanged non-code resource bytes. No archive is extracted or executed. Signing can change native code bytes, so those changes remain a separately reviewed transformation pinned by the signed-tree hashes. |
| `--pin` | Default `deploy/webhost/chromium.pin.json` refuses packaging until configured. Configured pins have an exact schema: version/platform, fixed official CfT URL, source archive SHA-256, signed-tree files/code inventories and exact P0 report/policy hashes. Platform is limited to `mac-arm64`, matching the current host path. No version or fake digest is invented in this commit. |
| `--stable-metadata`, `--metadata-receipt` | Receipt must name the fixed official metadata URL and hash the exact supplied JSON. Its declared retrieval must be within 24 hours, not in the future. The upstream document's timestamp must be no more than seven days before that declared retrieval. The pin must equal the one supplied Stable `mac-arm64` headless-shell version and URL. Duplicate JSON keys are rejected at every depth. This is an **offline supplied-freshness check**, not independent proof of current upstream state. |
| `--p0-policy`, `--p0-report` | Both must match the pin's SHA-256 values; policy also binds the report digest and names exact host and every browser code entitlement dictionary. Missing inputs fail with a prerequisite error. A JSON `approved` flag is not part of the schema. Matching a report hash is not proof that its claimed VM run occurred or that its conclusions are correct. |
| `--broker-config`, `--host-uid` | Parse the exact existing production configuration shape, refusing duplicate keys. Reuse the installer's exact pinned role requirements. Require three distinct non-root integer UIDs and nonaliased host/browser/base-role hashes. Candidate UID allocation is a proposal, not a directory-service lookup or an account reservation. |

This tool does **not** use the base installer's empty-entitlement-only browser policy: no
browser is added to that installer. Instead, it compares each actual signature with the
explicit byte-pinned operator-supplied P0 policy, preserving plist types (for example `true`
cannot equal integer `1`). That comparison is not an endorsement of an entitlement or a P0
approval. Any nonempty policy still needs independent review of the actual measured report.

## Input formats

The configured pin has these exact keys; placeholders below are intentionally not valid pins:

```json
{
  "format": "agent-vault-chromium-pin-v1",
  "platform": "mac-arm64",
  "version": "<reviewed four-part version>",
  "archiveURL": "https://storage.googleapis.com/chrome-for-testing-public/<version>/mac-arm64/chrome-headless-shell-mac-arm64.zip",
  "archiveSHA256": "<64 lowercase hex>",
  "files": {
    "chrome-headless-shell": {"sha256": "<signed file hash>", "executable": true},
    "<every other relative file>": {"sha256": "<file hash>", "executable": false}
  },
  "code": {
    "chrome-headless-shell": {"identifier": "dev.agentvault.chromium", "cdhash": "<40 lowercase hex>"},
    "<every other Mach-O file>": {"identifier": "dev.agentvault.chromium.<reviewed role>", "cdhash": "<40 lowercase hex>"}
  },
  "p0PolicySHA256": "<exact policy file hash>",
  "p0ReportSHA256": "<exact local report hash>"
}
```

Receipt: `format = agent-vault-cft-metadata-receipt-v1`, `sourceURL` equal to
`https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json`,
`retrievedAt` as a UTC ISO timestamp, and `sha256` of the supplied raw metadata file.
These four keys are exact. A trusted operator must establish actual acquisition provenance;
rewriting an offline receipt's time cannot establish freshness.

Policy: exact keys `format = agent-vault-webhost-entitlements-v1`, `reportSHA256`, `host`
(an entitlement dictionary) and `browser` (relative code paths mapped to exact entitlement
dictionaries). The script does not create this policy or infer it from cached signatures.

## Output and installer boundary

```text
AgentVaultWebHost
chrome-headless-shell-mac-arm64/...
deployment/webhost.json.disabled
deployment/dev.agentvault.webhost.plist.disabled
deployment/install-plan.json
evidence/{chromium.pin.json,stable-metadata.json,metadata-receipt.json,
          p0-entitlements.json,p0-report.txt,broker-config.json}
sbom.cdx.json
PREPARATION-ONLY.txt
manifest.json
```

The disabled host configuration matches `WebHostConfiguration`'s seven fields and binds the
exact host/broker requirements and all three UIDs. The candidate plist uses `_agentvaultweb`,
private data `/private/var/db/agent-vault-web`, fixed service `dev.agentvault.webhost` and host
`/Library/AgentVault/WebHost/AgentVaultWebHost`. The browser sits beside that host at the exact
relative path `HostLaunch.production` expects. The plan compares these roles and names; it
contains no commands and records `account.create = false`, `installable = false`,
`browserEnabled = false` and every P0–P4 gate unverified. Candidate files have `.disabled`
suffixes, and neither the base installer nor production broker consumes this directory.

CycloneDX inventories the host's exact hash, the browser's original archive URL/hash and a
separate signed-tree inventory hash. The archive hash is an external distribution reference,
not falsely labeled as the digest of re-signed code. The source archive itself is not copied.
`manifest.json` records every other file's digest, executable bit and mode. Stage prints its
hash; retain that separately for review. Verification rechecks actual signatures, exact
bytes/modes, supplied freshness and the regenerated disabled deployment plan. An edited
payload cannot authenticate itself with its own edited manifest.

Example after all local inputs have independently been reviewed:

```sh
python3 scripts/prepare-webhost-release.py stage \
  --host /reviewed/AgentVaultWebHost --host-sha256 <reviewed-sha256> \
  --browser /reviewed/chrome-headless-shell-mac-arm64 \
  --archive /reviewed/chrome-headless-shell-mac-arm64.zip \
  --pin /reviewed/chromium.pin.json \
  --stable-metadata /reviewed/stable.json --metadata-receipt /reviewed/receipt.json \
  --p0-policy /reviewed/p0-entitlements.json --p0-report /reviewed/p0-report.txt \
  --broker-config /reviewed/broker-config.json --host-uid <candidate-private-uid> \
  --output dist/AgentVault-webhost-preparation

python3 scripts/prepare-webhost-release.py verify \
  --payload dist/AgentVault-webhost-preparation \
  --manifest-sha256 <separately-retained-review-hash>
```

Staging and verification require canonical directory ancestry owned by root or the
operator, without group/other write permission except protected sticky directories.
macOS extended ACL entries are conservatively refused, including harmless deny entries;
an unavailable ACL inspection also refuses. Parent and staging descriptors remain open
through exclusive publication. Path identity checks refuse observed ancestry changes.
These rules exclude other-user pathname substitution; they do not isolate this tool from
malicious processes running as the operator or root. If ancestry changes at publication,
the command refuses and may leave the inspected payload under the relocated original
parent; it does not publish an uninspected substitute or replace an existing output.

Keep generated payloads and local signing/P0 evidence in ignored `dist/` or another private
location. The public commit contains only code, synthetic fixtures and the unconfigured pin.

## Evidence and remaining limits

Verified here: 33 tests using synthetic artifacts in isolated Python and with `-O`;
bytecode syntax, CLI help and diff whitespace checks. Tests use explicit fake Mach-O bytes and a byte-keyed
fake inspector; they do not sign or run native code. They exercise staged-copy identity
checks, failures across archive/pin/policy/metadata/role inputs, hardlinks/symlinks/FIFOs,
tampering, permission changes, exact entitlement types, output preservation, duplicate keys,
read-only revalidation and unchanged three-role base installer policy. Five additional
race/ancestry controls cover source mutation after archive hashing, resource substitution,
writable ancestry, and ancestor swaps before/at publication. A native ACL test grants
write access only on its synthetic temporary directory and verifies refusal. Five of the
new controls reject the original unfixed implementation; the additional observed swap
control also passes its existing fail-closed behavior. Existing CodeInspector native
parsing evidence belongs to the earlier installer/release record; it was not rerun.

Official sources checked on 15 October 2026:

- [CfT's official endpoint and platform documentation](https://github.com/GoogleChromeLabs/chrome-for-testing#json-api-endpoints)
  documents Stable-channel download metadata and `chrome-headless-shell` on `mac-arm64`.
- [The official metadata endpoint](https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json)
  supplies versions and download URLs. This unit does not treat a local SHA-256 as an upstream
  signature or invent a digest from that metadata.
- [Chrome's CfT documentation](https://developer.chrome.com/docs/automation-and-testing/chrome-for-testing)
  describes a versioned automation/testing product without auto-update. It does not establish
  suitability or confinement for this security-sensitive daemon use.

No browser version was selected, downloaded, re-signed or notarized. No P0 policy or matching
real signed-tree pin exists in this unit. Offline receipt authenticity, source/signing
transformation provenance, metadata recency relative to the real upstream, architecture and
installed runtime compatibility, renderer and whole-process sandbox/egress, private UID/process
isolation and actual human signing are unproved. A valid Bite signature establishes publisher
identity for the inspected bytes; it proves none of those runtime claims. All manifest proof
flags therefore stay false even when supplied inputs pass consistency checks.

Proposed parent-owned documentation update: list this as a **U6 preparation unit**, link this
note, and keep the implementation plan, deployment/threat-model gates and release readiness
status open. No recorder, mutation helper, shared audit or primary project document was edited.
