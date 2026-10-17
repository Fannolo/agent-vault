# Agent Vault seeded parser fuzz verification

Recorded: 2026-10-13T18:04:45.167881+00:00
Source checkpoint: `7e255123ea675016ccc0bc4e27c51d4ecda0f7f7` with uncommitted test additions and parent-owned shared JSON guard changes.

Command: `swift test --force-resolved-versions --scratch-path /tmp/agent-vault-fuzz-build -j 4 --filter AgentVaultParserFuzzTests`

**Final result: PASS, all 9 tests, exit 0.** Final log: `/tmp/agent-vault-parser-fuzz-final.log`. Swift Testing reported 0.376 seconds of test execution, after a 7.70-second incremental build. The selected XCTest compatibility runner reports zero tests separately; the nine executed cases are Swift Testing tests.

Executed budget: six fixed-seed tests × 512 iterations, with accepted/mutated pairs in five streams = 5,632 generated input cases, plus 95 explicit accepted/rejected grammar, type and byte/count controls = **5,727 input cases**. SplitMix64 generation and byte mutations are bounded. Each failure reports its seed, iteration, mutation, byte length, escaped input prefix and Base64 prefix.

| Stream | Seed |
| --- | --- |
| IPC request structure | `0x4950435f53484150` |
| IPC request bytes | `0x4950435f42595445` |
| IPC reply structure/bytes | `0x5245504c595f465a` |
| GitHub profiles | `0x474954485542465a` |
| MCP JSON/bytes | `0x4d43505f42595445` |
| MCP ambiguity/depth | `0x4d43505f53484150` |

## Defects reproduced and resolved by parent

Before the shared guard was added, the corrected second run had 7/9 tests pass and stopped two affected streams at their first reproducer:

1. Request seed `0x4950435f53484150`, case 0, literal duplicate field. `WireCodec.decodeRead` accepted `{"operation":"accounts","operation":"accounts"}`.
2. Reply seed `0x5245504c595f465a`, case 0, escaped duplicate envelope. `WireCodec.decodeReply` accepted `{"error":"busy","\u0065rror":"busy"}`. The initial corpus revision also accepted duplicate `snapshot` plus `\u0073napshot` with identical nested snapshot values.

Parent extracted the existing bounded syntax/depth/decoded-key validator into the Foundation-only AgentVaultJSON target, applied it before IPC and GitHub typed decoding, and preserved the MCP integral-request-ID spelling rule through an explicit mode. Final tests reject literal/escaped IPC duplicates, nested reply aliases, conflicting GitHub login/ID duplicates, and duplicate aliases in unknown upstream objects. Single escaped GitHub field names and normal profile controls are still accepted. No production source was modified by this worker.

The initial run also reported a test-oracle false positive on a valid UUID containing a lowercase hexadecimal letter. Codable uppercases UUID strings when encoding; the oracle now compares UUID identity while retaining all other semantic fields. The corrected second run proves the false positive was removed before production changes. The initial GitHub newline-anchor suspicion did not reproduce and is not treated as a defect.

## Source proof and scope

Read AGENTS.md, implementation contract, IPC wire documentation, current contract DTOs, schema-3 Package.resolved, WireCodec, JSONMessageValidator, GitHubAdapter, and existing narrow parser tests before adding this target. Assertions use generated known-good objects, guaranteed-invalid structural mutations, Foundation syntax/object parsing as an independent byte-mutation oracle, public output projections, and explicit contract bounds. Duplicate ambiguity tests are separate from Foundation dictionary parsing because Foundation collapses duplicates.

Controls cover every IPC operation; every snapshot collection count cap; request/reply/adapter body byte caps; credential, UID, grant, signature, challenge payload and nonce limits; unsafe login bytes and scalar types; extra upstream fields; Unicode/escapes; MCP numeric ID grammar and depth 64/65. Seeded structural mutations cover null/missing/nested fields, policy expansion, duplicate literal and escaped aliases, extra envelopes and invalid roots. Accepted mutated outputs are checked for typed bounds and semantic projection.

Only test files and the test-target entry were changed by this worker. Package.swift ownership was then released to the parent for shared-target dependencies. No Keychain operations, network calls, privileged installs, global configuration changes, business files, or commits. Dependency resolution used the local SwiftPM cache. Static GitHub decode is used; no GitHubAdapter session is initialized. MCP validator scope is syntax/ambiguity/depth/numeric ID spelling; existing transport tests retain framing and concurrency responsibility. This is bounded deterministic regression evidence, not exhaustive parser coverage or certification.

SHA-256 of final test artifacts, parser sources and local logs:

| File | SHA-256 |
| --- | --- |
| `Package.swift` | `6c811ff6485e47d6f689498d74b3affa087c8723396dc48b1c12bc2b4bb7c710` |
| `Tests/AgentVaultParserFuzzTests/FuzzCorpus.swift` | `5f790c98d3b9ff5c5ec68dd95d2ce5c75e064141819574efc2da960e67c19268` |
| `Tests/AgentVaultParserFuzzTests/GitHubParserFuzzTests.swift` | `b6b96b64a3dc14bb88a977c5f366d8f124dca991b19079737b831a6d69fe9214` |
| `Tests/AgentVaultParserFuzzTests/IPCParserFuzzTests.swift` | `ca4462fbcfd1d1475121ccf3247fc10781127e0523c83b578bcf6202a460a598` |
| `Tests/AgentVaultParserFuzzTests/MCPParserFuzzTests.swift` | `53eb142bbc8c9aa902889f8dd52882bdccf6242c9a9db678eb916afd5a21d98b` |
| `Tests/AgentVaultParserFuzzTests/README.md` | `54c32742d49b85978aad6dee7fb4f9abeb5effa08769be5fea1e9740ec049299` |
| `Sources/AgentVaultJSON/JSONObjectGuard.swift` | `3b8e23390c79e1c578c3885054dbb46050068a3da5c1608169f8bdeda32b83aa` |
| `Sources/AgentVaultIPC/WireCodec.swift` | `c6301eb158372379adcf6eb38a2eb40729a18d3c31730498a72af1e72356a222` |
| `Sources/AgentVaultMCPTransport/JSONMessageValidator.swift` | `4d34b81ca5ef4ca4861182d2cc579450ad040622d34edc7bb01369f3cf5ab697` |
| `Sources/AgentVaultCore/GitHubAdapter.swift` | `3bff6fe6cbd3d8eabe53975f499b4cda01a69b576d3aa40b9e967f530ee17fb8` |
| `Sources/AgentVaultContracts/Contracts.swift` | `6ed6883dd9d3cdc205acb43c7949b70705ac19e45add4608d599ad1354a073f1` |
| `Package.resolved` | `d6ae2d74b542049effc2a50eb14cba430acce47a836e0c97bba622e4453fbcb3` |
| `/tmp/agent-vault-parser-fuzz.log` | `8b3110e454b97802457a00070c2e46e274abaf5a7b50c846792256787f1f9bac` |
| `/tmp/agent-vault-parser-fuzz-second.log` | `398c6e62cf2f4b7f1e20eddbb42c7de8253952d4bd955b48e32f2c7e448d6ee1` |
| `/tmp/agent-vault-parser-fuzz-final.log` | `c727c02cfcfaca4c51bfc777cb014176621e6626f21fb567b8e69d0b7443dd2d` |
