# Deterministic parser corpus

Run `swift test --force-resolved-versions --scratch-path /tmp/agent-vault-fuzz-build -j 4 --filter AgentVaultParserFuzzTests`.
The target calls only in-memory IPC codecs, the MCP JSON validator, and GitHub profile
decoding. It uses synthetic bytes and does not open Keychain, sockets, browser profiles,
or network sessions.

Six seeded tests each run 512 iterations. The request byte mutation test has one input
per iteration; the other five have one accepted control and one mutated input. This is
5,632 generated inputs, plus 95 explicit grammar, type and size/count boundary controls
(5,727 input cases total on a passing run).
SplitMix64 seeds are fixed in `FuzzCorpus.swift`; failures include the seed, iteration,
mutation, byte length, escaped input prefix and Base64 prefix. Replay the same test and
seed to reproduce a case. Corpus generation and mutations are bounded.

The rejection properties cover missing/null/nested fields, operation policy expansion,
literal and escaped aliases for duplicate fields, malformed UTF-8/JSON, ambiguous
envelopes, unsafe logins and excessive MCP nesting. Accepted controls exercise Unicode,
JSON escapes/numbers, every IPC operation, permitted upstream extras, and limits on both
sides of a boundary. For byte mutations, acceptance is allowed only if the resulting
request preserves its semantic fields on a typed round trip, reply values remain bounded, the
GitHub output has exactly its two public fields, or MCP input is independently parsed
by Foundation as an object. The generators do not reproduce production parser logic.

MCP tests target the JSON validator, whose job is syntax, ambiguity, depth and numeric
request-ID spelling. Envelope authorization, framing, queues and rate limits remain
covered by their transport tests. These bounded deterministic cases are regression
evidence, not exhaustive coverage or security certification.
