# Agent Vault development

This is a development implementation with a Developer ID signed review bundle.
Keep README.md and docs/THREAT-MODEL.md aligned with measured evidence. Dedicated-UID
runtime isolation, real protected-key signing, production browser deployment and
notarization remain open gates. Do not claim production readiness or independent
security certification from unit tests, same-UID fixtures or model review.

Credentials and sessions must never be returned by an MCP tool. Do not add raw
secret retrieval, arbitrary execution, caller-supplied destinations, generic browser
evaluation, or credential content hashes to the public interface. Use closed action
types, runtime authorization on every call, and fixed service adapters.

Use synthetic accounts for tests. Native Keychain tests must use a unique test
namespace and delete only their own entries. Do not access existing user credentials.
Never print secret bytes, interpolate them into errors, or write them into the repo.

Run swift test and scripts/verify-mcp.py after changing core or MCP behavior.
State corruption, unavailable Keychain, missing grants and unknown inputs fail closed.
Keep actual verification and outstanding security work in docs/IMPLEMENTATION-PLAN.md.
