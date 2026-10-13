# Agent Vault development

This is an early local development prototype. Keep the security claim in README.md
and docs/THREAT-MODEL.md aligned with the code. Do not describe the prototype as an
isolated, signed or audited credential broker.

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
