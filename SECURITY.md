# Security policy

Agent Vault 0.1 is a development prototype. Use synthetic credentials only.
The [threat model](docs/THREAT-MODEL.md) documents missing isolation and authentication.

Report vulnerabilities privately using GitHub's **Report a vulnerability** action
on this repository when it is enabled. Do not put credentials, exploit secrets or
private account evidence into public issues. Public issues are appropriate for
general design questions and non-sensitive bugs.

No response-time commitment, security certification or supported production release
is promised at this stage. Keychain storage does not make a same-user MCP process
an isolation boundary.

The [authentication protocol draft](docs/AUTHENTICATION-PROTOCOL.md) defines native-only
credential entry and operation-only agent access. Synthetic leakage tests and model reviews
provide bounded evidence; they are not an independent audit or a claim of parity with
established password managers. Production browser access remains disabled.
