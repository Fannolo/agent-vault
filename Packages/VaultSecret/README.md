# VaultSecret

Trusted-service secret buffer. Construction consumes a caller's mutable byte
array on success. Descriptions and mirrors are redacted. Scoped byte access requires the
`SecretReveal` SPI; no Codable, Equatable, Hashable or public raw-value property is provided.

The allocation is immutable after construction and cleared before deallocation. This does
not guarantee erasure of prior aliases, hidden runtime copies, swap or crash dumps. Trusted
code with scoped access can intentionally copy bytes; SPI is an architectural boundary,
not an OS security boundary.

Swift arrays use copy-on-write. If another array shares the input storage, clearing the
consumed array first creates a mutable copy; the other array remains unchanged. Callers
must not treat consumption as erasure of existing copies.

The development broker and private browser use this package through `AgentVaultCredentials`.
The old shared-contract credential with readable String fields is removed. Only the private
wire serializer and browser fill adapter import that wrapper's reveal SPI. A source/graph
guard checks those imports; it is maintenance protection, not protection from hostile code
with the same OS authority. `matches` is a trusted SPI comparison: length is observable;
equal-length comparisons read every byte without a content-dependent early return.

The existing web-login grammar still requires nonempty username and password fields. This
does not define the schema for future imported items with optional fields. Validation and
the current JSON/CDP serializer make transient Data/String copies; complete memory erasure
is not claimed. Tests use synthetic values only. The frozen VaultCore codec is unchanged.
