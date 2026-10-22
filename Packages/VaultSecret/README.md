# VaultSecret

Standalone trusted-service secret buffer. Construction consumes a caller's mutable byte
array on success. Descriptions and mirrors are redacted. Scoped byte access requires the
`SecretReveal` SPI; no Codable, Equatable, Hashable or public raw-value property is provided.

The allocation is immutable after construction and cleared before deallocation. This does
not guarantee erasure of prior aliases, hidden runtime copies, swap or crash dumps. Trusted
code with scoped access can intentionally copy bytes; SPI is an architectural boundary,
not an OS security boundary.

Swift arrays use copy-on-write. If another array shares the input storage, clearing the
consumed array first creates a mutable copy; the other array remains unchanged. Callers
must not treat consumption as erasure of existing copies.

The package is not yet linked to any product. Replacing existing credential types and
enforcing the trusted reveal-import allowlist are separate integration work. Its tests
use synthetic values only. This package does not change the frozen VaultCore codec.
