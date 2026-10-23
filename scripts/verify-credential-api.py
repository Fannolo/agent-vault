#!/usr/bin/env python3
"""Compile real public API probes after the root package has been built."""
import importlib.util
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("credential_api_owned", ROOT / "scripts/verify-webhost-link-mutations.py")
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)

PROBES = (
    ("public_control", 'import AgentVaultCredentials\nimport Foundation\n'
     'let c = WebLoginCredential(Data("synthetic-user\\nSYNTHETIC-only".utf8))\nlet same = c == c\n', None),
    ("contracts_no_credential", 'import AgentVaultContracts\nlet c: WebLoginCredential? = nil\n',
     "cannot find type 'WebLoginCredential'"),
    ("no_password_property", 'import AgentVaultCredentials\nfunc f(_ c: WebLoginCredential) { _ = c.password }\n',
     "has no member 'password'"),
    ("no_public_reveal", 'import AgentVaultCredentials\n'
     'func f(_ c: WebLoginCredential) { c.withCanonicalBytes { _ in } }\n',
     "inaccessible due to '@_spi' protection level"),
    ("no_login_reveal", 'import AgentVaultCredentials\n'
     'func f(_ c: WebLoginCredential) { c.withLoginBytes { _, _ in } }\n',
     "inaccessible due to '@_spi' protection level"),
    ("no_username_property", 'import AgentVaultCredentials\nfunc f(_ c: WebLoginCredential) { _ = c.username }\n',
     "has no member 'username'"),
    ("no_bytes_property", 'import AgentVaultCredentials\nfunc f(_ c: WebLoginCredential) { _ = c.bytes }\n',
     "has no member 'bytes'"),
    ("no_storage_access", 'import AgentVaultCredentials\nfunc f(_ c: WebLoginCredential) { _ = c.storage }\n',
     "inaccessible due to 'private' protection level"),
)


def main():
    code, _ = owned.run_owned(["swift", "build", "--target", "AgentVaultCredentials", "--force-resolved-versions"],
                              timeout=300, cwd=ROOT)
    if code:
        raise SystemExit("credential_api_build_failed")
    code, output = owned.run_owned(["swift", "build", "--show-bin-path"], timeout=30, cwd=ROOT)
    if code:
        raise SystemExit("credential_api_build_path_unavailable")
    binary = Path(output.strip())
    with tempfile.TemporaryDirectory(prefix="av-credential-api-") as directory:
        source = Path(directory) / "Probe.swift"
        for name, text, diagnostic in PROBES:
            source.write_text(text)
            code, output = owned.run_owned([
                "swiftc", "-typecheck", "-I", str(binary / "Modules"),
                "-I", str(binary / "CSecretMemory.build"), str(source),
            ], timeout=30, cwd=ROOT)
            if diagnostic is None:
                passed = code == 0
            else:
                passed = code != 0 and diagnostic in output
            if not passed:
                raise SystemExit("credential_api_probe_failed: " + name)
    print("PASS: agent contracts and normal credential imports cannot reveal login fields")


if __name__ == "__main__":
    main()
