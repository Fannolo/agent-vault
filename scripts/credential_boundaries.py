"""Architectural credential boundary. This is a maintenance guard, not a sandbox."""
import re


REVEAL_IMPORTS = {
    "SecretReveal": {"Sources/AgentVaultCredentials/WebLoginCredential.swift"},
    "CredentialUse": {"Sources/AgentVaultWebHostProtocol/HostWire.swift", "Sources/AgentVaultWebHost/WebRun.swift",
                      "Sources/AgentVaultWebHost/SiteSession.swift"},
}


def check_credentials(root, targets, records=()):
    paths = set((root / "Sources").rglob("*.swift"))
    for record in records:
        if record["type"] == "test":
            continue
        if "VaultSecret" in record.get("product_dependencies", []) and record["name"] != "AgentVaultCredentials":
            raise SystemExit("credential_storage_dependency_forbidden: " + record["name"])
        for source in record.get("sources", []):
            if source.endswith(".swift"):
                paths.add(root / record["path"] / source)
    for path in paths:
        if not path.resolve().is_relative_to(root.resolve()):
            raise SystemExit("credential_source_outside_root")
        relative = path.relative_to(root).as_posix()
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent.is_relative_to(root)):
            raise SystemExit("credential_source_symlink")
        source = path.read_text()
        for spi, allowed in REVEAL_IMPORTS.items():
            if spi == "CredentialUse" and relative == "Sources/AgentVaultCredentials/WebLoginCredential.swift":
                # This module declares the SPI; it does not import its own reveal API.
                continue
            if re.search(r"@\s*_spi\s*\(\s*" + spi + r"\s*\)", source) and relative not in allowed:
                raise SystemExit("credential_reveal_import_forbidden: " + relative)
        if re.search(r"\bimport\s+(?:(?:typealias|struct|class|enum|protocol|let|var|func)\s+)?VaultSecret\b", source) and relative not in REVEAL_IMPORTS["SecretReveal"]:
            raise SystemExit("credential_storage_import_forbidden: " + relative)

    for name in ("AgentVaultContracts", "AgentVaultBridge", "AgentVaultMCPBridge", "AgentVaultApp",
                 "AgentVaultAppSupport", "AgentVaultIPC", "AgentVaultRuntime"):
        seen, todo = set(), [name]
        while todo:
            current = todo.pop()
            if current in seen:
                continue
            seen.add(current)
            todo.extend(targets.get(current, []))
        if "AgentVaultCredentials" in seen:
            raise SystemExit("credential_target_forbidden: " + name)
