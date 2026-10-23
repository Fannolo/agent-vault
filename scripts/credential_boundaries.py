"""Architectural credential boundary. This is a maintenance guard, not a sandbox."""
import re


REVEAL_IMPORTS = {
    "SecretReveal": {"Sources/AgentVaultCredentials/WebLoginCredential.swift", "Sources/AgentVaultCredentials/CloudAccessToken.swift"},
    "CredentialUse": {"Sources/AgentVaultWebHostProtocol/HostWire.swift", "Sources/AgentVaultWebHost/WebRun.swift",
                      "Sources/AgentVaultWebHost/SiteSession.swift"},
    "CloudTokenUse": {"Sources/AgentVaultCloud/SupabaseTransport.swift"},
}
# The one wrapper file that declares each reveal SPI; it may name only its own group.
REVEAL_DECLARATIONS = {
    "CredentialUse": "Sources/AgentVaultCredentials/WebLoginCredential.swift",
    "CloudTokenUse": "Sources/AgentVaultCredentials/CloudAccessToken.swift",
}
# Approved production consumers of the cloud transport. Every other non-test target is refused,
# including the CLI's MCP server, Core and any target added later.
CLOUD_CONSUMERS = {"AgentVaultBrokerDaemon"}


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
            if REVEAL_DECLARATIONS.get(spi) == relative:
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

    # Cloud sessions are held by the trusted service, never by its agent, browser, CLI or app roles.
    tests = {record["name"] for record in records if record["type"] == "test"}
    for name in sorted(set(targets) - tests - CLOUD_CONSUMERS - {"AgentVaultCloud"}):
        seen, todo = set(), [name]
        while todo:
            current = todo.pop()
            if current in seen:
                continue
            seen.add(current)
            todo.extend(targets.get(current, []))
        if "AgentVaultCloud" in seen:
            raise SystemExit("cloud_transport_target_forbidden: " + name)
