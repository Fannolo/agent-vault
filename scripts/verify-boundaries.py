#!/usr/bin/env python3
"""Check the package graph, rather than source naming, for secret-store boundaries."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    package = json.loads(subprocess.run(["swift", "package", "describe", "--type", "json"], cwd=ROOT,
                                        check=True, capture_output=True, text=True).stdout)
    targets = {target["name"]: set(target.get("target_dependencies", [])) for target in package["targets"]}
    kinds = {target["name"]: target["type"] for target in package["targets"]}

    def closure(name):
        assert name in targets, f"Missing required target: {name}"
        found, todo = set(), [name]
        while todo:
            node = todo.pop()
            if node in found:
                continue
            found.add(node)
            todo.extend(targets.get(node, []))
        return found

    for target in ("AgentVaultBridge", "AgentVaultApp", "AgentVaultAppSupport"):
        assert "AgentVaultCore" not in closure(target), f"{target} must not link the secret store"
    assert "AgentVaultBrowser" not in targets and "AgentVaultBrowserTests" not in targets, "the legacy WebKit engine must stay removed"
    assert "AgentVaultBrowserFixture" in targets, "retain the browser-independent synthetic fixture"
    # The credential-bearing web host wire stays with the broker daemon's link and the host.
    for target in ("AgentVaultCore", "AgentVaultContracts", "AgentVaultBridge", "AgentVaultMCPBridge",
                   "AgentVaultApp", "AgentVaultAppSupport", "AgentVaultCLI", "AgentVaultRuntime", "AgentVaultIPC"):
        assert "AgentVaultWebHostProtocol" not in closure(target), f"{target} must not link the credential-bearing host wire"
    assert {"AgentVaultCore", "AgentVaultWebHostProtocol"} <= closure("AgentVaultWebHostLink")
    product_targets = [name for name, kind in kinds.items() if kind != "test"]
    for target in product_targets:
        if target != "AgentVaultWebHost":
            assert "AgentVaultWebHost" not in closure(target), f"{target} must reach the web host only over IPC"
        if target in ("AgentVaultWebHostLink", "AgentVaultBrokerDaemon"):
            continue
        assert "AgentVaultWebHostLink" not in closure(target), f"{target} must not link the broker's host link"
    # The web host owns the browser but never the secret store, the broker's link or WebKit.
    host = closure("AgentVaultWebHost")
    for forbidden in ("AgentVaultCore", "AgentVaultWebHostLink", "AgentVaultRuntime"):
        assert forbidden not in host, f"AgentVaultWebHost must not link {forbidden}"
    assert kinds["AgentVaultWebHost"] == "executable", "the web host must be a separate executable"
    assert "AgentVaultMCPTransport" in closure("AgentVaultBridge"), "Bridge must bound input before SDK decoding"
    assert {"AgentVaultCore", "AgentVaultIPC", "AgentVaultRuntime"} <= closure("AgentVaultBrokerDaemon")
    print("PASS: package graph preserves broker, app and MCP bridge boundaries")


if __name__ == "__main__":
    main()
