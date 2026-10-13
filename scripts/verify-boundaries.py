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
    assert "AgentVaultBrowser" not in closure("AgentVaultBrokerDaemon"), "Headless production daemon cannot present a human WebKit view"
    assert "AgentVaultMCPTransport" in closure("AgentVaultBridge"), "Bridge must bound input before SDK decoding"
    assert {"AgentVaultCore", "AgentVaultIPC", "AgentVaultRuntime"} <= closure("AgentVaultBrokerDaemon")
    print("PASS: package graph preserves broker, app and MCP bridge boundaries")


if __name__ == "__main__":
    main()
