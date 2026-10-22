#!/usr/bin/env python3
"""Write deterministic CycloneDX metadata from the committed Swift lockfile."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    resolved = json.loads((ROOT / "Package.resolved").read_text())
    components = []
    for pin in sorted(resolved["pins"], key=lambda item: item["identity"]):
        state = pin["state"]
        components.append({
            "type": "library", "name": pin["identity"], "version": state.get("version", state["revision"]),
            "bom-ref": pin["identity"],
            "externalReferences": [{"type": "vcs", "url": pin["location"] + "/tree/" + state["revision"]}],
            "properties": [{"name": "swift:revision", "value": state["revision"]}],
        })
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"component": {"type": "application", "name": "Agent Vault", "version": "0.2.0"}},
                "components": components}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"Wrote inventory for {len(components)} pinned dependencies")


if __name__ == "__main__":
    main()
