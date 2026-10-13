#!/usr/bin/env python3
"""Build an isolated Developer ID review bundle; never install or alter a host."""
import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TEAM = "3JWAQ92CB4"
APP = "dev.agentvault.app"


def run(*args, **kwargs):
    return subprocess.run(list(args), cwd=ROOT, check=True, **kwargs)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--provisioning-profile", type=Path)
    parser.add_argument("--review-only", action="store_true")
    args = parser.parse_args()
    if not args.provisioning_profile and not args.review_only:
        parser.error("a Developer ID provisioning profile is required; --review-only builds a non-distributable review artifact")
    profile = None
    if args.provisioning_profile:
        profile = plistlib.loads(run("/usr/bin/security", "cms", "-D", "-i", str(args.provisioning_profile.resolve()), capture_output=True).stdout)
        ent = profile.get("Entitlements", {})
        app_id = ent.get("com.apple.application-identifier", "")
        groups = ent.get("keychain-access-groups", [])
        require(TEAM in profile.get("TeamIdentifier", []) and "OSX" in profile.get("Platform", []), "wrong team or platform")
        require(fnmatch.fnmatch(TEAM + "." + APP, app_id), "profile does not authorize this app")
        require(any(fnmatch.fnmatch(TEAM + "." + APP, group) for group in groups), "profile does not authorize private Keychain access")
        require(not ent.get("get-task-allow") and not profile.get("ProvisionedDevices"), "development/ad hoc profiles are not distribution profiles")

    run("swift", "build", "-c", "release", "--force-resolved-versions", "-j", "4")
    binary_dir = Path(run("swift", "build", "-c", "release", "--show-bin-path", capture_output=True, text=True).stdout.strip())
    output = ROOT / "dist" / "AgentVault-review"
    if output.exists():
        if output.is_symlink():
            raise SystemExit("Refusing a symlink output directory")
        shutil.rmtree(output)
    app = output / "AgentVault.app"
    (app / "Contents/MacOS").mkdir(parents=True)
    (app / "Contents/Resources").mkdir()
    shutil.copy2(binary_dir / "AgentVaultApp", app / "Contents/MacOS/AgentVault")
    shutil.copy2(ROOT / "packaging/mac/Info.plist", app / "Contents/Info.plist")
    signed = [(app, APP)]
    for binary, identity in (("agent-vault-bridge", "dev.agentvault.bridge"), ("agent-vault-broker", "dev.agentvault.broker")):
        shutil.copy2(binary_dir / binary, output / binary)
        signed.append((output / binary, identity))
    entitlements = []
    if profile:
        shutil.copy2(args.provisioning_profile, app / "Contents/embedded.provisionprofile")
        entitlements_path = output / "app.entitlements.plist"
        entitlements_path.write_bytes(plistlib.dumps({
            "com.apple.application-identifier": TEAM + "." + APP,
            "com.apple.developer.team-identifier": TEAM,
            "keychain-access-groups": [TEAM + "." + APP],
        }))
        entitlements = ["--entitlements", str(entitlements_path)]
    for path, identifier in signed:
        run("/usr/bin/codesign", "--force", "--sign", args.identity, "--timestamp", "--options", "runtime",
            "--identifier", identifier, *(entitlements if path == app else []), str(path))
        requirement = f'anchor apple generic and identifier "{identifier}" and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "{TEAM}"'
        run("/usr/bin/codesign", "--verify", "--strict", "-R=" + requirement, str(path))
        details = run("/usr/bin/codesign", "-d", "--verbose=4", str(path), capture_output=True, text=True).stderr
        require("runtime" in details and f"TeamIdentifier={TEAM}" in details, "signature lacks hardened runtime or expected publisher")
        declared = run("/usr/bin/codesign", "-d", "--entitlements", "-", str(path), capture_output=True).stdout
        if declared:
            claims = plistlib.loads(declared)
            require(not claims.get("com.apple.security.get-task-allow") and not claims.get("get-task-allow"), "debugger entitlement is forbidden")
    shutil.copytree(ROOT / "deploy/ipc", output / "deployment")
    run("python3", "scripts/generate-sbom.py", str(output / "sbom.cdx.json"))
    commit = run("git", "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    manifest = {
        "version": "0.2.0", "sourceCommit": commit, "publisherTeam": TEAM,
        "sourceDirty": bool(run("git", "status", "--porcelain", capture_output=True, text=True).stdout),
        "profileEmbedded": bool(profile), "notarized": False, "productionIsolationVerified": False,
        "distributionReady": False,
        "files": {str(file.relative_to(output)): hashlib.sha256(file.read_bytes()).hexdigest()
                  for file in sorted(output.rglob("*")) if file.is_file()},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (output / "REVIEW-ONLY.txt").write_text("Developer ID signed review artifact. Not notarized. Dedicated-UID isolation and real user-presence signing have not been verified. Browser actions remain disabled. Do not use real credentials until the documented gates pass.\n")
    archive = ROOT / "dist/AgentVault-review.zip"
    archive.unlink(missing_ok=True)
    run("/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(output), str(archive))
    print(archive)


if __name__ == "__main__":
    main()
