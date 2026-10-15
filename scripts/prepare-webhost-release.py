#!/usr/bin/env python3
"""Stage an offline, noninstallable browser review payload. Never download, sign or install."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("agentvault_installer", ROOT / "deploy/ipc/agentvault_installer.py")
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)
Refusal = installer.Refusal
require = installer.require

HOST_ID = "dev.agentvault.webhost"
BROWSER_ID = "dev.agentvault.chromium"
BROWSER_ROOT = "chrome-headless-shell-mac-arm64"
HOST_BINARY = "AgentVaultWebHost"
METADATA_URL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
HOST_PATH = "/Library/AgentVault/WebHost/" + HOST_BINARY
CONFIG_PATH = "/Library/Application Support/AgentVault/webhost.json"
DATA_PATH = "/private/var/db/agent-vault-web"
MACH_MAGICS = {bytes.fromhex(value) for value in ("feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}
MAX_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 8192


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hex_value(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def exact(value, keys, name):
    require(isinstance(value, dict) and set(value) == set(keys), name + " has unexpected or missing keys")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def regular_bytes(path, maximum=2 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "input must be a regular file with one link")
        return installer.FileSystem.read(None, fd, maximum)
    finally:
        os.close(fd)


def parse_document(data):
    try:
        return json.loads(data, object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal("nonfinite JSON value")))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("invalid JSON document") from None


def document(path):
    data = regular_bytes(path)
    return parse_document(data), data


def relative_path(value):
    require(isinstance(value, str) and bool(value) and "\\" not in value and "\0" not in value,
            "invalid inventory path")
    path = PurePosixPath(value)
    require(bool(path.parts) and not path.is_absolute() and value == str(path) and all(part not in (".", "..") for part in path.parts),
            "inventory paths must be normalized relative paths")
    require(len(path.parts) <= 24 and len(value.encode()) <= 1024, "inventory path exceeds bounds")
    return value


def load_pin(path):
    pin, raw = document(path)
    require(not (isinstance(pin, dict) and pin.get("status") == "unconfigured"),
            "browser pin is unconfigured; supply reviewed source provenance, signed inventory and a measured P0 policy first")
    exact(pin, ["format", "platform", "version", "archiveURL", "archiveSHA256", "files", "code",
                "p0PolicySHA256", "p0ReportSHA256"], "browser pin")
    require(pin["format"] == "agent-vault-chromium-pin-v1" and pin["platform"] == "mac-arm64", "unsupported browser pin")
    version = pin["version"]
    require(isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", version), "invalid browser version")
    expected = f"https://storage.googleapis.com/chrome-for-testing-public/{version}/mac-arm64/chrome-headless-shell-mac-arm64.zip"
    require(pin["archiveURL"] == expected, "browser URL is not the fixed official CfT archive URL")
    require(all(hex_value(pin[key]) for key in ("archiveSHA256", "p0PolicySHA256", "p0ReportSHA256")), "missing SHA-256 pin")
    require(isinstance(pin["files"], dict) and 1 <= len(pin["files"]) <= MAX_ENTRIES, "invalid browser inventory")
    for name, entry in pin["files"].items():
        relative_path(name)
        exact(entry, ["sha256", "executable"], "file inventory")
        require(hex_value(entry["sha256"]) and type(entry["executable"]) is bool, "invalid file inventory")
    require(isinstance(pin["code"], dict) and "chrome-headless-shell" in pin["code"], "missing browser code inventory")
    for name, entry in pin["code"].items():
        require(relative_path(name) in pin["files"], "code is absent from file inventory")
        exact(entry, ["identifier", "cdhash"], "code inventory")
        expected_id = entry["identifier"]
        require(isinstance(expected_id, str) and re.fullmatch(re.escape(BROWSER_ID) + r"(?:\.[a-zA-Z0-9.-]+)?", expected_id),
                "browser code identifier must belong to the separate browser role")
        require(hex_value(entry["cdhash"], 40), "invalid browser cdhash")
    require(pin["code"]["chrome-headless-shell"]["identifier"] == BROWSER_ID, "wrong main browser identifier")
    require(pin["files"]["chrome-headless-shell"]["executable"], "main browser must be executable")
    return pin, raw


def timestamp(value):
    require(isinstance(value, str), "missing metadata timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Refusal("invalid metadata timestamp") from None
    require(parsed.utcoffset() == timedelta(0), "metadata timestamp must be UTC")
    return parsed


def validate_metadata(pin, metadata_path, receipt_path, now):
    metadata, raw = document(metadata_path)
    receipt, receipt_raw = document(receipt_path)
    exact(receipt, ["format", "sourceURL", "retrievedAt", "sha256"], "metadata receipt")
    require(receipt["format"] == "agent-vault-cft-metadata-receipt-v1" and receipt["sourceURL"] == METADATA_URL,
            "metadata receipt names an unsupported source")
    require(receipt["sha256"] == digest(raw), "metadata receipt does not match the supplied bytes")
    retrieved = timestamp(receipt["retrievedAt"])
    require(timedelta(0) <= now - retrieved <= timedelta(hours=24), "metadata receipt is stale or future-dated; refresh official Stable metadata")
    require(isinstance(metadata, dict), "invalid Stable metadata")
    published = timestamp(metadata.get("timestamp"))
    require(timedelta(0) <= retrieved - published <= timedelta(days=7), "supplied official metadata timestamp is stale or future-dated")
    try:
        stable = metadata["channels"]["Stable"]
        downloads = stable["downloads"]["chrome-headless-shell"]
        matches = [entry for entry in downloads if entry["platform"] == "mac-arm64"]
        require(stable["channel"] == "Stable" and stable["version"] == pin["version"] and len(matches) == 1
                and matches[0]["url"] == pin["archiveURL"], "browser pin differs from supplied latest Stable metadata")
    except (KeyError, TypeError):
        raise Refusal("invalid Stable metadata") from None
    return raw, receipt_raw


def snapshot(source, destination, budget, depth=0):
    """Copy from opened descriptors; never follow a link or wait for a FIFO."""
    require(depth < 24, "browser payload is too deep")
    info = os.fstat(source)
    if stat.S_ISDIR(info.st_mode):
        destination.mkdir(mode=0o700)
        for name in sorted(os.listdir(source)):
            installer._name(name)
            budget[1] -= 1
            require(budget[1] >= 0, "browser payload has too many entries")
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=source)
            try:
                snapshot(child, destination / name, budget, depth + 1)
            finally:
                os.close(child)
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mode & 0o7000 == 0,
                "payload must contain only regular single-link files and directories")
        require(info.st_size <= budget[0], "browser payload exceeds byte bound")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            while True:
                block = os.read(source, min(65536, budget[0] + 1))
                if not block:
                    break
                budget[0] -= len(block)
                require(budget[0] >= 0, "browser payload exceeds byte bound")
                view = memoryview(block)
                while view:
                    view = view[os.write(fd, view):]
            os.fsync(fd)
            os.fchmod(fd, 0o755 if info.st_mode & 0o111 else 0o644)
        finally:
            os.close(fd)


def copy_input(source, destination, budget):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        snapshot(fd, destination, budget)
    finally:
        os.close(fd)


def inventory(root, include_modes=False):
    files, code = {}, set()
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            require(info.st_mode & 0o7022 == 0, "staged directory has unsafe permission bits")
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "staged payload contains a link or special file")
        require(info.st_mode & 0o7000 == 0, "staged payload contains special permission bits")
        name = str(path.relative_to(root))
        hashed = hashlib.sha256()
        with path.open("rb") as handle:
            magic = handle.read(4)
            hashed.update(magic)
            for block in iter(lambda: handle.read(65536), b""):
                hashed.update(block)
        executable = bool(info.st_mode & 0o111)
        files[name] = {"sha256": hashed.hexdigest(), "executable": executable}
        if include_modes:
            files[name]["mode"] = format(stat.S_IMODE(info.st_mode), "04o")
        if magic in MACH_MAGICS:
            code.add(name)
        else:
            require(not executable, "browser contains an executable that is not inventoried Mach-O code")
    return files, code


def inspect_code(inspector, path, identifier, expected_entitlements, cdhash=None):
    found = inspector.identity(str(path))
    require(found.identifier == identifier and found.team == installer.TEAM and found.hardened,
            "code must have the exact Bite Developer ID role and hardened runtime")
    require(not found.get_task_allow and not found.entitlements.get("com.apple.security.cs.debugger"), "debugger access is refused")
    require(hex_value(found.cdhash, 40) and (cdhash is None or cdhash == found.cdhash), "code hash does not match the pin")
    try:
        matches = plistlib.dumps(found.entitlements) == plistlib.dumps(expected_entitlements)
    except (TypeError, ValueError, OverflowError):
        raise Refusal("entitlement policy is not a supported property-list dictionary") from None
    require(matches, "signed entitlements differ from the supplied exact P0 policy")
    require(inspector.satisfies(str(path), installer.requirement(identifier, found.cdhash)), "code fails its pinned Developer ID requirement")
    return found.cdhash


def deployment_plan(pin, host_hash, broker_document, host_uid):
    parsed = installer.parse_config(broker_document)
    ipc = parsed["ipc"]
    pins = installer.config_pins(ipc)
    require(ipc["development"] is False and ipc["readServiceName"] == installer.READ_SERVICE
            and ipc["adminServiceName"] == installer.ADMIN_SERVICE, "broker configuration must use fixed production roles")
    uids = [host_uid, ipc["brokerUID"], ipc["allowedUID"]]
    require(all(type(uid) is int and 0 < uid < 2**32 - 1 for uid in uids) and len(set(uids)) == 3,
            "host, broker and agent UIDs must be distinct non-root integers")
    require(host_hash not in pins.values() and all(entry["cdhash"] not in [host_hash, *pins.values()] for entry in pin["code"].values()),
            "host, browser and existing role code hashes must differ")
    config = {"serviceName": HOST_ID, "hostRequirement": installer.requirement(HOST_ID, host_hash),
              "brokerRequirement": ipc["brokerRequirement"], "hostUID": host_uid,
              "brokerUID": ipc["brokerUID"], "agentUID": ipc["allowedUID"], "development": False}
    plist = {"Label": HOST_ID, "Program": HOST_PATH, "UserName": "_agentvaultweb", "GroupName": "_agentvaultweb",
             "InitGroups": False, "Umask": 0o077, "WorkingDirectory": DATA_PATH,
             "MachServices": {config["serviceName"]: True}, "ProcessType": "Adaptive"}
    plan = {"format": "agent-vault-webhost-install-plan-v1", "installable": False, "browserEnabled": False,
            "account": {"name": "_agentvaultweb", "uid": host_uid, "gid": host_uid, "create": False},
            "proposedFiles": [{"source": HOST_BINARY, "destination": HOST_PATH, "owner": "root", "mode": "0755"},
                              {"source": BROWSER_ROOT, "destination": str(Path(HOST_PATH).parent / BROWSER_ROOT), "owner": "root"},
                              {"source": "deployment/webhost.json.disabled", "destination": CONFIG_PATH, "owner": "root", "mode": "0644"},
                              {"source": "deployment/dev.agentvault.webhost.plist.disabled", "destination": "/Library/LaunchDaemons/" + HOST_ID + ".plist", "owner": "root", "mode": "0644"}],
            "proposedPrivateDirectory": {"path": DATA_PATH, "owner": "_agentvaultweb", "mode": "0700"},
            "unverifiedGates": ["P0", "P1", "P2", "P3", "P4"],
            "blockedWork": ["reviewed account allocation and retryable installer lifecycle", "protected broker composition/configuration",
                            "installed daemon sandbox and whole-process egress proof", "protected human signing", "notarization"]}
    return config, plist, plan


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def load_policy(pin, policy_path, report_path):
    try:
        policy, policy_raw = document(policy_path)
        report = regular_bytes(report_path)
    except FileNotFoundError:
        raise Refusal("P0 prerequisite missing: supply the measured report and exact reviewed entitlement policy") from None
    require(bool(report) and digest(report) == pin["p0ReportSHA256"] and digest(policy_raw) == pin["p0PolicySHA256"],
            "missing measured P0 report or exact reviewed entitlement policy bytes")
    exact(policy, ["format", "reportSHA256", "host", "browser"], "P0 entitlement policy")
    require(policy["format"] == "agent-vault-webhost-entitlements-v1" and policy["reportSHA256"] == digest(report), "P0 policy/report mismatch")
    require(isinstance(policy["host"], dict) and isinstance(policy["browser"], dict)
            and set(policy["browser"]) == set(pin["code"]) and all(isinstance(value, dict) for value in policy["browser"].values()),
            "P0 policy must name the exact host and browser code entitlement dictionaries")
    return policy, policy_raw, report


def verify_archive(path, pin):
    """Hash one opened archive; compare resource bytes without extracting or executing code."""
    archive_hash = hashlib.sha256()
    archive_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(archive_fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_BYTES, "invalid source archive")
        count = 0
        while True:
            block = os.read(archive_fd, 65536)
            if not block:
                break
            count += len(block)
            require(count <= MAX_BYTES, "source archive exceeds bound")
            archive_hash.update(block)
        require(archive_hash.hexdigest() == pin["archiveSHA256"], "source archive SHA-256 differs from the reviewed pin")
        os.lseek(archive_fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(archive_fd), "rb") as handle, zipfile.ZipFile(handle) as archive:
            entries = archive.infolist()
            require(len(entries) <= MAX_ENTRIES and sum(entry.file_size for entry in entries) <= MAX_BYTES,
                    "source archive exceeds expanded bounds")
            names, files = set(), set()
            for entry in entries:
                name = relative_path(entry.filename.rstrip("/"))
                require(name not in names, "duplicate source archive entry")
                names.add(name)
                require(name == BROWSER_ROOT or name.startswith(BROWSER_ROOT + "/"), "source archive escapes its platform directory")
                kind = stat.S_IFMT(entry.external_attr >> 16)
                require(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not entry.flag_bits & 1,
                        "source archive contains a link, special file or encrypted entry")
                if entry.is_dir():
                    continue
                relative = name[len(BROWSER_ROOT) + 1:]
                require(bool(relative), "invalid source archive file")
                if "_CodeSignature" in PurePosixPath(relative).parts:
                    continue
                files.add(relative)
                require(relative in pin["files"], "source archive file is absent from reviewed signed tree")
                with archive.open(entry) as source:
                    if relative in pin["code"]:
                        require(source.read(4) in MACH_MAGICS, "source code is not Mach-O")
                    else:
                        hashed = hashlib.sha256()
                        remaining = entry.file_size
                        while True:
                            block = source.read(min(65536, remaining + 1))
                            if not block:
                                break
                            remaining -= len(block)
                            require(remaining >= 0, "source resource exceeds declared size")
                            hashed.update(block)
                        require(hashed.hexdigest() == pin["files"][relative]["sha256"], "signed tree changed an upstream resource")
            expected = {name for name in pin["files"] if "_CodeSignature" not in PurePosixPath(name).parts}
            require(files == expected, "source archive and signed tree contain different files")
    except (zipfile.BadZipFile, NotImplementedError):
        raise Refusal("source archive is not a supported ZIP") from None
    finally:
        os.close(archive_fd)


def prepare(args, inspector=None, now=None):
    require(os.geteuid() != 0 and os.getuid() != 0, "preparation must never run as root")
    pin, pin_raw = load_pin(args.pin)
    metadata, receipt = validate_metadata(pin, args.stable_metadata, args.metadata_receipt,
                                          now or datetime.now(timezone.utc))
    policy, policy_raw, report = load_policy(pin, args.p0_policy, args.p0_report)
    verify_archive(args.archive, pin)
    broker_document = regular_bytes(args.broker_config, 16384)
    # Reject duplicate keys before the legacy installer's exact-shape parser.
    parse_document(broker_document)
    require(hex_value(args.host_sha256), "host SHA-256 is required")
    output = Path(args.output).absolute()
    require(not os.path.lexists(output), "output already exists; preparation never replaces artifacts")
    parent = output.parent.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix=".agentvault-webhost-", dir=parent) as directory:
        staged = Path(directory) / "payload"
        staged.mkdir(mode=0o700)
        budget = [MAX_BYTES, MAX_ENTRIES]
        copy_input(args.host, staged / HOST_BINARY, budget)
        copy_input(args.browser, staged / BROWSER_ROOT, budget)
        require((staged / HOST_BINARY).is_file() and (staged / HOST_BINARY).stat().st_mode & 0o111
                and digest(regular_bytes(staged / HOST_BINARY, MAX_BYTES)) == args.host_sha256,
                "host bytes do not match the reviewed SHA-256")
        files, code = inventory(staged / BROWSER_ROOT)
        require(files == pin["files"] and code == set(pin["code"]), "staged browser differs from the reviewed signed-tree inventory")
        inspector = inspector or installer.CodeInspector()
        host_hash = inspect_code(inspector, staged / HOST_BINARY, HOST_ID, policy["host"])
        for name, entry in pin["code"].items():
            inspect_code(inspector, staged / BROWSER_ROOT / name, entry["identifier"], policy["browser"][name], entry["cdhash"])
        require(inventory(staged / BROWSER_ROOT) == (files, code)
                and digest(regular_bytes(staged / HOST_BINARY, MAX_BYTES)) == args.host_sha256,
                "staged artifact changed during signature inspection")
        config, plist, plan = deployment_plan(pin, host_hash, broker_document, args.host_uid)
        deploy = staged / "deployment"
        deploy.mkdir()
        (deploy / "webhost.json.disabled").write_bytes(json_bytes(config))
        (deploy / "dev.agentvault.webhost.plist.disabled").write_bytes(plistlib.dumps(plist))
        (deploy / "install-plan.json").write_bytes(json_bytes(plan))
        evidence = staged / "evidence"
        evidence.mkdir()
        for name, raw in {"chromium.pin.json": pin_raw, "stable-metadata.json": metadata, "metadata-receipt.json": receipt,
                          "p0-entitlements.json": policy_raw, "p0-report.txt": report, "broker-config.json": broker_document}.items():
            (evidence / name).write_bytes(raw)
        component = {"type": "application", "name": "chrome-headless-shell", "version": pin["version"],
                     "bom-ref": "agent-vault:chromium:mac-arm64",
                     "externalReferences": [{"type": "distribution", "url": pin["archiveURL"],
                                              "hashes": [{"alg": "SHA-256", "content": pin["archiveSHA256"]}]}],
                     "properties": [{"name": "agent-vault:provenance", "value": "operator-supplied archive pin; not an upstream signature"},
                                    {"name": "agent-vault:signed-tree-inventory-sha256", "value": digest(json_bytes(files))}]}
        host_component = {"type": "application", "name": "AgentVaultWebHost", "bom-ref": HOST_ID,
                          "hashes": [{"alg": "SHA-256", "content": args.host_sha256}]}
        (staged / "sbom.cdx.json").write_bytes(json_bytes({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                                         "components": [component, host_component]}))
        (staged / "PREPARATION-ONLY.txt").write_text("Not installable or distribution ready. Browser remains disabled. P0–P4, whole-process egress, protected signing and notarization remain unverified. Offline receipts/report/pins are operator-supplied evidence, not authenticated upstream or runtime proof.\n")
        final_files, _ = inventory(staged, include_modes=True)
        manifest = {"format": "agent-vault-webhost-preparation-v1", "publisherTeam": installer.TEAM,
                    "installable": False, "distributionReady": False, "browserEnabled": False,
                    "runtimeProofVerified": False, "notarized": False, "offlineEvidenceAuthenticated": False,
                    "hostCDHash": host_hash, "sourceArchiveSHA256": pin["archiveSHA256"], "files": final_files}
        (staged / "manifest.json").write_bytes(json_bytes(manifest))
        # The same exclusive descriptor-relative rename used by the installer; no replacement.
        fs = installer.FileSystem(str(parent))
        source_parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fs.rename(source_parent, "payload", fs.base, output.name, installer.RENAME_EXCL)
        finally:
            os.close(source_parent)
            os.close(fs.base)
    return manifest


def verify_payload(payload, manifest_sha256, inspector=None, now=None):
    """Read-only revalidation against an externally retained manifest hash, never self-attestation."""
    require(os.geteuid() != 0 and os.getuid() != 0, "preparation verification must never run as root")
    payload = Path(payload)
    info = payload.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
            "payload must be a private directory, not a link")
    raw = regular_bytes(payload / "manifest.json")
    require(hex_value(manifest_sha256) and digest(raw) == manifest_sha256, "manifest differs from the externally retained SHA-256")
    manifest = parse_document(raw)
    exact(manifest, ["format", "publisherTeam", "installable", "distributionReady", "browserEnabled", "runtimeProofVerified",
                     "notarized", "offlineEvidenceAuthenticated", "hostCDHash", "sourceArchiveSHA256", "files"], "preparation manifest")
    require(manifest["format"] == "agent-vault-webhost-preparation-v1" and manifest["publisherTeam"] == installer.TEAM,
            "unknown preparation manifest")
    require(all(manifest[key] is False for key in ("installable", "distributionReady", "browserEnabled", "runtimeProofVerified",
                                                  "notarized", "offlineEvidenceAuthenticated")), "preparation may never claim activation or runtime proof")
    files, _ = inventory(payload, include_modes=True)
    files.pop("manifest.json")
    require(json_bytes(files) == json_bytes(manifest["files"]), "payload bytes or modes differ from the retained manifest")
    evidence = payload / "evidence"
    pin, _ = load_pin(evidence / "chromium.pin.json")
    require(manifest["sourceArchiveSHA256"] == pin["archiveSHA256"], "source archive pin mismatch")
    validate_metadata(pin, evidence / "stable-metadata.json", evidence / "metadata-receipt.json", now or datetime.now(timezone.utc))
    policy, _, _ = load_policy(pin, evidence / "p0-entitlements.json", evidence / "p0-report.txt")
    browser_files, browser_code = inventory(payload / BROWSER_ROOT)
    require(browser_files == pin["files"] and browser_code == set(pin["code"]), "browser inventory differs from pin")
    inspector = inspector or installer.CodeInspector()
    host_hash = inspect_code(inspector, payload / HOST_BINARY, HOST_ID, policy["host"], manifest["hostCDHash"])
    for name, entry in pin["code"].items():
        inspect_code(inspector, payload / BROWSER_ROOT / name, entry["identifier"], policy["browser"][name], entry["cdhash"])
    supplied_plan, _ = document(payload / "deployment/install-plan.json")
    broker_document = regular_bytes(evidence / "broker-config.json", 16384)
    parse_document(broker_document)
    try:
        host_uid = supplied_plan["account"]["uid"]
    except (KeyError, TypeError):
        raise Refusal("invalid deployment plan") from None
    config, plist, plan = deployment_plan(pin, host_hash, broker_document, host_uid)
    require(json_bytes(supplied_plan) == json_bytes(plan), "deployment plan differs from exact derived roles")
    require(regular_bytes(payload / "deployment/webhost.json.disabled") == json_bytes(config)
            and regular_bytes(payload / "deployment/dev.agentvault.webhost.plist.disabled") == plistlib.dumps(plist),
            "disabled configuration or plist differs from the exact plan")
    final_files, _ = inventory(payload, include_modes=True)
    final_files.pop("manifest.json")
    require(json_bytes(final_files) == json_bytes(files), "payload changed during verification")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage", help="copy explicitly reviewed local inputs into a new noninstallable payload")
    for flag in ("host", "host-sha256", "browser", "archive", "stable-metadata", "metadata-receipt",
                 "p0-policy", "p0-report", "broker-config", "output"):
        stage.add_argument("--" + flag, required=True)
    stage.add_argument("--pin", default=str(ROOT / "deploy/webhost/chromium.pin.json"))
    stage.add_argument("--host-uid", type=int, required=True, help="candidate UID only; no account is created")
    verify = commands.add_parser("verify", help="read-only signature, byte, role, plan and supplied-freshness recheck")
    verify.add_argument("--payload", required=True)
    verify.add_argument("--manifest-sha256", required=True, help="hash retained outside the payload after review")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            verify_payload(args.payload, args.manifest_sha256)
        else:
            prepare(args)
            print("Manifest SHA-256: " + digest(regular_bytes(Path(args.output) / "manifest.json")))
    except (Refusal, OSError, ValueError) as error:
        parser.exit(1, "webhost preparation refused: " + str(error) + "\n")
    print("Noninstallable browser preparation verified; every runtime gate remains open.")


if __name__ == "__main__":
    main()
