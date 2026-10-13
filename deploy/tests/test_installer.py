"""Sandbox tests for deploy/ipc/agentvault_installer.py. Never touches the live system.

Run with: python3 -I -O deploy/tests/test_installer.py
"""
import argparse
import ast
import base64
import dataclasses
import fcntl
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.environ.get("AGENTVAULT_INSTALLER") or os.path.join(HERE, "..", "ipc", "agentvault_installer.py")
sys.path.insert(0, os.path.dirname(INSTALLER))
import agentvault_installer as av  # noqa: E402

CLIENT = 501
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
KEY = b"\x04" + GX.to_bytes(32, "big") + GY.to_bytes(32, "big")
OTHER_KEY = b"\x04" + GX.to_bytes(32, "big") + (av.P256_P - GY).to_bytes(32, "big")  # -G


def export(key, protection="secure_enclave"):
    return json.dumps({"format": "agent-vault-approval-public-key-v1", "protection": protection,
                       "publicKeyX963Base64": base64.b64encode(key).decode()}).encode()


class FakeInspector:
    """Identities keyed by the SHA-256 of the main executable's bytes, like a cdhash."""

    def __init__(self):
        self.known, self.hook = {}, None

    def register(self, content, signed_as, **overrides):
        identity = dict(identifier=signed_as, team=av.TEAM, cdhash=hashlib.sha1(content).hexdigest(),
                        hardened=True, get_task_allow=False)
        identity.update(overrides)
        self.known[hashlib.sha256(content).hexdigest()] = av.CodeIdentity(**identity)

    def identity(self, path):
        if self.hook:
            self.hook(path)
        executable = os.path.join(path, "Contents", "MacOS", "AgentVault") if os.path.isdir(path) else path
        with open(executable, "rb") as handle:
            found = self.known.get(hashlib.sha256(handle.read()).hexdigest())
        if found is None:
            raise av.Refusal("codesign failed")
        return found

    def satisfies(self, path, text):
        found = self.identity(path)
        return found.team == av.TEAM and text == av.requirement(found.identifier, found.cdhash)


class SandboxCase(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="av-installer-"))
        self.root = os.path.join(self.tmp, "system")
        os.mkdir(self.root)
        self.payload = os.path.join(self.tmp, "payload")
        self.inspector = FakeInspector()
        av.Sandbox.create(self.root, CLIENT)
        self.sandbox = av.Sandbox(self.root, self.inspector)
        self.host = self.sandbox.host
        self.write_payload(b"v1")

    def tearDown(self):
        for dirpath, dirnames, _ in os.walk(self.tmp):
            for name in dirnames:
                path = os.path.join(dirpath, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o700)
        shutil.rmtree(self.tmp)

    def write_payload(self, version, register=True):
        if os.path.exists(self.payload):
            shutil.rmtree(self.payload)
        os.makedirs(os.path.join(self.payload, "AgentVault.app", "Contents", "MacOS"))
        files = {"agent-vault-broker": b"broker-" + version, "agent-vault-bridge": b"bridge-" + version,
                 "AgentVault.app/Contents/MacOS/AgentVault": b"app-" + version,
                 "AgentVault.app/Contents/Info.plist": b"<plist/>"}
        for name, content in files.items():
            with open(os.path.join(self.payload, name), "wb") as handle:
                handle.write(content)
        for name in ("agent-vault-broker", "agent-vault-bridge", "AgentVault.app/Contents/MacOS/AgentVault"):
            os.chmod(os.path.join(self.payload, name), 0o755)
        if register:
            self.inspector.register(b"broker-" + version, "dev.agentvault.broker")
            self.inspector.register(b"bridge-" + version, "dev.agentvault.bridge")
            self.inspector.register(b"app-" + version, "dev.agentvault.app")

    def args(self, **overrides):
        values = dict(payload=self.payload, client_uid=CLIENT, upgrade=False,
                      replace_client_uid=None, replace_approval_key=None)
        values.update(overrides)
        return argparse.Namespace(**values)

    def install(self, key=KEY, **overrides):
        return av.Installer(self.host).install(self.args(**overrides), key)

    def refuses(self, message, key=KEY, **overrides):
        before = self.observable()
        with self.assertRaises(av.Refusal) as caught:
            self.install(key, **overrides)
        self.assertIn(message, str(caught.exception))
        self.assertEqual(before, self.observable(), "a refused run changed the host")

    def path(self, *parts):
        return os.path.join(self.root, *parts)

    def meta(self, *parts):
        """(kind, uid, gid, mode, nlink, size) as the installer sees it."""
        return dataclasses.astuple(self.host.fs._meta(os.lstat(self.path(*parts))))

    def read(self, *parts):
        with open(self.path(*parts), "rb") as handle:
            return handle.read()

    def observable(self):
        """Every file, link and owner outside the installer's staging, plus accounts and launchd."""
        tree = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel = os.path.relpath(dirpath, self.root)
            dirnames[:] = [d for d in dirnames if os.path.join(rel, d) != os.path.join("private", "var", "db", av.STAGING_NAME)]
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                info = os.lstat(full)
                key = os.path.join(rel, name)
                if name == av.SANDBOX_STATE:
                    continue
                content = os.readlink(full) if os.path.islink(full) else (
                    read_file(full) if os.path.isfile(full) else None)
                tree[key] = (info.st_mode, tuple(self.host.fs.owners.get(f"{info.st_dev}:{info.st_ino}", ())), content)
        return tree, json.dumps(self.sandbox.state["accounts"], sort_keys=True), json.dumps(self.sandbox.state["launchd"])

    def seed_bytes(self):
        return {s: self.read("private", "var", "db", "agent-vault", s)
                if os.path.exists(self.path("private", "var", "db", "agent-vault", s)) else None for s in av.SEEDS}

    def plant(self, parts, content=b"x", mode=0o644, owner=(0, 0)):
        with open(self.path(*parts), "wb") as handle:
            handle.write(content)
        os.chmod(self.path(*parts), mode)
        info = os.lstat(self.path(*parts))
        if owner:
            self.host.fs.owners[f"{info.st_dev}:{info.st_ino}"] = list(owner)


class InstallTests(SandboxCase):
    def test_fresh_install_produces_the_runtime_layout(self):
        changes = self.install()
        self.assertIn("daemon restarted", changes)
        av.Installer(self.host).verify_installed()
        config = json.loads(self.read("Library", "Application Support", "AgentVault", "config.json"))
        self.assertEqual(set(config), {"ipc", "approvalPublicKey"})
        self.assertEqual(base64.b64decode(config["approvalPublicKey"]), KEY)
        ipc = config["ipc"]
        uid = ipc["brokerUID"]
        self.assertTrue(200 <= uid < 400)
        self.assertEqual((ipc["allowedUID"], ipc["development"]), (CLIENT, False))
        for key, identifier, content in (("brokerRequirement", "dev.agentvault.broker", b"broker-v1"),
                                         ("readRequirement", "dev.agentvault.bridge", b"bridge-v1"),
                                         ("adminRequirement", "dev.agentvault.app", b"app-v1")):
            self.assertEqual(ipc[key], av.requirement(identifier, hashlib.sha1(content).hexdigest()))
            self.assertIn('cdhash H"', ipc[key])
            self.assertIn('certificate leaf[subject.OU] = "3JWAQ92CB4"', ipc[key])
        self.assertEqual(self.meta("Library", "Application Support", "AgentVault")[:4], ("dir", 0, 0, 0o755))
        self.assertEqual(self.meta("Library", "Application Support", "AgentVault", "config.json")[:5], ("file", 0, 0, 0o644, 1))
        self.assertEqual(self.meta("private", "var", "db", "agent-vault")[:4], ("dir", uid, uid, 0o700))
        for seed in av.SEEDS:
            self.assertEqual(self.meta("private", "var", "db", "agent-vault", seed)[:6], ("file", uid, uid, 0o400, 1, 32))
        self.assertNotEqual(self.read("private", "var", "db", "agent-vault", "keychain.password"),
                            self.read("private", "var", "db", "agent-vault", "state-integrity.key"))
        self.assertEqual(self.read("Library", "PrivilegedHelperTools", av.LABEL), b"broker-v1")
        self.assertEqual(self.read("Library", "AgentVault", "agent-vault-bridge"), b"bridge-v1")
        self.assertEqual(self.read("Applications", "AgentVault.app", "Contents", "MacOS", "AgentVault"), b"app-v1")
        self.assertEqual(self.meta("Library", "PrivilegedHelperTools", av.LABEL)[:5], ("file", 0, 0, 0o755, 1))
        plist = plistlib.loads(self.read("Library", "LaunchDaemons", av.LABEL + ".plist"))
        self.assertNotIn("ProgramArguments", plist)
        self.assertEqual(plist["Program"], "/Library/PrivilegedHelperTools/dev.agentvault.broker")
        self.assertEqual(set(plist["MachServices"]), {av.READ_SERVICE, av.ADMIN_SERVICE})
        user = self.sandbox.state["accounts"]["Users"][av.ACCOUNT]
        self.assertEqual((user["UniqueID"], user["UserShell"], user["IsHidden"], user["Password"]),
                         (str(uid), "/usr/bin/false", "1", "*"))
        self.assertEqual(self.sandbox.state["accounts"]["Groups"][av.ACCOUNT]["PrimaryGroupID"], str(uid))
        self.assertEqual(self.sandbox.state["launchd"]["log"],
                         [["bootstrap", self.path("Library", "LaunchDaemons", av.LABEL + ".plist")]])
        self.assertEqual(sorted(os.listdir(self.path("private", "var", "db", av.STAGING_NAME))),
                         ["account.json", "install.lock"])

    def test_rerun_changes_nothing(self):
        self.install()
        before = self.observable()
        self.assertEqual(self.install(), [])
        self.assertEqual(before, self.observable())

    def test_upgrade_needs_flag_and_preserves_private_data(self):
        self.install()
        seeds = [self.read("private", "var", "db", "agent-vault", s) for s in av.SEEDS]
        self.write_payload(b"v2")
        self.refuses("--upgrade")
        changes = self.install(upgrade=True)
        self.assertIn(av.LABEL, changes)
        self.assertEqual(self.read("Library", "PrivilegedHelperTools", av.LABEL), b"broker-v2")
        self.assertEqual(self.read("Applications", "AgentVault.app", "Contents", "MacOS", "AgentVault"), b"app-v2")
        self.assertEqual(seeds, [self.read("private", "var", "db", "agent-vault", s) for s in av.SEEDS])
        self.assertEqual([a[0] for a in self.sandbox.state["launchd"]["log"]], ["bootstrap", "bootout", "bootstrap"])
        av.Installer(self.host).verify_installed()

    def test_key_and_client_changes_need_the_current_values(self):
        self.install()
        old = hashlib.sha256(KEY).hexdigest()
        self.refuses(f"--replace-approval-key {old}", key=OTHER_KEY)
        self.refuses("--replace-approval-key", key=OTHER_KEY, replace_approval_key="0" * 64)
        self.install(key=OTHER_KEY, replace_approval_key=old)
        config = json.loads(self.read("Library", "Application Support", "AgentVault", "config.json"))
        self.assertEqual(base64.b64decode(config["approvalPublicKey"]), OTHER_KEY)
        self.sandbox.state["accounts"]["Users"]["second"] = {"UniqueID": "502"}
        self.refuses("--replace-client-uid 501", key=OTHER_KEY, client_uid=502)
        self.install(key=OTHER_KEY, client_uid=502, replace_client_uid=CLIENT)

    def test_retry_converges_after_an_interruption_at_every_step(self):
        """Fails the Nth host mutation, checks every installed path is whole or absent,
        then reruns the same command and requires the final state and unchanged seeds."""
        for upgrade in (False, True):
            step = 0
            while True:
                step += 1
                self.tearDown()
                self.setUp()
                if upgrade:
                    self.install()
                    self.write_payload(b"v2")
                mutators = [(self.host.fs, n) for n in ("mkdir", "rename", "unlink", "rmdir", "chown", "chmod", "write")]
                mutators += [(self.host.accounts, "create"), (self.host.launchd, "bootstrap"), (self.host.launchd, "bootout")]
                calls, logged = [0], len(self.sandbox.state["launchd"]["log"])

                def faulty(original):
                    def call(*a, **k):
                        calls[0] += 1
                        if calls[0] == step:
                            raise OSError(5, "injected interruption")
                        return original(*a, **k)
                    return call

                for obj, name in mutators:
                    setattr(obj, name, faulty(getattr(obj, name)))
                try:
                    self.install(upgrade=upgrade)
                    completed = True
                except OSError:
                    completed = False
                finally:
                    for obj, name in mutators:
                        delattr(obj, name)
                self.assert_whole_or_absent(upgrade)
                seeds = self.seed_bytes()
                self.install(upgrade=upgrade)
                av.Installer(self.host).verify_installed()
                after = self.seed_bytes()
                self.assertTrue(all(seeds[s] in (None, after[s]) for s in av.SEEDS), f"seed changed at step {step}")
                self.assertEqual(self.sandbox.state["launchd"]["loaded"], [av.LABEL])
                if upgrade:
                    self.assertIn(["bootstrap", self.path("Library", "LaunchDaemons", av.LABEL + ".plist")],
                                  self.sandbox.state["launchd"]["log"][logged:], f"no restart after step {step}")
                self.assertEqual(self.read("Library", "PrivilegedHelperTools", av.LABEL),
                                 b"broker-v2" if upgrade else b"broker-v1")
                if completed:
                    break
            self.assertGreater(step, 20)

    def assert_whole_or_absent(self, upgrade):
        versions = (b"v1", b"v2") if upgrade else (b"v1",)
        for parts, content in ((("Library", "PrivilegedHelperTools", av.LABEL), b"broker-"),
                               (("Library", "AgentVault", "agent-vault-bridge"), b"bridge-"),
                               (("Applications", "AgentVault.app", "Contents", "MacOS", "AgentVault"), b"app-")):
            if os.path.lexists(self.path(*parts)):
                self.assertIn(self.read(*parts), [content + v for v in versions])
        if os.path.lexists(self.path("private", "var", "db", "agent-vault")):
            entries = os.listdir(self.path("private", "var", "db", "agent-vault"))
            for seed in entries:
                self.assertEqual(len(self.read("private", "var", "db", "agent-vault", seed)), 32)
        config = self.path("Library", "Application Support", "AgentVault", "config.json")
        if os.path.lexists(config):
            av.parse_config(self.read("Library", "Application Support", "AgentVault", "config.json"))
            self.assertEqual(self.meta("Library", "Application Support", "AgentVault", "config.json")[:4], ("file", 0, 0, 0o644))

    def test_concurrent_installer_is_refused(self):
        installer = av.Installer(self.host)
        installer.acquire()
        try:
            self.refuses("another Agent Vault installer is running")
        finally:
            installer.release()

    def test_uninstall_removes_only_its_own_items_and_keeps_private_data(self):
        self.install()
        seeds = self.seed_bytes()
        self.plant(("Library", "AgentVault", "unrelated"), owner=(0, 0))
        removed = av.Installer(self.host).uninstall()
        self.assertIn("config.json", removed)
        for parts in (("Library", "PrivilegedHelperTools", av.LABEL), ("Library", "AgentVault", "agent-vault-bridge"),
                      ("Applications", "AgentVault.app"), ("Library", "LaunchDaemons", av.LABEL + ".plist"),
                      ("Library", "Application Support", "AgentVault", "config.json")):
            self.assertFalse(os.path.lexists(self.path(*parts)), parts)
        self.assertTrue(os.path.exists(self.path("Library", "AgentVault", "unrelated")))
        self.assertEqual(seeds, self.seed_bytes())
        self.assertIn(av.ACCOUNT, self.sandbox.state["accounts"]["Users"])
        self.assertEqual(self.sandbox.state["launchd"]["loaded"], [])
        self.assertEqual(av.Installer(self.host).uninstall(), [])

    def test_uninstall_refuses_foreign_code_before_changing_anything(self):
        self.install()
        os.unlink(self.path("Library", "AgentVault", "agent-vault-bridge"))
        self.plant(("Library", "AgentVault", "agent-vault-bridge"), b"bridge-v1-modified", 0o755)
        before = self.observable()
        with self.assertRaises(av.Refusal):
            av.Installer(self.host).uninstall()
        self.assertEqual(before, self.observable())


class SignatureTests(SandboxCase):
    def test_unsigned_or_misattributed_payloads_are_refused(self):
        cases = [
            ("broker", dict(identifier="dev.agentvault.bridge"), "signed as 'dev.agentvault.bridge'"),
            ("app", dict(identifier="dev.agentvault.broker"), "signed as 'dev.agentvault.broker'"),
            ("bridge", dict(team="ABCDE12345"), "not signed by team"),
            ("bridge", dict(hardened=False), "hardened runtime"),
            ("app", dict(get_task_allow=True), "get-task-allow"),
            ("broker", dict(cdhash="not-a-hash"), "cdhash"),
        ]
        for role, override, message in cases:
            with self.subTest(role=role, override=override):
                identifier = {"broker": "dev.agentvault.broker", "bridge": "dev.agentvault.bridge",
                              "app": "dev.agentvault.app"}[role]
                self.inspector.register(role.encode() + b"-v1", identifier, **override)
                self.refuses(message)
                self.inspector.register(role.encode() + b"-v1", identifier)

    def test_unknown_signature_is_refused(self):
        self.write_payload(b"v9", register=False)
        self.refuses("has no valid signature")

    def test_payload_swapped_after_snapshot_is_not_installed(self):
        evil = os.path.join(self.payload, "agent-vault-broker")

        def swap(path):
            with open(evil, "wb") as handle:
                handle.write(b"evil")
        self.inspector.hook = swap
        self.install()
        self.assertEqual(self.read("Library", "PrivilegedHelperTools", av.LABEL), b"broker-v1")

    def test_payload_symlinks_and_special_files_are_refused(self):
        os.unlink(os.path.join(self.payload, "agent-vault-bridge"))
        os.symlink("/usr/bin/true", os.path.join(self.payload, "agent-vault-bridge"))
        self.refuses("without following links")
        os.unlink(os.path.join(self.payload, "agent-vault-bridge"))
        os.mkfifo(os.path.join(self.payload, "agent-vault-bridge"))
        self.refuses("not a regular file")

    def test_approval_key_export_is_checked(self):
        good = hashlib.sha256(KEY).hexdigest()
        self.assertEqual(av.approval_key(export(KEY), good), KEY)
        bad_point = KEY[:-1] + bytes([KEY[-1] ^ 1])
        for data, fingerprint, message in (
                (export(KEY, "software_fixture"), good, "not protected"),
                (export(KEY), "0" * 64, "fingerprint"),
                (export(bad_point), hashlib.sha256(bad_point).hexdigest(), "not a point"),
                (export(b"\x02" + KEY[1:33]), good, "uncompressed"),
                (b"{}", good, "not an Agent Vault key export")):
            with self.assertRaises(av.Refusal) as caught:
                av.approval_key(data, fingerprint)
            self.assertIn(message, str(caught.exception))


class HostStateTests(SandboxCase):
    def test_unsafe_ancestors_are_refused(self):
        support = self.path("Library", "Application Support")
        os.chmod(support, 0o775)
        self.refuses("writable by others")
        os.chmod(support, 0o755)
        info = os.lstat(self.path("Library"))
        self.host.fs.owners[f"{info.st_dev}:{info.st_ino}"] = [CLIENT, 20]
        self.refuses("not root-owned")

    def test_symlinked_directories_are_refused_and_not_followed(self):
        outside = os.path.join(self.tmp, "outside")
        os.mkdir(outside)
        os.symlink(outside, self.path("Library", "AgentVault"))
        self.refuses("/Library/AgentVault")
        self.assertEqual(os.listdir(outside), [])
        os.unlink(self.path("Library", "AgentVault"))
        os.rename(self.path("Library", "LaunchDaemons"), self.path("Library", "LaunchDaemons.real"))
        os.symlink(outside, self.path("Library", "LaunchDaemons"))
        self.refuses("/Library/LaunchDaemons")
        self.assertEqual(os.listdir(outside), [])

    def test_existing_items_with_wrong_type_owner_mode_or_links_are_refused(self):
        self.install()
        seeds = self.seed_bytes()
        uid = json.loads(self.read("Library", "Application Support", "AgentVault", "config.json"))["ipc"]["brokerUID"]
        data = ("private", "var", "db", "agent-vault")
        cases = [
            (("Library", "Application Support", "AgentVault", "config.json"), "owner", (CLIENT, 20), "owned by"),
            (("Library", "Application Support", "AgentVault", "config.json"), "mode", 0o666, "mode"),
            (("Library", "Application Support", "AgentVault", "config.json"), "symlink", None, "link"),
            (("Library", "Application Support", "AgentVault", "config.json"), "hardlink", None, "hard links"),
            (data + ("keychain.password",), "hardlink", None, "hard links"),
            (data + ("keychain.password",), "symlink", None, "link"),
            (data + ("state-integrity.key",), "mode", 0o440, "mode"),
            (data + ("state-integrity.key",), "owner", (0, 0), "owned by"),
            (data, "mode", 0o755, "mode"),
            (data, "owner", (CLIENT, 20), "owned by"),
            (("Library", "PrivilegedHelperTools", av.LABEL), "owner", (CLIENT, 20), "owned by"),
            (("Library", "PrivilegedHelperTools", av.LABEL), "hardlink", None, "hard links"),
            (("Library", "LaunchDaemons", av.LABEL + ".plist"), "mode", 0o664, "mode"),
            (("Applications", "AgentVault.app"), "owner", (CLIENT, 80), "owned by"),
        ]
        for parts, change, value, message in cases:
            with self.subTest(path=parts, change=change):
                full = self.path(*parts)
                info = os.lstat(full)
                key = f"{info.st_dev}:{info.st_ino}"
                saved_owner, saved_mode = list(self.host.fs.owners[key]), stat_mode(full)
                if change == "owner":
                    self.host.fs.owners[key] = list(value)
                elif change == "mode":
                    os.chmod(full, value)
                elif change == "hardlink":
                    os.link(full, os.path.join(self.tmp, "link"))
                else:
                    os.rename(full, full + ".moved")
                    os.symlink(full + ".moved", full)
                self.refuses(message, upgrade=True)
                if change == "owner":
                    self.host.fs.owners[key] = saved_owner
                elif change == "mode":
                    os.chmod(full, saved_mode)
                elif change == "hardlink":
                    os.unlink(os.path.join(self.tmp, "link"))
                else:
                    os.unlink(full)
                    os.rename(full + ".moved", full)
                self.assertEqual(self.install(), [])
        self.assertEqual(seeds, self.seed_bytes())
        self.assertEqual(uid, json.loads(self.read("Library", "Application Support", "AgentVault", "config.json"))["ipc"]["brokerUID"])

    def test_foreign_program_at_destination_is_not_replaced(self):
        os.makedirs(self.path("Applications", "AgentVault.app", "Contents", "MacOS"))
        self.plant(("Applications", "AgentVault.app", "Contents", "MacOS", "AgentVault"), b"someone-else", 0o755)
        for parts in (("Applications", "AgentVault.app"), ("Applications", "AgentVault.app", "Contents"),
                      ("Applications", "AgentVault.app", "Contents", "MacOS")):
            info = os.lstat(self.path(*parts))
            os.chmod(self.path(*parts), 0o755)
            self.host.fs.owners[f"{info.st_dev}:{info.st_ino}"] = [0, 0]
        self.refuses("has no valid signature")
        self.inspector.register(b"someone-else", "com.example.other")
        self.refuses("signed as 'com.example.other'")

    def test_broker_state_without_seed_is_not_reseeded(self):
        self.install()
        os.chmod(self.path("private", "var", "db", "agent-vault", "keychain.password"), 0o600)
        os.unlink(self.path("private", "var", "db", "agent-vault", "keychain.password"))
        self.plant(("private", "var", "db", "agent-vault", "broker.lock"), b"", 0o600, owner=None)
        self.refuses("refusing to create a new seed")

    def test_missing_seed_in_empty_data_directory_is_created_without_touching_the_other(self):
        self.install()
        kept = self.read("private", "var", "db", "agent-vault", "state-integrity.key")
        os.chmod(self.path("private", "var", "db", "agent-vault", "keychain.password"), 0o600)
        os.unlink(self.path("private", "var", "db", "agent-vault", "keychain.password"))
        self.install()
        self.assertEqual(kept, self.read("private", "var", "db", "agent-vault", "state-integrity.key"))
        self.assertEqual(len(self.read("private", "var", "db", "agent-vault", "keychain.password")), 32)

    def test_corrupt_or_foreign_configuration_is_refused(self):
        self.install()
        config = self.path("Library", "Application Support", "AgentVault", "config.json")
        original = self.read("Library", "Application Support", "AgentVault", "config.json")
        document = json.loads(original)
        document["ipc"]["brokerRequirement"] = document["ipc"]["brokerRequirement"].split(" and cdhash")[0]
        for content, message in ((b"not json", "not valid JSON"),
                                 (json.dumps(dict(document, extra=1)).encode(), "unexpected keys")):
            os.chmod(config, 0o644)
            with open(config, "wb") as handle:
                handle.write(content)
            self.refuses(message, upgrade=True)
        with open(config, "wb") as handle:
            handle.write(json.dumps(document).encode())
        with self.assertRaises(av.Refusal) as caught:
            av.Installer(self.host).verify_installed()
        self.assertIn("pinned requirement", str(caught.exception))
        with open(config, "wb") as handle:
            handle.write(original)

    def test_foreign_launchdaemon_plist_is_refused(self):
        self.plant(("Library", "LaunchDaemons", av.LABEL + ".plist"), plistlib.dumps({"Label": "com.example.other"}))
        self.refuses("not this installer's job")


class AccountTests(SandboxCase):
    def users(self):
        return self.sandbox.state["accounts"]["Users"]

    def groups(self):
        return self.sandbox.state["accounts"]["Groups"]

    def complete_account(self, uid=250, **user_overrides):
        self.groups()[av.ACCOUNT] = {"PrimaryGroupID": str(uid), "Password": "*", "RealName": "Agent Vault broker"}
        user = {"UniqueID": str(uid), "PrimaryGroupID": str(uid), "UserShell": "/usr/bin/false",
                "NFSHomeDirectory": "/var/empty", "RealName": "Agent Vault broker", "Password": "*", "IsHidden": "1"}
        user.update(user_overrides)
        self.users()[av.ACCOUNT] = user

    def test_existing_matching_account_is_reused(self):
        self.complete_account()
        self.install()
        self.assertEqual(json.loads(self.read("Library", "Application Support", "AgentVault", "config.json"))["ipc"]["brokerUID"], 250)

    def test_uid_collisions_are_avoided_for_a_new_account(self):
        self.users()["taken"] = {"UniqueID": "200"}
        self.groups()["taken"] = {"PrimaryGroupID": "201"}
        self.install()
        self.assertEqual(self.users()[av.ACCOUNT]["UniqueID"], "202")

    def test_unsafe_existing_accounts_are_refused(self):
        cases = [
            (dict(UserShell="/bin/zsh"), None, "UserShell"),
            (dict(IsHidden="0"), None, "IsHidden"),
            (dict(Password="********"), None, "Password"),
            (dict(UniqueID="251"), None, "disagree"),
            ({}, lambda: self.users().__setitem__("other", {"UniqueID": "250"}), "shared with another user"),
            ({}, lambda: self.groups().__setitem__("other", {"PrimaryGroupID": "250"}), "shared with another group"),
            ({}, lambda: self.groups()[av.ACCOUNT].__setitem__("GroupMembership", "client"), "has members"),
        ]
        for overrides, extra, message in cases:
            with self.subTest(message=message):
                self.complete_account(**overrides)
                self.users().pop("other", None)
                self.groups().pop("other", None)
                if extra:
                    extra()
                self.refuses(message)

    def test_account_with_uid_zero_or_client_uid_is_refused(self):
        self.complete_account(0)
        self.refuses("outside 200-399")
        self.complete_account(CLIENT)
        self.refuses("client UID is not exactly one")

    def test_partial_account_is_completed_only_with_the_journal(self):
        self.groups()[av.ACCOUNT] = {"PrimaryGroupID": "260"}
        self.refuses("exists partially")
        installer = av.Installer(self.host)
        installer.acquire()
        installer.stage_bytes("account.json", json.dumps({"uid": 260}).encode(), 0o600)
        installer.release()
        self.install()
        self.assertEqual(self.users()[av.ACCOUNT]["UniqueID"], "260")

    def test_client_must_be_one_ordinary_user(self):
        self.refuses("client UID", client_uid=777)
        self.users()["daemonish"] = {"UniqueID": "300"}
        self.refuses("client UID", client_uid=300)
        self.users()["alias"] = {"UniqueID": str(CLIENT)}
        self.refuses("client UID")

    def test_data_directory_without_account_is_refused(self):
        os.mkdir(self.path("private", "var", "db", "agent-vault"), 0o700)
        info = os.lstat(self.path("private", "var", "db", "agent-vault"))
        self.host.fs.owners[f"{info.st_dev}:{info.st_ino}"] = [333, 333]
        self.refuses("/private/var/db/agent-vault is owned by 333:333")


class StructureTests(unittest.TestCase):
    """The sandbox cannot reach the live system, and no guard depends on assert."""

    def tree(self):
        with open(INSTALLER) as handle:
            return ast.parse(handle.read())

    def test_installer_has_no_assert_statements(self):
        self.assertFalse([n.lineno for n in ast.walk(self.tree()) if isinstance(n, ast.Assert)])

    def test_only_filesystem_classes_touch_files_and_only_run_command_spawns(self):
        """Everything else, including Installer, reaches the host only through Host."""
        mutating = {"open", "mkdir", "rename", "replace", "unlink", "remove", "rmdir", "symlink", "link",
                    "chown", "lchown", "fchown", "chmod", "fchmod", "write", "makedirs", "truncate", "ftruncate",
                    "renames", "removedirs", "mkfifo", "system", "popen", "execv", "execve", "spawnv", "fork"}
        offenders = []
        for top in self.tree().body:
            if not isinstance(top, (ast.ClassDef, ast.FunctionDef)):
                continue
            for node in ast.walk(top):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    if node.value.id == "os" and node.attr in mutating and \
                            top.name not in ("FileSystem", "SandboxFileSystem", "Sandbox"):
                        offenders.append((top.name, "os." + node.attr))
                    if node.value.id == "subprocess" and node.attr in ("run", "Popen", "call", "check_output") \
                            and top.name != "run_command":
                        offenders.append((top.name, node.value.id + "." + node.attr))
                if isinstance(node, ast.Name) and node.id in ("open", "_libc") and \
                        top.name not in ("Sandbox", "main", "FileSystem"):
                    offenders.append((top.name, node.id))
        self.assertEqual(offenders, [])

    def test_sandbox_refuses_root_and_unmarked_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o700)
            with self.assertRaises(av.Refusal):
                av.SandboxFileSystem(tmp, {}, (CLIENT, 20))
            with mock.patch.object(av.os, "geteuid", return_value=0), self.assertRaises(av.Refusal):
                av.Sandbox.create(tmp, CLIENT)
            av.Sandbox.create(tmp, CLIENT)
            av.SandboxFileSystem(tmp, {}, (CLIENT, 20))
            for patched in ("geteuid", "getuid"):
                with mock.patch.object(av.os, patched, return_value=0), self.assertRaises(av.Refusal):
                    av.SandboxFileSystem(tmp, {}, (CLIENT, 20))
        with self.assertRaises(av.Refusal):
            av.SandboxFileSystem("/", {}, (CLIENT, 20))

    def test_generated_files_match_the_reviewed_templates(self):
        """config.json.template is also validated by the Swift ConfigurationTests."""
        templates = os.path.join(HERE, "..", "ipc")
        pins = {p.identifier: str(i) * 40 for i, p in enumerate(av.PROGRAMS)}
        with open(os.path.join(templates, "config.json.template")) as handle:
            text = handle.read()
        for marker, value in (("@BROKER_UID@", "260"), ("@CLIENT_UID@", "501"),
                              ("@APPROVAL_PUBLIC_KEY@", base64.b64encode(KEY).decode()),
                              ("@BROKER_CDHASH@", "0" * 40), ("@READ_CDHASH@", "1" * 40), ("@ADMIN_CDHASH@", "2" * 40)):
            text = text.replace(marker, value)
        self.assertEqual(json.loads(text), json.loads(av.render_config(pins, 260, 501, KEY)))
        with open(os.path.join(templates, av.LABEL + ".plist.template"), "rb") as handle:
            self.assertEqual(plistlib.loads(handle.read()), plistlib.loads(av.daemon_plist()))

    def test_live_host_refuses_without_root(self):
        if os.geteuid() == 0:
            self.skipTest("never exercised as root")
        with self.assertRaises(av.Refusal):
            av.live_host()

    def test_path_components_cannot_escape(self):
        for name in ("..", ".", "a/b", "", "x\0"):
            with self.assertRaises(av.Refusal):
                av._name(name)

    def test_run_command_allows_only_fixed_tools(self):
        with self.assertRaises(av.Refusal):
            av.run_command(["/bin/rm", "-rf", "/nonexistent-agentvault"])


class RealCodesignTests(unittest.TestCase):
    """Real codesign parsing on ad hoc copies of /usr/bin/true. Developer ID acceptance is
    covered by scripts/verify-installer.py --signed-payload."""

    def setUp(self):
        if not os.path.exists("/usr/bin/codesign"):
            self.skipTest("codesign unavailable")
        self.tmp = tempfile.mkdtemp(prefix="av-codesign-")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def signed(self, name, *options):
        path = os.path.join(self.tmp, name)
        shutil.copy("/usr/bin/true", path)
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "dev.agentvault.broker",
                        *options, path], check=True, capture_output=True)
        return path

    def test_ad_hoc_runtime_signature_is_parsed_and_refused_for_team(self):
        path = self.signed("adhoc", "--options", "runtime")
        identity = av.CodeInspector().identity(path)
        self.assertEqual(identity.identifier, "dev.agentvault.broker")
        self.assertTrue(identity.hardened)
        self.assertFalse(identity.get_task_allow)
        self.assertRegex(identity.cdhash, r"^[0-9a-f]{40}$")
        self.assertFalse(av.CodeInspector().satisfies(path, av.requirement("dev.agentvault.broker", identity.cdhash)))
        installer = av.Installer(av.Host(None, None, None, av.CodeInspector()))
        with self.assertRaises(av.Refusal) as caught:
            installer.inspect(av.PROGRAMS[0], path)
        self.assertIn("not signed by team", str(caught.exception))

    def test_missing_runtime_and_debug_entitlement_are_detected(self):
        self.assertFalse(av.CodeInspector().identity(self.signed("plain")).hardened)
        entitlements = os.path.join(self.tmp, "e.plist")
        with open(entitlements, "wb") as handle:
            handle.write(plistlib.dumps({"com.apple.security.get-task-allow": True}))
        debug = self.signed("debug", "--options", "runtime", "--entitlements", entitlements)
        self.assertTrue(av.CodeInspector().identity(debug).get_task_allow)

    def test_unsigned_and_tampered_code_is_refused(self):
        path = self.signed("tampered", "--options", "runtime")
        with open(path, "r+b") as handle:
            handle.seek(0x400)
            handle.write(b"\xff\xff\xff\xff")
        with self.assertRaises(av.Refusal):
            av.CodeInspector().identity(path)


def read_file(path):
    with open(path, "rb") as handle:
        return handle.read()


def stat_mode(path):
    return os.lstat(path).st_mode & 0o7777


if __name__ == "__main__":
    print(f"optimize={sys.flags.optimize} isolated={sys.flags.isolated}", file=sys.stderr)
    unittest.main()
