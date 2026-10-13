#!/usr/bin/python3 -I
"""Agent Vault root installer.

Live use, as root, from a root-owned copy of this file:

    sudo AGENT_VAULT_INSTALL=dedicated-account /usr/bin/python3 -I -O agentvault_installer.py \
        install --payload DIR --client-uid UID --approval-key-file KEY.json --approval-key-sha256 HEX

`--sandbox DIR` runs the same code against a simulated system tree in DIR. Sandbox mode
refuses to run as root, confines every file operation below DIR, and replaces the account
database and launchd with in-file fakes. See docs/INSTALLATION.md.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import fcntl
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

TEAM = "3JWAQ92CB4"
LABEL = "dev.agentvault.broker"
ACCOUNT = "_agentvault"
READ_SERVICE = "dev.agentvault.broker.read"
ADMIN_SERVICE = "dev.agentvault.broker.admin"
ADMIN_GID = 80
BROKER_IDS = range(200, 400)
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_PAYLOAD_ENTRIES = 4096
MAX_CONFIG_BYTES = 16_384

Path = Tuple[str, ...]
CONFIG_DIR: Path = ("Library", "Application Support", "AgentVault")
LAUNCH_DAEMONS: Path = ("Library", "LaunchDaemons")
DB: Path = ("private", "var", "db")
DATA_NAME = "agent-vault"
STAGING_NAME = "agent-vault-install"
SEEDS = ("keychain.password", "state-integrity.key")
SEED_BYTES = 32
# The only ancestor that may be group-writable: admin users can already replace apps there,
# which is why the configuration pins each program's cdhash.
GROUP_WRITABLE: Dict[Path, int] = {("Applications",): ADMIN_GID}


class Refusal(Exception):
    """The installer refuses. Everything it changed before is a state a retry resumes."""


@dataclass(frozen=True)
class Program:
    source: str
    identifier: str
    parent: Path
    name: str
    bundle: bool
    config_key: str


PROGRAMS = (
    Program("agent-vault-broker", "dev.agentvault.broker", ("Library", "PrivilegedHelperTools"),
            LABEL, False, "brokerRequirement"),
    Program("agent-vault-bridge", "dev.agentvault.bridge", ("Library", "AgentVault"),
            "agent-vault-bridge", False, "readRequirement"),
    Program("AgentVault.app", "dev.agentvault.app", ("Applications",),
            "AgentVault.app", True, "adminRequirement"),
)
# Directories the installer may create, root:wheel 0755. Others must already exist.
OWN_DIRS = {("Library", "AgentVault"), CONFIG_DIR, ("Library", "PrivilegedHelperTools")}


def requirement(identifier: str, cdhash: Optional[str] = None) -> str:
    text = (f'anchor apple generic and identifier "{identifier}" and certificate 1[field.1.2.840.113635.100.6.2.6]'
            f' and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "{TEAM}"')
    return f'{text} and cdhash H"{cdhash}"' if cdhash else text


def daemon_plist() -> bytes:
    program = "/" + "/".join(PROGRAMS[0].parent + (PROGRAMS[0].name,))
    return plistlib.dumps({
        "Label": LABEL, "Program": program, "UserName": ACCOUNT, "GroupName": ACCOUNT,
        "InitGroups": False, "Umask": 0o077, "WorkingDirectory": "/" + "/".join(DB + (DATA_NAME,)),
        "MachServices": {READ_SERVICE: True, ADMIN_SERVICE: True}, "ProcessType": "Adaptive",
        "AssociatedBundleIdentifiers": ["dev.agentvault.app"],
    })


def render_config(pins: Dict[str, str], broker_uid: int, client_uid: int, key: bytes) -> bytes:
    ipc = {"readServiceName": READ_SERVICE, "adminServiceName": ADMIN_SERVICE,
           "brokerUID": broker_uid, "allowedUID": client_uid, "development": False}
    for program in PROGRAMS:
        ipc[program.config_key] = requirement(program.identifier, pins[program.identifier])
    document = {"ipc": ipc, "approvalPublicKey": base64.b64encode(key).decode()}
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def config_pins(ipc: dict) -> Dict[str, str]:
    pins = {}
    for program in PROGRAMS:
        match = re.fullmatch(re.escape(requirement(program.identifier)) + r' and cdhash H"([0-9a-f]{40})"',
                             str(ipc[program.config_key]))
        if match is None:
            raise Refusal(f"{program.config_key} is not this installer's pinned requirement")
        pins[program.identifier] = match.group(1)
    return pins


def parse_config(data: bytes) -> dict:
    ipc_keys = {"readServiceName", "adminServiceName", "brokerRequirement", "readRequirement",
                "adminRequirement", "brokerUID", "allowedUID", "development"}
    try:
        document = json.loads(data)
        key = base64.b64decode(document["approvalPublicKey"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise Refusal("the existing configuration is not valid JSON with a base64 approval key") from None
    if not (isinstance(document, dict) and set(document) == {"ipc", "approvalPublicKey"}
            and isinstance(document["ipc"], dict) and set(document["ipc"]) == ipc_keys):
        raise Refusal("the existing configuration has unexpected keys")
    return {"ipc": document["ipc"], "key": key}


P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def approval_key(export: bytes, fingerprint: str) -> bytes:
    """Parses the app's `--print-approval-public-key` export and checks the fingerprint the
    operator read from the app. Refuses fixture keys and points not on P-256."""
    try:
        document = json.loads(export)
        key = base64.b64decode(document["publicKeyX963Base64"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise Refusal("the approval key file is not an Agent Vault key export") from None
    if document.get("format") != "agent-vault-approval-public-key-v1":
        raise Refusal("the approval key file has an unknown format")
    if document.get("protection") not in ("secure_enclave", "keychain_user_presence"):
        raise Refusal("the approval key is not protected by user presence")
    if len(key) != 65 or key[0] != 4:
        raise Refusal("the approval key is not an uncompressed X9.63 P-256 point")
    x, y = int.from_bytes(key[1:33], "big"), int.from_bytes(key[33:], "big")
    if not (x < P256_P and y < P256_P and (y * y - x * x * x + 3 * x - P256_B) % P256_P == 0):
        raise Refusal("the approval key is not a point on P-256")
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or hashlib.sha256(key).hexdigest() != fingerprint:
        raise Refusal("the approval key does not match the confirmed SHA-256 fingerprint")
    return key


# ---------------------------------------------------------------------------- host access


@dataclass(frozen=True)
class Meta:
    kind: str  # dir, file, link or other
    uid: int
    gid: int
    mode: int
    nlink: int
    size: int


def _kind(mode: int) -> str:
    return {stat.S_IFDIR: "dir", stat.S_IFREG: "file", stat.S_IFLNK: "link"}.get(stat.S_IFMT(mode), "other")


def _name(name: str) -> str:
    if not name or name in (".", "..") or "/" in name or "\0" in name or len(name.encode()) > 255:
        raise Refusal("unsafe path component")
    return name


_libc = ctypes.CDLL(None, use_errno=True)
RENAME_SWAP, RENAME_EXCL = 0x2, 0x4


class FileSystem:
    """Every operation is relative to a directory descriptor obtained by walking down from
    the base with O_NOFOLLOW, so no path string ever reaches a mutating call."""

    def __init__(self, base: str):
        self.base_path = base.rstrip("/")
        self.base = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    def display(self, path: Path) -> str:
        """Absolute path for read-only tools such as codesign."""
        return self.base_path + "/" + "/".join(path)

    def _meta(self, info: os.stat_result) -> Meta:
        return Meta(_kind(info.st_mode), info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
                    info.st_nlink, info.st_size)

    def fstat(self, fd: int) -> Meta:
        return self._meta(os.fstat(fd))

    def lstat(self, dirfd: int, name: str) -> Optional[Meta]:
        try:
            return self._meta(os.stat(_name(name), dir_fd=dirfd, follow_symlinks=False))
        except FileNotFoundError:
            return None

    def open_dir(self, dirfd: int, name: str) -> int:
        return os.open(_name(name), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)

    def open_file(self, dirfd: int, name: str, flags: int, mode: int = 0o600) -> int:
        return os.open(_name(name), flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dirfd)

    def listdir(self, dirfd: int) -> List[str]:
        return sorted(os.listdir(dirfd))

    def read(self, fd: int, limit: int) -> bytes:
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > limit:
                raise Refusal("file exceeds its size limit")
            chunks.append(chunk)

    def write(self, fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)

    def mkdir(self, dirfd: int, name: str, mode: int) -> None:
        os.mkdir(_name(name), mode, dir_fd=dirfd)

    def chown(self, fd: int, uid: int, gid: int) -> None:
        os.fchown(fd, uid, gid)

    def chmod(self, fd: int, mode: int) -> None:
        os.fchmod(fd, mode)

    def rename(self, src_dir: int, src: str, dst_dir: int, dst: str, flags: int = 0) -> None:
        if flags == 0:
            os.rename(_name(src), _name(dst), src_dir_fd=src_dir, dst_dir_fd=dst_dir)
            return
        if _libc.renameatx_np(src_dir, _name(src).encode(), dst_dir, _name(dst).encode(), flags) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))

    def unlink(self, dirfd: int, name: str) -> None:
        os.unlink(_name(name), dir_fd=dirfd)

    def rmdir(self, dirfd: int, name: str) -> None:
        os.rmdir(_name(name), dir_fd=dirfd)

    def open_source(self, path: str) -> int:
        """Read-only descriptor for the operator's payload directory."""
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def open_source_entry(self, dirfd: int, name: str) -> int:
        """Read-only, never follows a link and never blocks on a FIFO."""
        return os.open(_name(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dirfd)


class SandboxFileSystem(FileSystem):
    """A FileSystem confined to a marked temporary directory, for non-root dry runs.

    It cannot run as root, so the kernel itself refuses writes to the live system; every
    operation is descriptor-relative below the sandbox. Ownership is simulated: what the
    installer creates starts as root with the parent's group, as it would live, and an
    inode planted by anything else reports the invoking user's logical UID."""

    def __init__(self, root: str, owners: Dict[str, List[int]], default_owner: Tuple[int, int]):
        if os.geteuid() == 0 or os.getuid() == 0:
            raise Refusal("sandbox mode never runs as root")
        real = os.path.realpath(root)
        info = os.lstat(real)
        if real == "/" or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise Refusal("the sandbox must be a private directory of the invoking user")
        if not os.path.isfile(os.path.join(real, SANDBOX_STATE)) or os.path.islink(os.path.join(real, SANDBOX_STATE)):
            raise Refusal("the sandbox is not marked; create it with sandbox-init")
        super().__init__(real)
        self.owners, self.default_owner = owners, default_owner

    def _meta(self, info: os.stat_result) -> Meta:
        uid, gid = self.owners.get(f"{info.st_dev}:{info.st_ino}", self.default_owner)
        return Meta(_kind(info.st_mode), uid, gid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size)

    def _forget(self, dirfd: int, name: str) -> None:
        try:
            info = os.stat(_name(name), dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if info.st_nlink <= 1 or stat.S_ISDIR(info.st_mode):
            self.owners.pop(f"{info.st_dev}:{info.st_ino}", None)

    def chown(self, fd: int, uid: int, gid: int) -> None:
        info = os.fstat(fd)
        self.owners[f"{info.st_dev}:{info.st_ino}"] = [uid, gid]

    def _created(self, dirfd: int, name: str) -> None:
        info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        self.owners[f"{info.st_dev}:{info.st_ino}"] = [0, self.fstat(dirfd).gid]

    def mkdir(self, dirfd: int, name: str, mode: int) -> None:
        super().mkdir(dirfd, name, mode)
        self._created(dirfd, name)

    def open_file(self, dirfd: int, name: str, flags: int, mode: int = 0o600) -> int:
        fd = super().open_file(dirfd, name, flags, mode)
        if flags & os.O_CREAT and flags & os.O_EXCL:
            self._created(dirfd, name)
        return fd

    def rename(self, src_dir: int, src: str, dst_dir: int, dst: str, flags: int = 0) -> None:
        if flags == 0:
            self._forget(dst_dir, dst)
        super().rename(src_dir, src, dst_dir, dst, flags)

    def unlink(self, dirfd: int, name: str) -> None:
        self._forget(dirfd, name)
        super().unlink(dirfd, name)

    def rmdir(self, dirfd: int, name: str) -> None:
        self._forget(dirfd, name)
        super().rmdir(dirfd, name)


def run_command(argv: List[str], check: bool = True) -> subprocess.CompletedProcess:
    if argv[0] not in ("/usr/bin/codesign", "/usr/bin/dscl", "/bin/launchctl"):
        raise Refusal("command is not allowed")
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
    if check and result.returncode != 0:
        raise Refusal(f"{os.path.basename(argv[0])} failed with status {result.returncode}")
    return result


@dataclass(frozen=True)
class CodeIdentity:
    identifier: str
    team: str
    cdhash: str
    hardened: bool
    get_task_allow: bool


class CodeInspector:
    """Read-only codesign queries. The host-native slice's cdhash is the one that runs."""

    def identity(self, path: str) -> CodeIdentity:
        run_command(["/usr/bin/codesign", "--verify", "--strict", "--deep", path])
        details = run_command(["/usr/bin/codesign", "-d", "--verbose=4", path]).stderr.decode(errors="replace")
        fields = dict(line.split("=", 1) for line in details.splitlines() if "=" in line)
        entitlements = run_command(["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", path]).stdout
        claims = plistlib.loads(entitlements) if entitlements.strip() else {}
        flags = re.search(r"flags=0x[0-9a-f]+\(([^)]*)\)", fields.get("CodeDirectory v", ""))
        return CodeIdentity(fields.get("Identifier", ""), fields.get("TeamIdentifier", ""),
                            fields.get("CDHash", ""), bool(flags and "runtime" in flags.group(1).split(",")),
                            bool(claims.get("com.apple.security.get-task-allow") or claims.get("get-task-allow")))

    def satisfies(self, path: str, text: str) -> bool:
        return run_command(["/usr/bin/codesign", "--verify", "--strict", "--deep", "-R=" + text, path],
                           check=False).returncode == 0


class LiveAccounts:
    """The local directory node through dscl."""

    def records(self, kind: str) -> Dict[str, Dict[str, str]]:
        attribute = "UniqueID" if kind == "Users" else "PrimaryGroupID"
        out = run_command(["/usr/bin/dscl", "-plist", ".", "-readall", "/" + kind, attribute]).stdout
        records = {}
        for entry in plistlib.loads(out):
            names = entry.get("dsAttrTypeStandard:RecordName", [])
            ids = entry.get("dsAttrTypeStandard:" + attribute, [])
            for name in names:
                records[name] = {attribute: ids[0]} if ids else {}
        return records

    def read(self, kind: str, name: str) -> Dict[str, str]:
        out = run_command(["/usr/bin/dscl", "-plist", ".", "-read", f"/{kind}/{name}"]).stdout
        return {key.split(":", 1)[-1]: ",".join(values) for key, values in plistlib.loads(out).items()}

    def create(self, kind: str, name: str, attribute: Optional[str] = None, value: Optional[str] = None) -> None:
        run_command(["/usr/bin/dscl", ".", "-create", f"/{kind}/{name}"] + ([attribute, value] if attribute else []))


class LiveLaunchd:
    def loaded(self, label: str) -> bool:
        return run_command(["/bin/launchctl", "print", f"system/{label}"], check=False).returncode == 0

    def bootout(self, label: str) -> None:
        run_command(["/bin/launchctl", "bootout", f"system/{label}"])

    def bootstrap(self, plist: str) -> None:
        run_command(["/bin/launchctl", "bootstrap", "system", plist])


class FakeAccounts:
    def __init__(self, state: dict):
        self.state = state  # {"Users": {name: {attr: value}}, "Groups": {...}}

    def records(self, kind: str) -> Dict[str, Dict[str, str]]:
        attribute = "UniqueID" if kind == "Users" else "PrimaryGroupID"
        return {name: {attribute: attrs[attribute]} if attribute in attrs else {}
                for name, attrs in self.state[kind].items()}

    def read(self, kind: str, name: str) -> Dict[str, str]:
        return dict(self.state[kind][name], RecordName=name)

    def create(self, kind: str, name: str, attribute: Optional[str] = None, value: Optional[str] = None) -> None:
        record = self.state[kind].setdefault(name, {})
        if attribute:
            record[attribute] = value


class FakeLaunchd:
    def __init__(self, state: dict):
        self.state = state  # {"loaded": [labels], "log": [actions]}

    def loaded(self, label: str) -> bool:
        return label in self.state["loaded"]

    def bootout(self, label: str) -> None:
        self.state["loaded"].remove(label)
        self.state["log"].append(["bootout", label])

    def bootstrap(self, plist: str) -> None:
        self.state["loaded"].append(LABEL)
        self.state["log"].append(["bootstrap", plist])


@dataclass
class Host:
    fs: FileSystem
    accounts: object
    launchd: object
    inspector: object
    random: object = os.urandom


def live_host() -> Host:
    if os.geteuid() != 0:
        raise Refusal("run as root, or use --sandbox for a dry run")
    if os.environ.get("AGENT_VAULT_INSTALL") != "dedicated-account":
        raise Refusal("set AGENT_VAULT_INSTALL=dedicated-account to confirm a live installation")
    return Host(FileSystem("/"), LiveAccounts(), LiveLaunchd(), CodeInspector())


SANDBOX_STATE = ".agentvault-sandbox.json"


class Sandbox:
    """Persistent simulated host: a marked private directory plus its JSON state."""

    def __init__(self, root: str, inspector: object = None):
        with open(os.path.join(root, SANDBOX_STATE), "rb") as handle:
            self.state = json.loads(handle.read())
        self.root = root
        fs = SandboxFileSystem(root, self.state["owners"], tuple(self.state["default_owner"]))
        self.host = Host(fs, FakeAccounts(self.state["accounts"]), FakeLaunchd(self.state["launchd"]),
                         inspector or CodeInspector())

    def save(self) -> None:
        path = os.path.join(self.root, SANDBOX_STATE)
        with open(path + ".tmp", "w") as handle:
            json.dump(self.state, handle, indent=1, sort_keys=True)
        os.replace(path + ".tmp", path)

    @staticmethod
    def create(root: str, client_uid: int, client_name: str = "client") -> "Sandbox":
        """Marks an empty private directory and builds the macOS directories the installer
        expects, with their real owners and modes. Client UID owns everything unmarked."""
        if os.geteuid() == 0:
            raise Refusal("sandbox mode never runs as root")
        if os.listdir(root):
            raise Refusal("sandbox-init needs an empty directory")
        os.chmod(root, 0o700)
        state = {"owners": {}, "default_owner": [client_uid, 20], "launchd": {"loaded": [], "log": []},
                 "accounts": {"Users": {"root": {"UniqueID": "0"}, client_name: {"UniqueID": str(client_uid)}},
                              "Groups": {"wheel": {"PrimaryGroupID": "0"}, "admin": {"PrimaryGroupID": "80"}}}}
        with open(os.path.join(root, SANDBOX_STATE), "w") as handle:
            json.dump(state, handle)
        sandbox = Sandbox(root, inspector=object())
        fs = sandbox.host.fs
        fs.chown(fs.base, 0, 0)
        for path, mode, gid in ((("private",), 0o755, 0), (("private", "var"), 0o755, 0), (DB, 0o755, 0),
                                (("Library",), 0o755, 0), (("Library", "Application Support"), 0o755, ADMIN_GID),
                                (LAUNCH_DAEMONS, 0o755, 0), (("Library", "PrivilegedHelperTools"), 0o1755, 0),
                                (("Applications",), 0o775, ADMIN_GID)):
            parent = walk(fs, path[:-1])
            fs.mkdir(parent, path[-1], 0o700)
            fd = fs.open_dir(parent, path[-1])
            fs.chmod(fd, mode)
            fs.chown(fd, 0, gid)
            os.close(fd)
            os.close(parent)
        sandbox.save()
        return sandbox


# --------------------------------------------------------------------------- the installer


def protected_ancestor(path: Path, meta: Meta) -> bool:
    if meta.kind != "dir" or meta.uid != 0:
        return False
    if path in GROUP_WRITABLE:
        return meta.gid == GROUP_WRITABLE[path] and meta.mode & 0o002 == 0
    return meta.mode & 0o022 == 0


def walk(fs: FileSystem, path: Path) -> int:
    """Opens a directory, refusing symlinks and any component another user could replace."""
    fd = os.dup(fs.base)
    try:
        if not protected_ancestor((), fs.fstat(fd)):
            raise Refusal("/ is not a protected root directory")
        for index, name in enumerate(path):
            try:
                child = fs.open_dir(fd, name)
            except OSError as error:
                raise Refusal(f"/{'/'.join(path[:index + 1])} is missing or not a directory ({error.strerror})") from None
            os.close(fd)
            fd = child
            if not protected_ancestor(path[:index + 1], fs.fstat(fd)):
                raise Refusal(f"/{'/'.join(path[:index + 1])} is not root-owned or is writable by others")
        return fd
    except BaseException:
        os.close(fd)
        raise


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def expect(meta: Optional[Meta], kind: str, uid: int, gid: int, mode: int, label: str) -> None:
    require(meta is not None, f"{label} is missing")
    require(meta.kind == kind, f"{label} is a {meta.kind}, expected a {kind}; refusing to replace it")
    require((meta.uid, meta.gid) == (uid, gid), f"{label} is owned by {meta.uid}:{meta.gid}, expected {uid}:{gid}")
    require(meta.mode == mode, f"{label} has mode {meta.mode:04o}, expected {mode:04o}")
    require(kind != "file" or meta.nlink == 1, f"{label} has {meta.nlink} hard links")


@dataclass
class Plan:
    pins: Dict[str, str]
    broker_uid: int
    config: bytes
    create_account: bool


class Installer:
    def __init__(self, host: Host):
        self.host, self.fs = host, host.fs
        self.staging = -1
        self.lock = -1

    # Staging: /private/var/db/agent-vault-install, root:wheel 0700. Holds the lock, the
    # account journal and snapshots. Nothing else can write there, so it is the one place
    # stale files from an interrupted run may be deleted.

    def acquire(self) -> None:
        db = walk(self.fs, DB)
        try:
            if self.fs.lstat(db, STAGING_NAME) is None:
                try:
                    self.fs.mkdir(db, STAGING_NAME, 0o700)
                    fd = self.fs.open_dir(db, STAGING_NAME)
                    self.fs.chown(fd, 0, 0)
                    os.close(fd)
                except FileExistsError:
                    pass
            expect(self.fs.lstat(db, STAGING_NAME), "dir", 0, 0, 0o700, "the installer staging directory")
            self.staging = self.fs.open_dir(db, STAGING_NAME)
        finally:
            os.close(db)
        try:
            self.lock = self.fs.open_file(self.staging, "install.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL)
            self.fs.chown(self.lock, 0, 0)
        except FileExistsError:
            self.lock = self.fs.open_file(self.staging, "install.lock", os.O_RDWR)
        expect(self.fs.fstat(self.lock), "file", 0, 0, 0o600, "the installer lock")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal("another Agent Vault installer is running") from None
        for name in self.fs.listdir(self.staging):
            if name not in ("install.lock", "account.json", "restart.pending"):
                self.remove_staged(name)

    def release(self) -> None:
        for fd in (self.lock, self.staging):
            if fd >= 0:
                os.close(fd)
        self.lock = self.staging = -1

    def remove_staged(self, name: str, dirfd: Optional[int] = None, depth: int = 0) -> None:
        dirfd = self.staging if dirfd is None else dirfd
        require(depth < 64, "staged tree is too deep")
        meta = self.fs.lstat(dirfd, name)
        if meta is None:
            return
        if meta.kind == "dir":
            child = self.fs.open_dir(dirfd, name)
            try:
                for entry in self.fs.listdir(child):
                    self.remove_staged(entry, child, depth + 1)
            finally:
                os.close(child)
            self.fs.rmdir(dirfd, name)
        else:
            self.fs.unlink(dirfd, name)

    def stage_bytes(self, name: str, data: bytes, mode: int, uid: int = 0, gid: int = 0) -> None:
        fd = self.fs.open_file(self.staging, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            self.fs.write(fd, data)
            self.fs.chmod(fd, mode)
            self.fs.chown(fd, uid, gid)
        finally:
            os.close(fd)

    def staged_path(self, *names: str) -> str:
        return self.fs.display(DB + (STAGING_NAME,) + names)

    # Snapshot: copy each payload into staging before inspecting it, so the operator's
    # directory can change afterwards without affecting what is verified and installed.

    def snapshot(self, payload_dir: str) -> None:
        source = self.fs.open_source(payload_dir)
        try:
            self.fs.mkdir(self.staging, "snapshot", 0o700)
            target = self.fs.open_dir(self.staging, "snapshot")
            self.fs.chown(target, 0, 0)
            budget = [MAX_PAYLOAD_BYTES, MAX_PAYLOAD_ENTRIES]
            try:
                for program in PROGRAMS:
                    self.copy(source, program.source, target, program.bundle, budget, 0)
            finally:
                os.close(target)
        finally:
            os.close(source)

    def copy(self, src: int, name: str, dst: int, allow_dir: bool, budget: List[int], depth: int) -> None:
        budget[1] -= 1
        require(budget[1] >= 0 and depth < 32, "payload has too many entries")
        try:
            fd = self.fs.open_source_entry(src, name)
        except OSError as error:
            raise Refusal(f"payload entry {name!r} cannot be opened without following links ({error.strerror})") from None
        try:
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode) and allow_dir:
                self.fs.mkdir(dst, name, 0o700)
                child = self.fs.open_dir(dst, name)
                try:
                    for entry in self.fs.listdir(fd):
                        self.copy(fd, entry, child, True, budget, depth + 1)
                    self.fs.chmod(child, 0o755)
                    self.fs.chown(child, 0, 0)
                finally:
                    os.close(child)
                return
            require(stat.S_ISREG(info.st_mode), f"payload entry {name!r} is not a regular file")
            data = self.fs.read(fd, budget[0])
            budget[0] -= len(data)
            self.stage_file(dst, name, data, 0o755 if info.st_mode & 0o111 or depth == 0 else 0o644)
        finally:
            os.close(fd)

    def stage_file(self, dirfd: int, name: str, data: bytes, mode: int) -> None:
        fd = self.fs.open_file(dirfd, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            self.fs.write(fd, data)
            self.fs.chmod(fd, mode)
            self.fs.chown(fd, 0, 0)
        finally:
            os.close(fd)

    def inspect(self, program: Program, path: str, pinned: Optional[str] = None) -> CodeIdentity:
        try:
            found = self.host.inspector.identity(path)
        except (Refusal, ValueError, subprocess.SubprocessError):
            raise Refusal(f"{program.source} has no valid signature") from None
        require(found.identifier == program.identifier, f"{program.source} is signed as {found.identifier!r}")
        require(found.team == TEAM, f"{program.source} is not signed by team {TEAM}")
        require(found.hardened, f"{program.source} lacks the hardened runtime")
        require(not found.get_task_allow, f"{program.source} allows debugger attachment (get-task-allow)")
        require(re.fullmatch(r"[0-9a-f]{40}", found.cdhash) is not None, f"{program.source} has no SHA-256 cdhash")
        require(pinned is None or found.cdhash == pinned, f"{program.source} is not the pinned code")
        require(self.host.inspector.satisfies(path, requirement(program.identifier, found.cdhash)),
                f"{program.source} does not satisfy its Developer ID requirement")
        return found

    # Accounts. The journal records the UID chosen before the first dscl write, so a partial
    # record is completed only if this installer started it.

    def account_attributes(self, uid: int) -> Dict[str, Dict[str, str]]:
        return {"Groups": {"PrimaryGroupID": str(uid), "Password": "*", "RealName": "Agent Vault broker"},
                "Users": {"UniqueID": str(uid), "PrimaryGroupID": str(uid), "UserShell": "/usr/bin/false",
                          "NFSHomeDirectory": "/var/empty", "RealName": "Agent Vault broker",
                          "Password": "*", "IsHidden": "1"}}

    def journal(self) -> Optional[int]:
        meta = self.fs.lstat(self.staging, "account.json")
        if meta is None:
            return None
        expect(meta, "file", 0, 0, 0o600, "the account journal")
        fd = self.fs.open_file(self.staging, "account.json", os.O_RDONLY)
        try:
            uid = json.loads(self.fs.read(fd, 256)).get("uid")
        finally:
            os.close(fd)
        require(isinstance(uid, int) and uid in BROKER_IDS, "the account journal is invalid")
        return uid

    def plan_account(self, client_uid: int) -> Tuple[int, bool]:
        accounts = self.host.accounts
        users, groups = accounts.records("Users"), accounts.records("Groups")
        clients = [name for name, attrs in users.items() if attrs.get("UniqueID") == str(client_uid)]
        require(client_uid >= 501 and len(clients) == 1 and clients[0] != ACCOUNT,
                "the client UID is not exactly one ordinary local user")
        journal = self.journal()
        present = {kind: ACCOUNT in records for kind, records in (("Users", users), ("Groups", groups))}
        if not any(present.values()):
            used = {int(a["UniqueID"]) for a in users.values() if a.get("UniqueID", "").isdigit()} | \
                   {int(a["PrimaryGroupID"]) for a in groups.values() if a.get("PrimaryGroupID", "").isdigit()}
            uid = journal if journal is not None else next((n for n in BROKER_IDS if n not in used), None)
            require(uid is not None and uid not in used, "no free UID/GID pair in 200-399")
            return uid, True
        records = {kind: accounts.read(kind, ACCOUNT) if present[kind] else {} for kind in present}
        ids = {records["Users"].get("UniqueID"), records["Groups"].get("PrimaryGroupID")} - {None}
        if not ids and journal is not None:
            ids = {str(journal)}
        require(len(ids) == 1 and next(iter(ids)).isdigit(), f"{ACCOUNT} user and group IDs disagree or are missing")
        uid = int(next(iter(ids)))
        require(uid in BROKER_IDS and uid != client_uid, f"{ACCOUNT} has UID {uid}, outside 200-399 or equal to the client")
        require([n for n, a in users.items() if a.get("UniqueID") == str(uid)] in ([ACCOUNT], []),
                f"UID {uid} is shared with another user")
        require([n for n, a in groups.items() if a.get("PrimaryGroupID") == str(uid)] in ([ACCOUNT], []),
                f"GID {uid} is shared with another group")
        require(not records["Groups"].get("GroupMembership"), f"group {ACCOUNT} has members")
        complete = True
        for kind, wanted in self.account_attributes(uid).items():
            for attribute, value in wanted.items():
                actual = records[kind].get(attribute)
                require(actual in (None, value), f"{ACCOUNT} {kind[:-1].lower()} has {attribute}={actual!r}, expected {value!r}")
                complete = complete and actual is not None
        require(complete or journal == uid, f"{ACCOUNT} exists partially and this installer did not create it")
        return uid, not complete

    def create_account(self, uid: int) -> None:
        if self.journal() is None:
            self.stage_bytes("account.json.new", json.dumps({"uid": uid}).encode(), 0o600)
            self.fs.rename(self.staging, "account.json.new", self.staging, "account.json")
        for kind, wanted in self.account_attributes(uid).items():
            record = self.host.accounts.read(kind, ACCOUNT) if ACCOUNT in self.host.accounts.records(kind) else None
            if record is None:
                self.host.accounts.create(kind, ACCOUNT)
                record = {}
            for attribute, value in wanted.items():
                if attribute not in record:
                    self.host.accounts.create(kind, ACCOUNT, attribute, value)

    # Installed files.

    def own_dir(self, path: Path, create: bool) -> int:
        """Opens an installer-owned or system directory, creating an owned one if allowed."""
        parent = walk(self.fs, path[:-1])
        try:
            if path in OWN_DIRS and self.fs.lstat(parent, path[-1]) is None and create:
                os.close(self.stage_dir("newdir", 0o755, 0, 0))
                self.fs.rename(self.staging, "newdir", parent, path[-1], RENAME_EXCL)
            meta = self.fs.lstat(parent, path[-1])
            require(meta is not None, f"/{'/'.join(path)} is missing")
            require(protected_ancestor(path, meta), f"/{'/'.join(path)} is not root-owned or is writable by others")
            return self.fs.open_dir(parent, path[-1])
        finally:
            os.close(parent)

    def stage_dir(self, name: str, mode: int, uid: int, gid: int) -> int:
        self.fs.mkdir(self.staging, name, 0o700)
        fd = self.fs.open_dir(self.staging, name)
        self.fs.chmod(fd, mode)
        self.fs.chown(fd, uid, gid)
        return fd

    def installed_identity(self, program: Program, dirfd: int, pins: Optional[Dict[str, str]]) -> Optional[str]:
        """Returns the cdhash of our program at its destination, None if absent; refuses anything else."""
        label = "/" + "/".join(program.parent + (program.name,))
        meta = self.fs.lstat(dirfd, program.name)
        if meta is None:
            return None
        expect(meta, "dir" if program.bundle else "file", 0, 0, 0o755, label)
        found = self.inspect(program, self.fs.display(program.parent + (program.name,)),
                             pins.get(program.identifier) if pins else None)
        return found.cdhash

    def read_existing(self, dirfd: int, name: str, label: str, limit: int) -> Optional[bytes]:
        meta = self.fs.lstat(dirfd, name)
        if meta is None:
            return None
        expect(meta, "file", 0, 0, 0o644, label)
        fd = self.fs.open_file(dirfd, name, os.O_RDONLY)
        try:
            return self.fs.read(fd, limit)
        finally:
            os.close(fd)

    def existing_config(self) -> Optional[dict]:
        parent = walk(self.fs, CONFIG_DIR[:-1])
        try:
            meta = self.fs.lstat(parent, CONFIG_DIR[-1])
            if meta is None:
                return None
            expect(meta, "dir", 0, 0, 0o755, "/" + "/".join(CONFIG_DIR))
        finally:
            os.close(parent)
        dirfd = self.own_dir(CONFIG_DIR, create=False)
        try:
            data = self.read_existing(dirfd, "config.json", "the existing configuration", MAX_CONFIG_BYTES)
        finally:
            os.close(dirfd)
        return None if data is None else dict(parse_config(data), raw=data)

    def replace_file(self, path: Path, name: str, data: bytes) -> bool:
        dirfd = self.own_dir(path, create=True)
        try:
            if self.read_existing(dirfd, name, "/" + "/".join(path + (name,)), MAX_CONFIG_BYTES) == data:
                return False
            self.stage_bytes(name, data, 0o644)
            self.fs.rename(self.staging, name, dirfd, name)
            return True
        finally:
            os.close(dirfd)

    def place(self, program: Program, pins: Dict[str, str]) -> bool:
        dirfd = self.own_dir(program.parent, create=True)
        try:
            current = self.installed_identity(program, dirfd, None)
            if current == pins[program.identifier]:
                return False
            snapshot = self.fs.open_dir(self.staging, "snapshot")
            try:
                if current is None:
                    self.fs.rename(snapshot, program.source, dirfd, program.name, RENAME_EXCL)
                else:
                    self.fs.rename(snapshot, program.source, dirfd, program.name, RENAME_SWAP)
                    self.remove_staged(program.source, snapshot)
            finally:
                os.close(snapshot)
            return True
        finally:
            os.close(dirfd)

    def data_state(self, broker_uid: int) -> Optional[List[str]]:
        """Read-only. None if the private directory is absent, else the seeds still to create.
        Present seeds must be exact; a missing seed is created only in an otherwise empty
        directory, never beside broker state that may depend on the lost one."""
        db = walk(self.fs, DB)
        try:
            meta = self.fs.lstat(db, DATA_NAME)
            if meta is None:
                return None
            expect(meta, "dir", broker_uid, broker_uid, 0o700, "/private/var/db/agent-vault")
            data = self.fs.open_dir(db, DATA_NAME)
        finally:
            os.close(db)
        try:
            entries = self.fs.listdir(data)
            missing = [seed for seed in SEEDS if seed not in entries]
            require(not missing or set(entries) <= set(SEEDS),
                    "broker state exists but a seed is missing; refusing to create a new seed beside it")
            for seed in SEEDS:
                if seed not in missing:
                    meta = self.fs.lstat(data, seed)
                    expect(meta, "file", broker_uid, broker_uid, 0o400, f"seed {seed}")
                    require(meta.size == SEED_BYTES, f"seed {seed} is not {SEED_BYTES} bytes")
            return missing
        finally:
            os.close(data)

    def ensure_data(self, broker_uid: int) -> bool:
        """Seeds are generated in staging and moved in with RENAME_EXCL, so root never writes
        through a name inside the broker-owned directory and never replaces existing bytes."""
        missing = self.data_state(broker_uid)
        db = walk(self.fs, DB)
        try:
            if missing is None:
                fd = self.stage_dir("data", 0o700, broker_uid, broker_uid)
                try:
                    for seed in SEEDS:
                        self.stage_seed(fd, seed, broker_uid)
                finally:
                    os.close(fd)
                self.fs.rename(self.staging, "data", db, DATA_NAME, RENAME_EXCL)
                return True
            data = self.fs.open_dir(db, DATA_NAME)
        finally:
            os.close(db)
        try:
            for seed in missing:
                self.stage_seed(self.staging, seed, broker_uid)
                try:
                    self.fs.rename(self.staging, seed, data, seed, RENAME_EXCL)
                except FileExistsError:
                    self.fs.unlink(self.staging, seed)
        finally:
            os.close(data)
        require(self.data_state(broker_uid) == [], "the broker seeds are incomplete")
        return bool(missing)

    def stage_seed(self, dirfd: int, name: str, broker_uid: int) -> None:
        fd = self.fs.open_file(dirfd, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            self.fs.write(fd, self.host.random(SEED_BYTES))
            self.fs.chmod(fd, 0o400)
            self.fs.chown(fd, broker_uid, broker_uid)
        finally:
            os.close(fd)

    # Commands.

    def plan(self, args: argparse.Namespace, key: bytes) -> Plan:
        pins = {}
        for program in PROGRAMS:
            pins[program.identifier] = self.inspect(program, self.staged_path("snapshot", program.source)).cdhash
        require(len(set(pins.values())) == len(PROGRAMS), "two payloads have the same cdhash")
        broker_uid, create_account = self.plan_account(args.client_uid)
        config = render_config(pins, broker_uid, args.client_uid, key)
        existing = self.existing_config()
        if existing:
            old, new = existing["ipc"], parse_config(config)["ipc"]
            require(old["brokerUID"] == broker_uid, "the configured broker UID differs from the _agentvault account")
            if old["allowedUID"] != args.client_uid:
                require(args.replace_client_uid == old["allowedUID"],
                        f"the client UID changes from {old['allowedUID']}; confirm with --replace-client-uid {old['allowedUID']}")
            if existing["key"] != key:
                old_fingerprint = hashlib.sha256(existing["key"]).hexdigest()
                require(args.replace_approval_key == old_fingerprint,
                        f"the approval key changes; confirm with --replace-approval-key {old_fingerprint}")
            changed = [k for k in new if k not in ("allowedUID",) and old[k] != new[k]]
            require(not changed or args.upgrade, f"installed code pins change ({', '.join(changed)}); confirm with --upgrade")
        for program in PROGRAMS:
            dirfd = self.existing_dir(program.parent)
            if dirfd is not None:
                try:
                    self.installed_identity(program, dirfd, None)
                finally:
                    os.close(dirfd)
        self.preflight_files(broker_uid)
        return Plan(pins, broker_uid, config, create_account)

    def existing_dir(self, path: Path) -> Optional[int]:
        parent = walk(self.fs, path[:-1])
        try:
            meta = self.fs.lstat(parent, path[-1])
        finally:
            os.close(parent)
        if meta is None:
            require(path in OWN_DIRS, f"/{'/'.join(path)} is missing")
            return None
        if path in OWN_DIRS and path != ("Library", "PrivilegedHelperTools"):
            expect(meta, "dir", 0, 0, 0o755, "/" + "/".join(path))
        return self.own_dir(path, create=False)

    def preflight_files(self, broker_uid: int) -> None:
        dirfd = walk(self.fs, LAUNCH_DAEMONS)
        try:
            plist = self.read_existing(dirfd, LABEL + ".plist", "the LaunchDaemon plist", 65536)
        finally:
            os.close(dirfd)
        if plist is not None:
            try:
                label = plistlib.loads(plist).get("Label")
            except Exception:
                label = None
            require(label == LABEL, "the LaunchDaemon plist exists but is not this installer's job")
        self.data_state(broker_uid)

    def install(self, args: argparse.Namespace, key: bytes) -> List[str]:
        self.acquire()
        try:
            self.snapshot(args.payload)
            plan = self.plan(args, key)
            # Marks the run before the first change, so a retry after an interruption
            # restarts the daemon even when it finds nothing left to change.
            interrupted = self.fs.lstat(self.staging, "restart.pending") is not None
            if not interrupted:
                self.stage_bytes("restart.pending", b"", 0o600)
            changes = []
            if plan.create_account:
                self.create_account(plan.broker_uid)
                changes.append(f"account {ACCOUNT} uid {plan.broker_uid}")
            if self.ensure_data(plan.broker_uid):
                changes.append("broker seeds")
            for program in PROGRAMS:
                if self.place(program, plan.pins):
                    changes.append(program.name)
            if self.replace_file(CONFIG_DIR, "config.json", plan.config):
                changes.append("config.json")
            if self.replace_file(LAUNCH_DAEMONS, LABEL + ".plist", daemon_plist()):
                changes.append("LaunchDaemon plist")
            self.verify_installed(plan.broker_uid)
            if changes or interrupted or not self.host.launchd.loaded(LABEL):
                if self.host.launchd.loaded(LABEL):
                    self.host.launchd.bootout(LABEL)
                self.host.launchd.bootstrap(self.fs.display(LAUNCH_DAEMONS + (LABEL + ".plist",)))
                changes.append("daemon restarted")
            self.fs.unlink(self.staging, "restart.pending")
            self.remove_staged("snapshot")
            return changes
        finally:
            self.release()

    def verify_installed(self, broker_uid: Optional[int] = None) -> None:
        config = self.existing_config()
        require(config is not None, "no configuration is installed")
        ipc = config["ipc"]
        require(broker_uid is None or ipc["brokerUID"] == broker_uid, "configured broker UID mismatch")
        pins = config_pins(ipc)
        for program in PROGRAMS:
            dirfd = self.own_dir(program.parent, create=False)
            try:
                require(self.installed_identity(program, dirfd, pins) is not None, f"{program.name} is not installed")
            finally:
                os.close(dirfd)
        require(self.data_state(ipc["brokerUID"]) == [], "the broker private directory or its seeds are missing")
        dirfd = walk(self.fs, LAUNCH_DAEMONS)
        try:
            require(self.read_existing(dirfd, LABEL + ".plist", "the LaunchDaemon plist", 65536) == daemon_plist(),
                    "the LaunchDaemon plist differs from this installer's")
        finally:
            os.close(dirfd)

    def uninstall(self) -> List[str]:
        """Removes this installer's job, programs and configuration. Keeps the account and
        /private/var/db/agent-vault. Refuses before changing anything if an item is not ours."""
        self.acquire()
        try:
            config = self.existing_config()
            pins = config_pins(config["ipc"]) if config else None
            present = []
            for program in PROGRAMS:
                dirfd = self.existing_dir(program.parent)
                if dirfd is not None:
                    try:
                        if self.installed_identity(program, dirfd, pins):
                            present.append(program)
                    finally:
                        os.close(dirfd)
            dirfd = walk(self.fs, LAUNCH_DAEMONS)
            try:
                plist = self.read_existing(dirfd, LABEL + ".plist", "the LaunchDaemon plist", 65536)
                require(plist is None or plistlib.loads(plist).get("Label") == LABEL,
                        "the LaunchDaemon plist is not this installer's job")
                removed = []
                if self.host.launchd.loaded(LABEL):
                    self.host.launchd.bootout(LABEL)
                    removed.append("daemon stopped")
                if plist is not None:
                    self.fs.unlink(dirfd, LABEL + ".plist")
                    removed.append("LaunchDaemon plist")
            finally:
                os.close(dirfd)
            for program in present:
                dirfd = self.own_dir(program.parent, create=False)
                try:
                    self.fs.rename(dirfd, program.name, self.staging, "removed", RENAME_EXCL)
                finally:
                    os.close(dirfd)
                self.remove_staged("removed")
                removed.append(program.name)
            if config:
                dirfd = self.own_dir(CONFIG_DIR, create=False)
                try:
                    self.fs.unlink(dirfd, "config.json")
                finally:
                    os.close(dirfd)
                removed.append("config.json")
            return removed
        finally:
            self.release()


# --------------------------------------------------------------------------------- CLI


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install, verify or uninstall the Agent Vault broker.")
    parser.add_argument("--sandbox", metavar="DIR", help="dry run against a sandbox made by sandbox-init")
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install")
    install.add_argument("--payload", required=True, help="directory with AgentVault.app, agent-vault-bridge, agent-vault-broker")
    install.add_argument("--client-uid", type=int, required=True)
    install.add_argument("--approval-key-file", required=True, help="output of AgentVault --print-approval-public-key")
    install.add_argument("--approval-key-sha256", required=True, help="fingerprint shown by the app, typed by the operator")
    install.add_argument("--upgrade", action="store_true", help="allow new code pins over an existing configuration")
    install.add_argument("--replace-client-uid", type=int, metavar="CURRENT_UID")
    install.add_argument("--replace-approval-key", metavar="CURRENT_SHA256")
    commands.add_parser("verify")
    commands.add_parser("uninstall")
    init = commands.add_parser("sandbox-init")
    init.add_argument("--client-uid", type=int, required=True)
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    sandbox = None
    try:
        if args.command == "sandbox-init":
            require(args.sandbox is not None, "sandbox-init needs --sandbox DIR")
            Sandbox.create(args.sandbox, args.client_uid)
            print(f"sandbox ready: {args.sandbox}")
            return 0
        if args.sandbox:
            sandbox = Sandbox(args.sandbox)
            host = sandbox.host
        else:
            host = live_host()
        installer = Installer(host)
        if args.command == "install":
            with open(args.approval_key_file, "rb") as handle:
                key = approval_key(handle.read(4096), args.approval_key_sha256)
            changes = installer.install(args, key)
            print("installed: " + (", ".join(changes) if changes else "already current"))
        elif args.command == "verify":
            installer.acquire()
            try:
                installer.verify_installed()
            finally:
                installer.release()
            print("verified: installed files, pins, seeds and plist match")
        else:
            removed = installer.uninstall()
            print("removed: " + (", ".join(removed) if removed else "nothing")
                  + f"; kept /private/var/db/agent-vault and the {ACCOUNT} account")
        return 0
    except Refusal as error:
        print(f"agentvault-installer: refused: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"agentvault-installer: stopped: {error.strerror}; rerun the same command to resume", file=sys.stderr)
        return 1
    finally:
        if sandbox is not None:
            sandbox.save()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
