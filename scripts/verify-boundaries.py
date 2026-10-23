#!/usr/bin/env python3
"""Check the package graph, rather than source naming, for secret-store boundaries."""
import importlib.util
import functools
import json
import os
import re
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Experimental codec and storage packages stay isolated until their integration is approved.
QUARANTINED_PACKAGES = ("VaultCore", "VaultPersistence")


def _quarantined_name(value):
    return value.casefold() in {name.casefold() for name in QUARANTINED_PACKAGES}


class FixtureBoundaryError(RuntimeError):
    """Fixed public code; never include paths, source bytes or tool diagnostics."""


def _text(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise FixtureBoundaryError("fixture_graph_invalid")
    return value


def _names(value):
    if not isinstance(value, list):
        raise FixtureBoundaryError("fixture_graph_invalid")
    return [_text(item) for item in value]


def _identity(path):
    info = path.stat()
    return info.st_dev, info.st_ino


def _fixture_path(root, path):
    """Directory identity survives symlinks and case aliases on insensitive volumes."""
    fixtures = set()
    for name in QUARANTINED_PACKAGES:
        portable = root / "Packages" / name
        if not portable.is_dir():
            raise FixtureBoundaryError("fixture_input_unavailable")
        fixtures.add(_identity(portable))
    path = path.resolve(strict=True)
    return any(_identity(parent) in fixtures for parent in (path, *path.parents))


def _controlled_path(root, value):
    path = Path(_text(value))
    if path.is_absolute() or ".." in path.parts:
        raise FixtureBoundaryError("fixture_source_path")
    current = root
    for part in path.parts:
        current = current / part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise FixtureBoundaryError("fixture_source_symlink")
    if _fixture_path(root, current):
        raise FixtureBoundaryError("fixture_source_path")
    return current


def _dependency_source_path(root, value, fixture_root):
    path = Path(_text(value))
    if path.is_absolute() or ".." in path.parts:
        raise FixtureBoundaryError("fixture_source_path")
    path = (root / path).resolve(strict=True)
    if _fixture_path(fixture_root, path):
        raise FixtureBoundaryError("fixture_source_path")
    return path


def _scan(path):
    """Do not follow even an otherwise uninteresting entry's symlink."""
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise FixtureBoundaryError("fixture_source_symlink")
    if stat.S_ISDIR(mode):
        with os.scandir(path) as entries:
            for entry in entries:
                _scan(Path(entry.path))
    elif stat.S_ISREG(mode):
        if path.suffix == ".swift":
            # Conservative identifiers also catch attributed/declaration-specific imports.
            tokens = "|".join(re.escape(name) for name in (*QUARANTINED_PACKAGES, "AVSEAL01", "AVMEMB01", "AVTPIN03"))
            if re.search(r"\b(?:" + tokens + r")\b", path.read_text(encoding="utf-8")):
                raise FixtureBoundaryError("fixture_source_reference")
    else:
        raise FixtureBoundaryError("fixture_source_invalid")


def _base_sources(root):
    manifest = _controlled_path(root, "Package.swift")
    if not stat.S_ISREG(manifest.lstat().st_mode):
        raise FixtureBoundaryError("fixture_source_invalid")
    # Read the manifest, but linkage is decided from SwiftPM, not a manifest regex.
    manifest.read_text(encoding="utf-8")
    for name in ("Sources", "Tests"):
        path = _controlled_path(root, name)
        if not path.is_dir():
            raise FixtureBoundaryError("fixture_source_invalid")
        _scan(path)


def _check_resolved_dependencies(root, package, resolved):
    """Validate SwiftPM show-dependencies' nested tree, including repeated nodes."""
    todo = [(resolved, ())]
    packages = {}
    count = 0
    while todo:
        node, ancestors = todo.pop()
        count += 1
        if count > 4096 or len(ancestors) > 64 or not isinstance(node, dict):
            raise FixtureBoundaryError("fixture_graph_invalid")
        identity, name = _text(node.get("identity")), _text(node.get("name"))
        _text(node.get("url"))
        _text(node.get("version"))
        path = Path(_text(node.get("path")))
        if not path.is_absolute():
            raise FixtureBoundaryError("fixture_graph_invalid")
        path = path.resolve(strict=True)
        identity_key = _identity(path)
        if not path.is_dir() or identity_key in ancestors:
            raise FixtureBoundaryError("fixture_graph_invalid")
        if _quarantined_name(identity) or _quarantined_name(name) or _fixture_path(root, path):
            raise FixtureBoundaryError("fixture_dependency")
        children = node.get("dependencies")
        if not isinstance(children, list):
            raise FixtureBoundaryError("fixture_graph_invalid")
        if not ancestors:
            if identity_key != _identity(root):
                raise FixtureBoundaryError("fixture_graph_invalid")
            # A missing top-level branch must not silently turn a partial tree green.
            if any(not isinstance(child, dict) for child in children):
                raise FixtureBoundaryError("fixture_graph_invalid")
            if {_text(child.get("identity")) for child in children} != {
                    _text(dependency.get("identity")) for dependency in package["dependencies"]}:
                raise FixtureBoundaryError("fixture_graph_invalid")
        else:
            packages.setdefault(identity_key, path)
        if len(children) > 4096 - count - len(todo):
            raise FixtureBoundaryError("fixture_graph_invalid")
        todo.extend((child, (*ancestors, identity_key)) for child in children)
    # Check every occurrence above before deduplicating the actual describe queries.
    for path in packages.values():
        dependency = _read_graph(path, _describe)
        _package_shape(path, dependency)
        _check_compiler_inputs(root, path, dependency, scan=False)


def _package_shape(root, package):
    if not isinstance(package, dict):
        raise FixtureBoundaryError("fixture_graph_invalid")
    path = Path(_text(package.get("path")))
    if not path.is_absolute() or _identity(path) != _identity(root):
        raise FixtureBoundaryError("fixture_graph_invalid")
    for key in ("dependencies", "products", "targets"):
        if not isinstance(package.get(key), list):
            raise FixtureBoundaryError("fixture_graph_invalid")
    if not package["targets"]:
        raise FixtureBoundaryError("fixture_graph_invalid")


def _check_compiler_inputs(fixture_root, root, package, *, scan):
    for product in package["products"]:
        if not isinstance(product, dict):
            raise FixtureBoundaryError("fixture_graph_invalid")
        if any(_quarantined_name(name) for name in [_text(product.get("name")), *_names(product.get("targets"))]):
            raise FixtureBoundaryError("fixture_dependency")
    seen = set()
    for target in package["targets"]:
        if not isinstance(target, dict):
            raise FixtureBoundaryError("fixture_graph_invalid")
        name = _text(target.get("name"))
        if name in seen:
            raise FixtureBoundaryError("fixture_graph_invalid")
        seen.add(name)
        _text(target.get("type"))
        _text(target.get("module_type"))
        references = [name, _text(target.get("c99name"))]
        for key in ("target_dependencies", "product_dependencies", "product_memberships"):
            references.extend(_names(target.get(key, [])))
        if any(_quarantined_name(name) for name in references):
            raise FixtureBoundaryError("fixture_dependency")
        relative = Path(_text(target.get("path")))
        path = (_controlled_path(root, str(relative)) if scan else
                _dependency_source_path(root, str(relative), fixture_root))
        if not path.is_dir():
            raise FixtureBoundaryError("fixture_source_invalid")
        if scan:
            _scan(path)
        for source in _names(target.get("sources")):
            # Validate source spelling before joining: absolute paths must not replace the target.
            source = Path(source)
            if source.is_absolute() or ".." in source.parts:
                raise FixtureBoundaryError("fixture_source_path")
            file = (_controlled_path(root, str(relative / source)) if scan else
                    _dependency_source_path(root, str(relative / source), fixture_root))
            if not stat.S_ISREG(file.stat().st_mode):
                raise FixtureBoundaryError("fixture_source_invalid")


def check_fixture_boundary(root, package, resolved=None):
    """Semantic guard for actual SwiftPM describe and resolved trees; safe under -O."""
    try:
        root = Path(root).resolve(strict=True)
        _base_sources(root)
        _package_shape(root, package)
        for dependency in package["dependencies"]:
            if not isinstance(dependency, dict):
                raise FixtureBoundaryError("fixture_graph_invalid")
            if _quarantined_name(_text(dependency.get("identity"))):
                raise FixtureBoundaryError("fixture_dependency")
            kind = dependency.get("type")
            if kind == "fileSystem":
                # Identity and package aliases do not substitute for real path identity.
                path = Path(_text(dependency.get("path")))
                dependency_path = (root / path).resolve(strict=True)
                if _fixture_path(root, dependency_path):
                    raise FixtureBoundaryError("fixture_dependency")
                if not dependency_path.is_dir():
                    raise FixtureBoundaryError("fixture_graph_invalid")
            elif kind == "sourceControl":
                _text(dependency.get("url"))
                if not isinstance(dependency.get("requirement"), dict) or not dependency["requirement"]:
                    raise FixtureBoundaryError("fixture_graph_invalid")
            else:
                raise FixtureBoundaryError("fixture_graph_invalid")
        _check_compiler_inputs(root, root, package, scan=True)
        _scan(root / "Package.swift")
        _check_resolved_dependencies(root, package, resolved)
    except (OSError, UnicodeError, ValueError, RuntimeError) as error:
        if isinstance(error, FixtureBoundaryError):
            raise
        raise FixtureBoundaryError("fixture_input_unavailable") from None


@functools.cache
def _owned_helper():
    spec = importlib.util.spec_from_file_location(
        "boundary_owned_process", ROOT / "scripts/verify-webhost-link-mutations.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def _swiftpm(root, arguments):
    return _owned_helper().run_owned(
        ["swift", "package", "--force-resolved-versions", *arguments], timeout=120, cwd=root)


def _describe(root):
    return _swiftpm(root, ["describe", "--type", "json"])


def _show_dependencies(root):
    # SwiftPM diagnostics share run_owned's captured stream. JSON has its own private file.
    with tempfile.TemporaryDirectory(prefix="fixture-graph-") as directory:
        path = Path(directory) / "dependencies.json"
        with path.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
        code, _diagnostics = _swiftpm(
            root, ["show-dependencies", "--format", "json", "--output-path", str(path)])
        if code != 0:
            return code, ""
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise FixtureBoundaryError("fixture_graph_invalid")
        return code, path.read_text(encoding="utf-8")


def _read_graph(root, query):
    """Query metadata only; root source preflight belongs to the public readers."""
    try:
        code, output = query(root)
    except FixtureBoundaryError:
        raise
    except (OSError, UnicodeError, RuntimeError, ImportError):
        raise FixtureBoundaryError("fixture_graph_unavailable") from None
    if code != 0:
        raise FixtureBoundaryError("fixture_graph_unavailable")
    if not isinstance(output, str) or len(output) > 8 * 1024 * 1024:
        raise FixtureBoundaryError("fixture_graph_invalid")
    try:
        return json.loads(output)
    except (ValueError, TypeError, RecursionError):
        raise FixtureBoundaryError("fixture_graph_invalid") from None


def read_package(root):
    _preflight(root)
    return _read_graph(root, _describe)


def read_resolved_dependencies(root):
    _preflight(root)
    return _read_graph(root, _show_dependencies)


def _preflight(root):
    try:
        _base_sources(root)
    except FixtureBoundaryError:
        raise
    except (OSError, UnicodeError, RuntimeError):
        raise FixtureBoundaryError("fixture_graph_unavailable") from None


def main():
    if not __debug__:
        raise SystemExit("boundary_optimization_forbidden")
    try:
        package = read_package(ROOT)
        check_fixture_boundary(ROOT, package, read_resolved_dependencies(ROOT))
    except FixtureBoundaryError as error:
        raise SystemExit(str(error)) from None
    targets = {target["name"]: set(target.get("target_dependencies", [])) for target in package["targets"]}
    kinds = {target["name"]: target["type"] for target in package["targets"]}
    credential_spec = importlib.util.spec_from_file_location("credential_boundaries", ROOT / "scripts/credential_boundaries.py")
    credential_guard = importlib.util.module_from_spec(credential_spec)
    credential_spec.loader.exec_module(credential_guard)
    credential_guard.check_credentials(ROOT, targets, package["targets"])

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
