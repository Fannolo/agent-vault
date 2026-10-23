"""Synthetic fixture-only boundary controls; no root Swift build or live service."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load("fixture_boundary", ROOT / "scripts/verify-boundaries.py")
owned = load("fixture_owned", ROOT / "scripts/verify-webhost-link-mutations.py")


class FixtureBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.old_umask = os.umask(0o077)
        self.directory = tempfile.TemporaryDirectory(prefix="guard-test-")
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(os.umask, self.old_umask)
        self.root = Path(self.directory.name).resolve()
        self.swift_state = self.root / ".swift-state"
        self.commands = []
        environment = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file",
                       "CLANG_MODULE_CACHE_PATH": str(self.swift_state / "module-cache"),
                       "SWIFTPM_MODULECACHE_OVERRIDE": str(self.swift_state / "module-cache")}
        env_patch = patch.dict(os.environ, environment)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        runner_patch = patch.object(guard._owned_helper(), "run_owned", side_effect=self.run_command)
        runner_patch.start()
        self.addCleanup(runner_patch.stop)
        self.write("Package.swift", "// synthetic fixture\n")
        self.write("Sources/App/App.swift", "import Foundation\n")
        self.write("Tests/AppTests/Tests.swift", "import Foundation\n")
        self.write("Packages/VaultCore/Sources/VaultCore/Codec.swift", "// VaultCore AVSEAL01 AVMEMB01\n")
        self.write("Packages/VaultRecord/Sources/VaultRecord/Record.swift", "// unreviewed codec\n")
        self.write("Packages/VaultPersistence/Sources/VaultPersistence/Record.swift", "// unreviewed codec\n")
        # Field shapes measured from SwiftPM describe, also exercised below on real fixtures.
        self.graph = {
            "path": str(self.root), "dependencies": [], "products": [],
            "targets": [{"name": "App", "c99name": "App", "type": "library",
                         "module_type": "SwiftTarget", "path": "Sources/App", "sources": ["App.swift"]}]
        }
        self.resolved = self.node(self.root, "guard-fixture", "GuardFixture")

    def node(self, path, identity, name, dependencies=None):
        return {"identity": identity, "name": name, "url": str(path), "version": "unspecified",
                "path": str(path), "dependencies": [] if dependencies is None else dependencies}

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def run_command(self, command, timeout=120, cwd=None):
        cwd = self.root if cwd is None else Path(cwd)
        if command[:2] == ["swift", "package"]:
            state = self.swift_state / hashlib.sha256(str(cwd).encode()).hexdigest()[:16]
            command = [*command[:2], "--scratch-path", str(state / "scratch"),
                       "--cache-path", str(state / "cache"), "--config-path", str(state / "config"),
                       "--security-path", str(state / "security"), *command[2:]]
        code, output = owned.run_owned(command, timeout=timeout, cwd=cwd)
        self.commands.append((command, code, output))
        return code, output

    def utility(self, directory, name="Utility"):
        self.write(directory + "/Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   f'let package = Package(name: "{name}", targets: [.target(name: "{name}")])\n')
        self.write(directory + f"/Sources/{name}/Unit.swift", "// unrelated dependency\n")

    def check(self):
        guard.check_fixture_boundary(self.root, self.graph, self.resolved)

    def rejected(self, code):
        with self.assertRaises(guard.FixtureBoundaryError) as caught:
            self.check()
        self.assertEqual(str(caught.exception), code)

    def test_missing_fixture_anchor_fails_closed(self):
        anchor = self.root / "Packages/VaultCore"
        anchor.rename(self.root / "Packages/MovedCodec")
        self.rejected("fixture_input_unavailable")

    def test_fixture_anchor_must_be_directory(self):
        anchor = self.root / "Packages/VaultCore"
        anchor.rename(self.root / "Packages/MovedCodec")
        anchor.write_text("not a directory")
        self.rejected("fixture_input_unavailable")

    def test_unreviewed_storage_imports_are_quarantined(self):
        for statement in ("import VaultPersistence", "@testable import VaultPersistence",
                          'import class VaultPersistence.VaultKernel', 'let marker = "AVTPIN03"'):
            with self.subTest(statement=statement):
                path = self.write("Sources/App/Record.swift", statement + "\n")
                self.rejected("fixture_source_reference")
                path.unlink()

    def test_unreviewed_storage_alias_and_wrapper_compiler_paths_are_quarantined(self):
        canonical = self.root / "Packages/VaultPersistence"
        (self.root / "RecordAlias").symlink_to(canonical, target_is_directory=True)
        self.graph["dependencies"] = [{"identity": "recordalias", "type": "fileSystem", "path": "RecordAlias"}]
        self.resolved["dependencies"] = [self.node(canonical, "recordalias", "Renamed")]
        self.rejected("fixture_dependency")
        # An ancestor package compiling the canonical files under another module name.
        self.utility("Packages", "Wrapper")
        self.graph["dependencies"] = [{"identity": "packages", "type": "fileSystem", "path": "Packages"}]
        self.resolved["dependencies"] = [self.node(self.root / "Packages", "packages", "Wrapper")]
        dependency = {"path": str(self.root / "Packages"), "dependencies": [], "products": [],
                      "targets": [{"name": "Codec", "c99name": "Codec", "type": "library",
                                   "module_type": "SwiftTarget", "path": "VaultPersistence/Sources/VaultPersistence",
                                   "sources": ["Record.swift"]}]}
        with patch.object(guard, "_read_graph", return_value=dependency):
            self.rejected("fixture_source_path")

    def test_unreviewed_storage_anchor_and_names_fail_closed(self):
        self.graph["products"] = [{"name": "VaultPersistence", "targets": ["App"]}]
        self.rejected("fixture_dependency")
        self.graph["products"] = []
        anchor = self.root / "Packages/VaultPersistence"
        anchor.rename(self.root / "Packages/RenamedRecord")
        self.rejected("fixture_input_unavailable")


    def test_unreviewed_record_imports_are_quarantined(self):
        for statement in ("import VaultRecord", "@testable import VaultRecord",
                          "import struct VaultRecord.Record"):
            with self.subTest(statement=statement):
                path = self.write("Sources/App/Record.swift", statement + "\n")
                self.rejected("fixture_source_reference")
                path.unlink()

    def test_unreviewed_record_alias_and_wrapper_compiler_paths_are_quarantined(self):
        canonical = self.root / "Packages/VaultRecord"
        (self.root / "RecordAlias").symlink_to(canonical, target_is_directory=True)
        self.graph["dependencies"] = [{"identity": "recordalias", "type": "fileSystem", "path": "RecordAlias"}]
        self.resolved["dependencies"] = [self.node(canonical, "recordalias", "Renamed")]
        self.rejected("fixture_dependency")
        # An ancestor package compiling the canonical files under another module name.
        self.utility("Packages", "Wrapper")
        self.graph["dependencies"] = [{"identity": "packages", "type": "fileSystem", "path": "Packages"}]
        self.resolved["dependencies"] = [self.node(self.root / "Packages", "packages", "Wrapper")]
        dependency = {"path": str(self.root / "Packages"), "dependencies": [], "products": [],
                      "targets": [{"name": "Codec", "c99name": "Codec", "type": "library",
                                   "module_type": "SwiftTarget", "path": "VaultRecord/Sources/VaultRecord",
                                   "sources": ["Record.swift"]}]}
        with patch.object(guard, "_read_graph", return_value=dependency):
            self.rejected("fixture_source_path")

    def test_unreviewed_record_anchor_and_names_fail_closed(self):
        self.graph["products"] = [{"name": "VaultRecord", "targets": ["App"]}]
        self.rejected("fixture_dependency")
        self.graph["products"] = []
        anchor = self.root / "Packages/VaultRecord"
        anchor.rename(self.root / "Packages/RenamedRecord")
        self.rejected("fixture_input_unavailable")

    def test_unrelated_manifest_dependency_and_target_maintenance_passes(self):
        self.write("Package.swift", "// unrelated manifest maintenance\nimport PackageDescription\n")
        self.utility("LocalUtility")
        self.graph["dependencies"] = [{"identity": "utility", "type": "fileSystem", "path": "LocalUtility"},
                                      {"identity": "logging", "type": "sourceControl", "url": "https://example.invalid/logging.git",
                                       "requirement": {"exact": ["1.0.0"]}}]
        self.utility(".build/checkouts/logging", "Logging")
        remote = self.node(self.root / ".build/checkouts/logging", "logging", "Logging")
        remote.update(url="https://example.invalid/logging.git", version="1.0.0")
        self.resolved["dependencies"] = [self.node(self.root / "LocalUtility", "utility", "Utility"), remote]
        self.write("Custom/Extra/Extra.swift", "public struct Extra {}\n")
        self.graph["targets"].append({"name": "Extra", "c99name": "Extra", "type": "library",
                                       "module_type": "SwiftTarget", "path": "Custom/Extra", "sources": ["Extra.swift"],
                                       "product_dependencies": ["Logging"], "target_dependencies": ["App"]})
        self.graph["products"] = [{"name": "Useful", "targets": ["Extra"]}]
        self.check()

    def test_direct_and_attributed_imports_in_sources_and_tests(self):
        for tree in ("Sources/App", "Tests/AppTests"):
            for statement in ("import VaultCore", "@testable import VaultCore", "@_exported import VaultCore",
                              "@_implementationOnly import VaultCore", "import struct VaultCore.LoginItem"):
                with self.subTest(tree=tree, statement=statement):
                    file = self.write(tree + "/Injected.swift", statement + "\n")
                    self.rejected("fixture_source_reference")
                    file.unlink()

    def test_wire_tokens_in_both_trees_are_rejected(self):
        for tree in ("Sources/App", "Tests/AppTests"):
            for token in ("AVSEAL01", "AVMEMB01"):
                with self.subTest(tree=tree, token=token):
                    file = self.write(tree + "/Token.swift", 'let magic = "' + token + '"\n')
                    self.rejected("fixture_source_reference")
                    file.unlink()

    def test_manifest_import_and_wire_tokens_are_rejected(self):
        for text in ("import VaultCore", 'let wire = "AVSEAL01"', 'let wire = "AVMEMB01"'):
            with self.subTest(text=text):
                self.write("Package.swift", text + "\n")
                self.rejected("fixture_source_reference")

    def test_only_controlled_paths_are_scanned(self):
        for name in (".git", ".swiftpm", ".build", "dist", "runtime", "verification-logs", "generated"):
            self.write(name + "/Ignored.swift", "import VaultCore\n")
            (self.root / name / "alias").symlink_to(self.root / "Packages/VaultCore", target_is_directory=True)
        self.check()

    def test_generated_custom_target_is_controlled(self):
        self.write("generated/Extra/Extra.swift", "import VaultCore\n")
        self.graph["targets"][0].update(path="generated/Extra", sources=["Extra.swift"])
        self.rejected("fixture_source_reference")

    def test_dependency_paths_resolve_independently_of_identity(self):
        (self.root / "Alias").symlink_to("Packages/VaultCore", target_is_directory=True)
        for path in ("Packages/VaultCore", str(self.root / "Packages/VaultCore"), "Alias"):
            with self.subTest(path=path):
                self.graph["dependencies"] = [{"identity": "innocent-name", "type": "fileSystem", "path": path}]
                self.rejected("fixture_dependency")

    def test_module_target_product_and_dependency_identity_are_rejected(self):
        baseline = copy.deepcopy(self.graph)
        for field in ("name", "c99name", "target_dependencies", "product_dependencies", "product_memberships"):
            with self.subTest(field=field):
                self.graph = copy.deepcopy(baseline)
                self.graph["targets"][0][field] = "VaultCore" if field in ("name", "c99name") else ["VaultCore"]
                self.rejected("fixture_dependency")
        for product in ({"name": "VaultCore", "targets": ["App"]}, {"name": "Other", "targets": ["VaultCore"]}):
            self.graph = copy.deepcopy(baseline)
            self.graph["products"] = [product]
            self.rejected("fixture_dependency")
        self.graph = copy.deepcopy(baseline)
        self.graph["dependencies"] = [{"identity": "vaultcore", "type": "sourceControl",
                                       "url": "https://example.invalid/renamed", "requirement": {"exact": ["1.0.0"]}}]
        self.rejected("fixture_dependency")

    def test_source_file_and_directory_symlinks_are_rejected(self):
        for tree in ("Sources/App", "Tests/AppTests"):
            for target in ("Packages/VaultCore/Sources/VaultCore/Codec.swift", "Packages/VaultCore"):
                with self.subTest(tree=tree, target=target):
                    link = self.root / tree / "alias"
                    link.symlink_to(self.root / target)
                    self.rejected("fixture_source_symlink")
                    link.unlink()

    def test_source_tree_symlinks_are_rejected(self):
        for tree in ("Sources", "Tests"):
            with self.subTest(tree=tree):
                directory = self.root / tree
                saved = self.root / (tree + "-saved")
                directory.rename(saved)
                directory.symlink_to("Packages/VaultCore", target_is_directory=True)
                self.rejected("fixture_source_symlink")
                directory.unlink()
                saved.rename(directory)

    def test_manifest_symlink_refused_before_graph_command(self):
        manifest = self.root / "Package.swift"
        manifest.unlink()
        manifest.symlink_to("Packages/VaultCore/Sources/VaultCore/Codec.swift")
        with patch.object(guard, "_describe") as describe:
            with self.assertRaisesRegex(guard.FixtureBoundaryError, "^fixture_source_symlink$"):
                guard.read_package(self.root)
            describe.assert_not_called()

    def test_target_paths_cannot_escape_or_enter_portable_package(self):
        for path in ("../outside", str(self.root / "Sources/App"), "Packages/VaultCore/Sources/VaultCore"):
            with self.subTest(path=path):
                self.graph["targets"][0]["path"] = path
                self.rejected("fixture_source_path")

    def test_custom_target_ancestor_symlink_is_rejected(self):
        (self.root / "Custom").symlink_to("Packages/VaultCore", target_is_directory=True)
        self.graph["targets"][0]["path"] = "Custom/Sources/VaultCore"
        self.rejected("fixture_source_symlink")

    def test_graph_source_paths_cannot_escape_target_or_root(self):
        for path in ("../App/App.swift", "/outside.swift", "../../../outside.swift"):
            with self.subTest(path=path):
                self.graph["targets"][0]["sources"] = [path]
                self.rejected("fixture_source_path")

    def test_missing_roots_manifest_target_and_declared_source_fail_closed(self):
        for relative in ("Sources", "Tests", "Package.swift", "Sources/App", "Sources/App/App.swift"):
            with self.subTest(path=relative):
                path = self.root / relative
                saved = self.root / "saved"
                path.rename(saved)
                self.rejected("fixture_input_unavailable")
                saved.rename(path)
        self.graph["targets"][0]["sources"] = ["Missing.swift"]
        self.rejected("fixture_input_unavailable")

    def test_unreadable_source_and_manifest_fail_closed(self):
        original = Path.read_text
        for relative in ("Sources/App/App.swift", "Package.swift"):
            def read(path, *args, **kwargs):
                if path == self.root / relative:
                    raise PermissionError("external diagnostic must stay private")
                return original(path, *args, **kwargs)
            with self.subTest(path=relative), patch.object(Path, "read_text", read):
                self.rejected("fixture_input_unavailable")

    def test_traversal_failure_is_not_silently_skipped(self):
        original = os.scandir
        def scan(path):
            if Path(path) == self.root / "Tests/AppTests":
                raise OSError("external diagnostic must stay private")
            return original(path)
        with patch.object(guard.os, "scandir", scan):
            self.rejected("fixture_input_unavailable")

    def test_malformed_and_missing_graph_schema_fail_closed(self):
        baseline = copy.deepcopy(self.graph)
        graphs = [None, [], {}, {**baseline, "targets": []}, {**baseline, "dependencies": None},
                  {**baseline, "products": None}, {**baseline, "path": "/"},
                  {**baseline, "targets": [baseline["targets"][0]] * 2}]
        for key in ("targets", "dependencies", "products", "path"):
            graph = copy.deepcopy(baseline)
            del graph[key]
            graphs.append(graph)
        for key in ("name", "c99name", "type", "module_type", "path", "sources"):
            graph = copy.deepcopy(baseline)
            del graph["targets"][0][key]
            graphs.append(graph)
        for key in ("target_dependencies", "product_dependencies", "sources"):
            graph = copy.deepcopy(baseline)
            graph["targets"][0][key] = [None]
            graphs.append(graph)
        for dependency in ({}, {"type": "registry", "identity": "unknown"},
                           {"type": "fileSystem", "identity": "local"},
                           {"type": "sourceControl", "identity": "remote", "url": "x"}):
            graphs.append({**baseline, "dependencies": [dependency]})
        for graph in graphs:
            with self.subTest(graph=graph):
                self.graph = graph
                self.rejected("fixture_graph_invalid")

    def test_command_failure_timeout_and_malformed_output_use_fixed_codes(self):
        for response, expected in (((1, "private external stderr"), "fixture_graph_unavailable"),
                                   ((None, "timeout private"), "fixture_graph_unavailable"),
                                   ((0, "not json private"), "fixture_graph_invalid")):
            with self.subTest(response=response), patch.object(guard, "_describe", return_value=response):
                with self.assertRaisesRegex(guard.FixtureBoundaryError, "^" + expected + "$"):
                    guard.read_package(self.root)
        for error in (OSError("private spawn failure"), RuntimeError("private cleanup failure")):
            with patch.object(guard, "_describe", side_effect=error):
                with self.assertRaisesRegex(guard.FixtureBoundaryError, "^fixture_graph_unavailable$"):
                    guard.read_package(self.root)

    def test_entrypoint_optimized_refuses_before_graph_even_for_valid_tree(self):
        program = ("import importlib.util; "
                   f"s=importlib.util.spec_from_file_location('guard', {str(ROOT / 'scripts/verify-boundaries.py')!r}); "
                   "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                   "m.read_package=lambda _: (_ for _ in ()).throw(RuntimeError('GRAPH_WAS_QUERIED')); m.main()")
        code, output = owned.run_owned([sys.executable, "-I", "-O", "-c", program], timeout=30, cwd=self.root)
        self.assertEqual(code, 1)
        self.assertEqual(output.strip(), "boundary_optimization_forbidden")

    def describe_fixture(self):
        return guard.read_package(self.root)

    def resolve_fixture(self):
        return guard.read_resolved_dependencies(self.root)

    def test_actual_local_alias_product_module_alias_and_custom_path_schema(self):
        self.write("Packages/VaultCore/Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "VaultCore", products: [.library(name: "VaultCore", targets: ["VaultCore"])], '
                   'targets: [.target(name: "VaultCore")])\n')
        self.write("generated/Extra/Extra.swift", "public struct Extra {}\n")
        (self.root / "Alias").symlink_to("Packages/VaultCore", target_is_directory=True)
        for dependency_path in ("Packages/VaultCore", "Alias"):
            with self.subTest(path=dependency_path):
                self.write("Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                           'let package = Package(name: "GuardFixture", dependencies: ['
                           f'.package(name: "PortableAlias", path: "{dependency_path}")], targets: ['
                           '.target(name: "Extra", dependencies: [.product(name: "VaultCore", package: "PortableAlias", '
                           'moduleAliases: ["VaultCore": "Renamed"])], path: "generated/Extra")])\n')
                self.graph = self.describe_fixture()
                dependency = self.graph["dependencies"][0]
                self.assertEqual(dependency["type"], "fileSystem")
                self.assertEqual(Path(dependency["path"]).resolve(), self.root / "Packages/VaultCore")
                target = self.graph["targets"][0]
                self.assertEqual(target["product_dependencies"], ["VaultCore"])
                self.assertEqual(target["path"], "generated/Extra")
                self.assertEqual(target["sources"], ["Extra.swift"])
                self.rejected("fixture_dependency")
                self.graph["dependencies"] = []  # Isolate the independently measured product check.
                self.rejected("fixture_dependency")

    def test_actual_unrelated_manifest_maintenance_passes(self):
        self.write("Utility/Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "Utility", products: [.library(name: "Utility", targets: ["Utility"])], '
                   'targets: [.target(name: "Utility")])\n')
        self.write("Utility/Sources/Utility/Utility.swift", "public struct Utility {}\n")
        self.write("generated/Extra/Extra.swift", "import Utility\n")
        self.write("Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "MaintainedFixture", products: [.library(name: "Extra", targets: ["Extra"])], '
                   'dependencies: [.package(path: "Utility")], targets: ['
                   '.target(name: "Extra", dependencies: [.product(name: "Utility", package: "Utility")], path: "generated/Extra")])\n')
        self.graph = self.describe_fixture()
        self.resolved = self.resolve_fixture()
        self.check()

    def wrapper_fixture(self, *, forbidden, alias=False):
        module = "VaultCore" if forbidden else "Utility"
        directory = "Packages/VaultCore" if forbidden else "Utility"
        self.write(directory + "/Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   f'let package = Package(name: "{module}", products: [.library(name: "{module}", '
                   f'targets: ["{module}"])], targets: [.target(name: "{module}")])\n')
        self.write(directory + f"/Sources/{module}/Unit.swift", "public struct Unit {}\n")
        if alias:
            (self.root / "Alias").symlink_to(directory, target_is_directory=True)
        dependency = "Alias" if alias else directory
        package_alias = "Alias" if alias else "PortableAlias"
        aliases = f', moduleAliases: ["{module}": "Renamed"]' if alias else ""
        self.write("Wrapper/Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "Wrapper", products: [.library(name: "Wrapper", targets: ["Wrapper"])], '
                   f'dependencies: [.package(name: "{package_alias}", path: "../{dependency}")], '
                   'targets: [.target(name: "Wrapper", dependencies: ['
                   f'.product(name: "{module}", package: "{package_alias}"{aliases})])])\n')
        self.write("Wrapper/Sources/Wrapper/Unit.swift", f'import {"Renamed" if alias else module}\n')
        self.write("Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "Probe", products: [.library(name: "App", targets: ["App"])], '
                   'dependencies: [.package(path: "Wrapper")], '
                   'targets: [.target(name: "App", dependencies: [.product(name: "Wrapper", package: "Wrapper")])])\n')
        self.write("Sources/App/App.swift", "import Wrapper\n")
        self.graph = guard.read_package(self.root)
        self.resolved = self.resolve_fixture()
        self.assertEqual([d["identity"] for d in self.graph["dependencies"]], ["wrapper"])
        child = self.resolved["dependencies"][0]["dependencies"][0]
        self.assertEqual(child["name"], module)
        self.assertEqual(Path(child["path"]).resolve(), self.root / directory)
        for path in [self.root / "Package.swift", *self.root.glob("Sources/**/*.swift")]:
            self.assertNotIn("VaultCore", path.read_text())

    def test_actual_transitive_wrapper_is_rejected(self):
        self.wrapper_fixture(forbidden=True)
        self.rejected("fixture_dependency")

    def test_actual_transitive_package_path_and_module_alias_is_rejected(self):
        self.wrapper_fixture(forbidden=True, alias=True)
        self.rejected("fixture_dependency")

    def test_actual_safe_transitive_wrapper_passes(self):
        self.wrapper_fixture(forbidden=False)
        self.check()

    def test_actual_safe_transitive_module_alias_passes(self):
        self.wrapper_fixture(forbidden=False, alias=True)
        self.check()

    def resolved_wrapper(self):
        self.utility("Wrapper", "Wrapper")
        self.utility("External", "External")
        self.graph["dependencies"] = [{"identity": "wrapper", "type": "fileSystem", "path": "Wrapper"}]
        child = self.node(self.root / "External", "external", "External")
        wrapper = self.node(self.root / "Wrapper", "wrapper", "Wrapper", [child])
        self.resolved["dependencies"] = [wrapper]
        return child

    def test_transitive_identity_name_and_real_path_are_independent_checks(self):
        child = self.resolved_wrapper()
        baseline = child.copy()
        for field in ("identity", "name"):
            with self.subTest(field=field):
                child[field] = "vAuLtCoRe"
                self.rejected("fixture_dependency")
                child.update(baseline)
        (self.root / "Alias").symlink_to("Packages/VaultCore", target_is_directory=True)
        for path in ("Packages/VaultCore", "Alias", "Packages/VaultCore/Sources/VaultCore"):
            with self.subTest(path=path):
                child["path"] = str(self.root / path)
                self.rejected("fixture_dependency")

    def test_safe_shared_nodes_pass_but_every_occurrence_is_checked(self):
        child = self.resolved_wrapper()
        shared = copy.deepcopy(child)
        self.resolved["dependencies"][0]["dependencies"].append(shared)
        self.check()
        self.assertEqual(len(self.commands), 2, "shared package should be described only once")
        shared["name"] = "VaultCore"
        self.rejected("fixture_dependency")

    def test_safe_fetched_dependency_path_alias_passes_without_source_scan(self):
        child = self.resolved_wrapper()
        self.write("External/Sources/Unit.swift", "// VaultCore is only mentioned in an external comment\n")
        (self.root / "FetchedAlias").symlink_to("External", target_is_directory=True)
        child.update(path=str(self.root / "FetchedAlias"), url="https://example.invalid/external.git", version="1.0.0")
        self.check()

    def test_missing_malformed_and_partial_resolved_trees_fail_closed(self):
        self.resolved_wrapper()
        baseline = copy.deepcopy(self.resolved)
        trees = [None, [], {}, {**baseline, "path": str(self.root / "Wrapper")},
                 {**baseline, "dependencies": []}]
        for key in ("identity", "name", "url", "version", "path", "dependencies"):
            for value in (None, 42, "" if key != "dependencies" else {}):
                tree = copy.deepcopy(baseline)
                tree["dependencies"][0]["dependencies"][0][key] = value
                trees.append(tree)
            tree = copy.deepcopy(baseline)
            del tree["dependencies"][0]["dependencies"][0][key]
            trees.append(tree)
        for value in ("External", str(self.root / "External/Package.swift")):
            tree = copy.deepcopy(baseline)
            tree["dependencies"][0]["dependencies"][0]["path"] = value
            trees.append(tree)
        for tree in trees:
            with self.subTest(tree=tree):
                self.resolved = tree
                self.rejected("fixture_graph_invalid")
        with self.assertRaisesRegex(guard.FixtureBoundaryError, "^fixture_graph_invalid$"):
            guard.check_fixture_boundary(self.root, self.graph)

    def test_unavailable_resolved_path_fails_closed(self):
        child = self.resolved_wrapper()
        child["path"] = str(self.root / "NotFetched")
        self.rejected("fixture_input_unavailable")

    def test_resolved_cycle_depth_and_node_limits_fail_closed(self):
        child = self.resolved_wrapper()
        child["dependencies"] = [self.resolved]
        self.rejected("fixture_graph_invalid")
        child["dependencies"] = [self.node(self.root / "External", "external", "External")] * 4097
        self.rejected("fixture_graph_invalid")
        current = child
        for index in range(65):
            path = self.write(f"Deep/{index}/Package.swift", "// deep dependency\n").parent
            next_node = self.node(path, f"deep-{index}", f"Deep{index}")
            current["dependencies"] = [next_node]
            current = next_node
        self.rejected("fixture_graph_invalid")

    def test_resolved_command_failure_timeout_and_malformed_output_fail_closed(self):
        for response, expected in (((1, "private stderr"), "fixture_graph_unavailable"),
                                   ((None, "private timeout"), "fixture_graph_unavailable"),
                                   ((0, None), "fixture_graph_invalid"),
                                   ((0, b"{}"), "fixture_graph_invalid"),
                                   ((0, "not JSON"), "fixture_graph_invalid"),
                                   ((0, "[" * 2000), "fixture_graph_invalid"),
                                   ((0, " " * (8 * 1024 * 1024 + 1)), "fixture_graph_invalid")):
            with self.subTest(expected=expected), patch.object(guard, "_show_dependencies", return_value=response):
                with self.assertRaisesRegex(guard.FixtureBoundaryError, "^" + expected + "$"):
                    guard.read_resolved_dependencies(self.root)
        for error in (OSError("private spawn"), RuntimeError("private cleanup")):
            with patch.object(guard, "_show_dependencies", side_effect=error):
                with self.assertRaisesRegex(guard.FixtureBoundaryError, "^fixture_graph_unavailable$"):
                    guard.read_resolved_dependencies(self.root)

    def test_main_requires_resolved_query_before_success(self):
        with patch.object(guard, "ROOT", self.root), patch.object(guard, "read_package", return_value=self.graph), \
                patch.object(guard, "_show_dependencies", return_value=(1, "private stderr")) as query:
            with self.assertRaises(SystemExit) as caught:
                guard.main()
            self.assertEqual(str(caught.exception), "fixture_graph_unavailable" if __debug__ else "boundary_optimization_forbidden")
            self.assertEqual(query.call_count, 1 if __debug__ else 0)

    def pinned_git_fixture(self):
        self.utility("LocalRemote", "Helper")
        manifest = self.root / "LocalRemote/Package.swift"
        manifest.write_text(manifest.read_text().replace('targets: [.target',
            'products: [.library(name: "Helper", targets: ["Helper"])], targets: [.target'))
        git = ["git", "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "core.hooksPath=/dev/null",
               "-c", "init.templateDir="]
        repo = self.root / "LocalRemote"
        self.assertEqual(self.run_command([*git, "init"], cwd=repo)[0], 0)
        for version in (1, 2):
            self.write("LocalRemote/Sources/Helper/Unit.swift", f"public let fixtureValue = {version}\n")
            for arguments in (["add", "Package.swift", "Sources"],
                              ["commit", "-m", f"Synthetic version {version}"], ["tag", f"{version}.0.0"]):
                self.assertEqual(self.run_command([*git, *arguments], cwd=repo)[0], 0)
        self.write("Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "Pinned", dependencies: ['
                   f'.package(url: "{repo.as_uri()}", exact: "1.0.0")], targets: ['
                   '.target(name: "App", dependencies: [.product(name: "Helper", package: "LocalRemote")])])\n')
        self.write("Sources/App/App.swift", "import Helper\npublic let value = fixtureValue\n")
        self.assertEqual(self.run_command(["swift", "package", "resolve"])[0], 0)
        self.pin = (self.root / "Package.resolved").read_bytes()
        self.assertEqual(json.loads(self.pin)["pins"][0]["state"]["version"], "1.0.0")
        # New scratch AND cache: the query must perform a real cold checkout of the valid pin.
        self.swift_state = self.root / ".cold-swift-state"
        self.commands.clear()

    def test_actual_cold_pinned_graph_uses_json_file_despite_diagnostics(self):
        self.pinned_git_fixture()
        self.graph = guard.read_package(self.root)
        self.resolved = guard.read_resolved_dependencies(self.root)
        self.assertEqual((self.root / "Package.resolved").read_bytes(), self.pin)
        command, code, diagnostics = self.commands[-1]
        self.assertEqual(code, 0)
        self.assertIn("Fetching", diagnostics)
        self.assertIn("Creating working copy", diagnostics)
        self.assertIn("--output-path", command)
        self.assertLess(command.index("--force-resolved-versions"), command.index("show-dependencies"))
        self.assertEqual(self.resolved["dependencies"][0]["version"], "1.0.0")
        self.check()
        self.assertEqual((self.root / "Package.resolved").read_bytes(), self.pin)
        self.assertTrue(all("--force-resolved-versions" in cmd for cmd, _, _ in self.commands))

    def test_actual_stale_pin_graph_refuses_without_rewriting_lock(self):
        self.pinned_git_fixture()
        manifest = self.root / "Package.swift"
        original = manifest.read_bytes()
        with owned.changed_source(manifest, original, original.replace(b'exact: "1.0.0"', b'exact: "2.0.0"')):
            guard.read_package(self.root)  # describe alone does not validate lock freshness.
            self.assertEqual((self.root / "Package.resolved").read_bytes(), self.pin)
            with self.assertRaisesRegex(guard.FixtureBoundaryError, "^fixture_graph_unavailable$"):
                guard.read_resolved_dependencies(self.root)
            self.assertEqual((self.root / "Package.resolved").read_bytes(), self.pin)
            self.assertEqual(self.commands[-1][1], 1)

    def compiler_fixture(self, layout, *, forbidden):
        stub = "public func probeValue() -> Int { 731 }\n"
        canonical = self.write("Packages/VaultCore/Sources/VaultCore/Codec.swift", stub)
        wrapper = "Packages" if layout == "ancestor" else "Wrapper"
        target_path = "VaultCore/Sources/VaultCore" if layout == "ancestor" and forbidden else "Sources/Codec"
        if layout in ("symlink", "source-symlink"):
            destination = canonical if forbidden else self.write("Safe/Codec.swift", stub)
            if layout == "symlink":
                link = self.root / wrapper / "Sources/Codec"
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(destination.parent, target_is_directory=True)
            else:
                link = self.root / wrapper / "Sources/Codec/Codec.swift"
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(destination)
        elif not forbidden:
            self.write(wrapper + "/Sources/Codec/Codec.swift", stub)
        self.write(wrapper + "/Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "Utility", products: [.library(name: "Codec", targets: ["Codec"])], '
                   f'targets: [.target(name: "Codec", path: "{target_path}")])\n')
        self.write("Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   f'let package = Package(name: "Probe", dependencies: [.package(path: "{wrapper}")], '
                   f'targets: [.target(name: "App", dependencies: [.product(name: "Codec", package: "{wrapper}")])])\n')
        self.write("Sources/App/App.swift", "import Codec\npublic let value = probeValue()\n")
        self.graph = guard.read_package(self.root)
        self.resolved = guard.read_resolved_dependencies(self.root)
        metadata = guard._read_graph(self.root / wrapper, guard._describe)
        target = metadata["targets"][0]
        compiler_input = self.root / wrapper / target["path"] / target["sources"][0]
        self.assertEqual(compiler_input.samefile(canonical), forbidden)
        self.assertEqual(compiler_input.read_text(), stub)
        self.assertEqual(target["name"], "Codec")

    def test_actual_ancestor_package_canonical_compiler_input_is_rejected(self):
        self.compiler_fixture("ancestor", forbidden=True)
        self.rejected("fixture_source_path")

    def test_actual_symlink_target_canonical_compiler_input_is_rejected(self):
        self.compiler_fixture("symlink", forbidden=True)
        self.rejected("fixture_source_path")

    def test_actual_symlink_source_canonical_compiler_input_is_rejected(self):
        self.compiler_fixture("source-symlink", forbidden=True)
        self.rejected("fixture_source_path")

    def test_actual_safe_ancestor_package_passes(self):
        self.compiler_fixture("ancestor", forbidden=False)
        self.check()

    def test_actual_safe_symlink_target_passes(self):
        self.compiler_fixture("symlink", forbidden=False)
        self.check()

    def test_actual_safe_symlink_source_passes(self):
        self.compiler_fixture("source-symlink", forbidden=False)
        self.check()

    def test_actual_case_alias_compiler_input_is_rejected_when_samefile(self):
        canonical = self.write("Packages/VaultCore/Sources/VaultCore/Codec.swift",
                               "public func probeValue() -> Int { 731 }\n")
        alias = self.root / "packages/vaultcore/sources/vaultcore/Codec.swift"
        if not alias.exists() or not alias.samefile(canonical):
            self.skipTest("filesystem does not alias this alternate-case compiler input")
        self.write("Package.swift", '// swift-tools-version: 6.2\nimport PackageDescription\n'
                   'let package = Package(name: "Probe", targets: ['
                   '.target(name: "Codec", path: "packages/vaultcore/sources/vaultcore")])\n')
        self.graph = guard.read_package(self.root)
        self.resolved = guard.read_resolved_dependencies(self.root)
        self.assertEqual(self.graph["targets"][0]["path"], "packages/vaultcore/sources/vaultcore")
        self.rejected("fixture_source_path")

    def test_dependency_metadata_paths_and_schema_fail_closed(self):
        self.compiler_fixture("ancestor", forbidden=False)
        wrapper = self.root / "Packages"
        baseline = guard._read_graph(wrapper, guard._describe)
        variants = [(None, "fixture_graph_invalid"), ({}, "fixture_graph_invalid")]
        for key in ("path", "targets", "products", "dependencies"):
            graph = copy.deepcopy(baseline)
            del graph[key]
            variants.append((graph, "fixture_graph_invalid"))
        for key in ("name", "c99name", "type", "module_type", "path", "sources"):
            graph = copy.deepcopy(baseline)
            del graph["targets"][0][key]
            variants.append((graph, "fixture_graph_invalid"))
        for key, value, code in (("path", "Missing", "fixture_input_unavailable"),
                                 ("path", "../Sources/App", "fixture_source_path"),
                                 ("sources", ["Missing.swift"], "fixture_input_unavailable"),
                                 ("sources", ["../Codec/Codec.swift"], "fixture_source_path"),
                                 ("sources", [str(self.root / "Sources/App/App.swift")], "fixture_source_path"),
                                 ("sources", [None], "fixture_graph_invalid"),
                                 ("sources", {}, "fixture_graph_invalid")):
            graph = copy.deepcopy(baseline)
            graph["targets"][0][key] = value
            variants.append((graph, code))
        for graph, code in variants:
            with self.subTest(graph=graph), patch.object(guard, "_describe", return_value=(0, json.dumps(graph))):
                self.rejected(code)

    def test_actual_dependency_metadata_query_refusal_fails_closed(self):
        self.compiler_fixture("ancestor", forbidden=False)
        manifest = self.root / "Packages/Package.swift"
        with owned.changed_source(manifest, manifest.read_bytes(), b"not a valid Swift manifest\n"):
            self.rejected("fixture_graph_unavailable")
            self.assertNotEqual(self.commands[-1][1], 0)

    def test_dependency_source_comments_and_uncontrolled_paths_are_not_scanned(self):
        self.compiler_fixture("ancestor", forbidden=False)
        self.write("Packages/Sources/Codec/Codec.swift", "// VaultCore AVSEAL01 AVMEMB01\n")
        self.write("Packages/unrelated/Other.swift", "import VaultCore\n")
        (self.root / "Packages/unrelated/alias").symlink_to(self.root / "Packages/VaultCore")
        self.check()

    def test_output_file_missing_empty_malformed_size_and_type_fail_closed(self):
        for variant, expected in (("missing", "fixture_graph_unavailable"),
                                  ("empty", "fixture_graph_invalid"), ("malformed", "fixture_graph_invalid"),
                                  ("oversized", "fixture_graph_invalid"), ("directory", "fixture_graph_invalid"),
                                  ("symlink", "fixture_graph_invalid"), ("encoding", "fixture_graph_unavailable")):
            def query(root, arguments):
                path = Path(arguments[arguments.index("--output-path") + 1])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                if variant in ("missing", "directory", "symlink"):
                    path.unlink()
                if variant == "directory":
                    path.mkdir()
                elif variant == "symlink":
                    path.symlink_to(self.root / "Package.swift")
                elif variant == "malformed":
                    path.write_text("not JSON")
                elif variant == "oversized":
                    path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
                elif variant == "encoding":
                    path.write_bytes(b"\xff")
                return 0, json.dumps(self.resolved)  # stdout must never rescue an invalid file.
            with self.subTest(variant=variant), patch.object(guard, "_swiftpm", side_effect=query):
                with self.assertRaisesRegex(guard.FixtureBoundaryError, "^" + expected + "$"):
                    guard.read_resolved_dependencies(self.root)

    def test_output_file_valid_json_cannot_override_command_refusal(self):
        def query(root, arguments):
            Path(arguments[arguments.index("--output-path") + 1]).write_text(json.dumps(self.resolved))
            return 1, "private SwiftPM error"
        with patch.object(guard, "_swiftpm", side_effect=query):
            with self.assertRaisesRegex(guard.FixtureBoundaryError, "^fixture_graph_unavailable$"):
                guard.read_resolved_dependencies(self.root)


if __name__ == "__main__":
    unittest.main()
