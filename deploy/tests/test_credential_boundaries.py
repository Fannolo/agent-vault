import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("credential_boundaries", ROOT / "scripts/credential_boundaries.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class CredentialBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="av-credential-boundary-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_trusted_reveal_imports_are_accepted(self):
        for spi, paths in guard.REVEAL_IMPORTS.items():
            for path in paths:
                module = "VaultSecret" if spi == "SecretReveal" else "AgentVaultCredentials"
                self.write(path, f"@_spi({spi}) import {module}\n")
        guard.check_credentials(self.root, {})

    def test_bridge_and_new_modules_cannot_add_reveal(self):
        for target in ["AgentVaultMCPBridge", "AgentVaultCore", "UnlistedAdapter"]:
            for spi in guard.REVEAL_IMPORTS:
                with self.subTest(target=target, spi=spi):
                    path = self.write(f"Sources/{target}/Bad.swift", f"@ _spi ( {spi} ) import AgentVaultCredentials")
                    with self.assertRaisesRegex(SystemExit, "credential_reveal_import_forbidden"):
                        guard.check_credentials(self.root, {})
                    path.unlink()

    def test_raw_secret_module_is_unavailable_to_agent_modules(self):
        for declaration in ["internal import VaultSecret", "import class VaultSecret.SecretBytes",
                            "import struct VaultSecret.LoginSecret"]:
            with self.subTest(declaration=declaration):
                self.write("Sources/AgentVaultMCPBridge/Bad.swift", declaration)
                with self.assertRaisesRegex(SystemExit, "credential_storage_import_forbidden"):
                    guard.check_credentials(self.root, {})

    def test_transitive_credential_dependency_is_forbidden(self):
        with self.assertRaisesRegex(SystemExit, "credential_target_forbidden"):
            guard.check_credentials(self.root, {"AgentVaultBridge": {"Wrapper"}, "Wrapper": {"AgentVaultCredentials"}})

    def test_broker_and_host_can_depend_on_credential_module(self):
        guard.check_credentials(self.root, {"AgentVaultCore": {"AgentVaultCredentials"},
                                           "AgentVaultWebHost": {"AgentVaultCredentials"}})

    def test_custom_target_path_cannot_bypass_reveal_check(self):
        self.write("Custom/Module/Bad.swift", "@_spi(CredentialUse) import AgentVaultCredentials")
        with self.assertRaisesRegex(SystemExit, "credential_reveal_import_forbidden"):
            guard.check_credentials(self.root, {}, [{"name": "Custom", "type": "library", "path": "Custom/Module",
                                                     "sources": ["Bad.swift"]}])

    def test_secret_product_is_only_linked_by_trusted_wrapper(self):
        with self.assertRaisesRegex(SystemExit, "credential_storage_dependency_forbidden"):
            guard.check_credentials(self.root, {}, [{"name": "AgentVaultBridge", "type": "executable",
                                                     "product_dependencies": ["VaultSecret"]}])


if __name__ == "__main__":
    unittest.main()
