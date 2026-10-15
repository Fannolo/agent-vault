"""Exercise the release builder against real ad hoc code signatures, without credentials."""
import importlib.util
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("build_release", ROOT / "scripts/build-release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseEntitlementsTests(unittest.TestCase):
    def setUp(self):
        if not Path("/usr/bin/codesign").exists():
            self.skipTest("codesign unavailable")
        self.directory = tempfile.TemporaryDirectory(prefix="av-release-entitlements-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def signed(self, claims):
        binary = self.root / "fixture"
        shutil.copy("/usr/bin/true", binary)
        options = []
        if claims is not None:
            entitlements = self.root / "claims.plist"
            entitlements.write_bytes(plistlib.dumps(claims))
            options = ["--entitlements", str(entitlements)]
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
                        "--identifier", release.APP, *options, str(binary)],
                       check=True, capture_output=True)
        return binary

    def test_unentitled_review_role_has_empty_dictionary(self):
        binary = self.signed(None)
        self.assertEqual(release.signed_entitlements(binary), {})
        release.verify_entitlements(binary, {})

    def test_entitled_app_is_read_as_plist_and_matches_declared_policy(self):
        claims = {
            "com.apple.application-identifier": release.TEAM + "." + release.APP,
            "com.apple.developer.team-identifier": release.TEAM,
            "keychain-access-groups": [release.TEAM + "." + release.APP],
        }
        binary = self.signed(claims)
        self.assertEqual(release.signed_entitlements(binary), claims)
        release.verify_entitlements(binary, claims)
        with self.assertRaisesRegex(SystemExit, "exact declared policy"):
            release.verify_entitlements(binary, {})

    def test_extra_signed_capability_is_rejected(self):
        binary = self.signed({"com.apple.security.cs.debugger": True})
        with self.assertRaisesRegex(SystemExit, "exact declared policy"):
            release.verify_entitlements(binary, {})

    def test_release_and_installer_share_one_publisher_and_parser(self):
        self.assertEqual(release.TEAM, release.installer.TEAM)
        self.assertEqual(release.installer.__file__, str(ROOT / "deploy/ipc/agentvault_installer.py"))

    def test_unreadable_or_contradictory_claims_stop_the_release(self):
        duplicate = b"<plist><dict><key>k</key><true/><key>k</key><false/></dict></plist>"
        for xml, default in ((b"<plist><dict>", b"[Dict]"), (b"", b"[Dict]"), (duplicate, b"[Dict]")):
            def run(argv, check=True):
                return subprocess.CompletedProcess(argv, 0, xml if "--xml" in argv else default, b"")
            with self.subTest(xml=xml), mock.patch.object(release.installer, "run_command", side_effect=run), \
                    self.assertRaises(SystemExit):
                release.verify_entitlements(self.root / "fixture", {})


if __name__ == "__main__":
    unittest.main()
