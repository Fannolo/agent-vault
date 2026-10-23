#!/usr/bin/env python3
"""Source-bound cloud client verification: suite, targeted mutants and exact restoration.

Run on a clean committed tree. Every command runs through the canonical process-group owner
(`run_owned` in verify-webhost-link-mutations.py). Each mutant edits one file in place inside
`changed_source`, which restores the exact original bytes even on interruption. A mutant counts
as detected only when its named marker appears in the failing output, so a build failure or an
unrelated test failure does not count. Raw logs, mutated-source hashes and the result stay in a
new private directory below the git-ignored verification-logs/. No network or credential use.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cloud_client_owned", ROOT / "scripts/verify-webhost-link-mutations.py")
OWNED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNED)

SWIFT = ["swift", "test", "--force-resolved-versions", "--jobs", "4"]
SUITE = [
    ("cloud", SWIFT + ["--filter", "AgentVaultCloudTests"], 900),
    ("native-root", SWIFT, 2400),
    ("boundaries", [sys.executable, "-I", "scripts/verify-boundaries.py"], 600),
    ("credential-normal", [sys.executable, "-I", "deploy/tests/test_credential_boundaries.py"], 120),
    ("credential-optimized", [sys.executable, "-I", "-O", "deploy/tests/test_credential_boundaries.py"], 120),
    ("api", [sys.executable, "-I", "scripts/verify-credential-api.py"], 900),
    ("mcp", [sys.executable, "scripts/verify-mcp.py"], 900),
]

T = "Sources/AgentVaultCloud/SupabaseTransport.swift"
H = "Sources/AgentVaultCloud/CloudHTTPRequest.swift"
E = "Sources/AgentVaultCloud/CloudTransport.swift"
K = "Sources/AgentVaultCredentials/CloudAccessToken.swift"
G = "scripts/credential_boundaries.py"
PUT, CAS, CHANGES, VAULT, HEAD = ("fixedPutRouteUsesOnlyTrustedHeadersAndImmutableRetry", "conditionalHeadBodiesUseNullOrPrefixedDigests",
                                  "changesVerifyDigestAndCursorBeforeReturningCiphertext", "createVaultConfirmsOwnershipOfAnExistingId",
                                  "headIsScopedAndConditionalWriteNeverRetries")
WITNESS, REDIRECT = "redirectDelegateWitnessRefusesTheNewRequest", "redirectIsRefusedBeforeTheNewHostReceivesCredentials"
API = [sys.executable, "-I", "scripts/verify-credential-api.py"]
GUARD = [sys.executable, "-I", "deploy/tests/test_credential_boundaries.py"]


def swift(*tests):
    return ("swift", "|".join(tests), ["✘ Test " + test + "(" for test in tests])


MUTANTS = [
    ("put route", T, '_ = try await request("objects", method: "POST"', '_ = try await request("object", method: "POST"', swift(PUT)),
    ("put drops exact-retry preference", T, 'body: body, prefer: "return=minimal,resolution=ignore-duplicates", success: [201, 200, 204])',
     'body: body, prefer: "return=minimal", success: [201, 200, 204])', swift(PUT)),
    ("write uses read profile", T, 'method == "GET" ? "Accept-Profile" : "Content-Profile"',
     'method == "GET" ? "Accept-Profile" : "Accept-Profile"', swift(PUT, CAS)),
    ("read uses write profile", T, 'method == "GET" ? "Accept-Profile" : "Content-Profile"',
     'method == "GET" ? "Content-Profile" : "Content-Profile"', swift(CHANGES)),
    ("authorization scheme", T, '"Bearer " + String(decoding:', '"bearer " + String(decoding:', swift(PUT, CHANGES)),
    ("publishable key header", T, 'forHTTPHeaderField: "apikey")', 'forHTTPHeaderField: "x-apikey")', swift(PUT, CHANGES)),
    ("object body without hex prefix", T, '"body": "\\\\x" + object.bytes.hex]', '"body": object.bytes.hex]', swift(PUT)),
    ("object vault uppercase", T, '["vault_id": vault.uuidString.lowercased(), "body"', '["vault_id": vault.uuidString, "body"', swift(PUT)),
    ("conditional head omits null expected", T, '"p_expected": NSNull(), ', '', swift(CAS)),
    ("conditional head vault uppercase", T, '["p_vault": vault.uuidString.lowercased(),', '["p_vault": vault.uuidString,', swift(CAS)),
    ("cursor includes its own row", T, 'value: "gt.\\(cursor)"', 'value: "gte.\\(cursor)"', swift(CHANGES)),
    ("create vault ignores duplicates", T, 'prefer: "return=minimal", success: [201])',
     'prefer: "return=minimal,resolution=ignore-duplicates", success: [201])', swift(VAULT)),
    ("create vault skips ownership", T, "guard let row = rows.first else { throw CloudError.conflict }",
     "guard let row = rows.first else { return }", swift(VAULT)),
    ("forbidden reported as unauthorized", T, "if response.status == 403 { throw CloudError.denied }",
     "if response.status == 403 { throw CloudError.unauthorized }", swift(HEAD)),
    ("rollback reported as conflict", T, "if response.status == 409 { throw CloudError.conflict }",
     "if response.status == 409 || response.status == 500 { throw CloudError.conflict }", swift(HEAD)),
    ("redirect followed", H, "        completionHandler(nil)\n        finish(.failure(.invalidResponse))",
     "        completionHandler(request)", swift(WITNESS, REDIRECT) if sys.platform == "darwin" else swift(WITNESS)),
    ("response URL unchecked", H, "response.url == expectedURL,", "", swift("responseFromAnotherDestinationIsRefused")),
    ("endpoint not canonical", E, "self.origin = url", "self.origin = origin", swift("endpointIsCanonicalSoExactResponseURLsMatch")),
    ("token reveal shares browser SPI", K, "@_spi(CloudTokenUse)\n    public func withTokenBytes",
     "@_spi(CredentialUse)\n    public func withTokenBytes",
     ("command", API, ["credential_api_probe_failed: credential_use_no_cloud_token_reveal"])),
    ("browser file may import token SPI", G, '"CloudTokenUse": {"Sources/AgentVaultCloud/SupabaseTransport.swift"},',
     '"CloudTokenUse": {"Sources/AgentVaultCloud/SupabaseTransport.swift", "Sources/AgentVaultWebHost/WebRun.swift"},',
     ("command", GUARD, ["FAIL: test_cloud_token_reveal_has_its_own_group"])),
    ("cloud graph reverts to denylist", G, '    for name in sorted(set(targets) - tests - CLOUD_CONSUMERS - {"AgentVaultCloud"}):',
     '    for name in ("AgentVaultBridge", "AgentVaultMCPBridge", "AgentVaultMCPTransport", "AgentVaultWebHost",\n'
     '                 "AgentVaultWebHostProtocol", "AgentVaultApp", "AgentVaultAppSupport", "AgentVaultIPC"):',
     ("command", GUARD, ["FAIL: test_cloud_transport_is_unavailable_to_every_unapproved_role",
                         "FAIL: test_cli_mcp_server_cannot_reach_cloud_through_core"])),
]
RESTORED = [
    ("restored-cloud", SWIFT + ["--filter", "AgentVaultCloudTests"], 900),
    ("restored-api", API, 900),
    ("restored-credential", GUARD, 120),
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def snapshot():
    paths = sorted({path for _, path, *_ in MUTANTS} | {
        "Tests/AgentVaultCloudTests/CloudTransportTests.swift", "deploy/tests/test_credential_boundaries.py",
        "scripts/verify-credential-api.py", "scripts/verify-boundaries.py", "scripts/verify-webhost-link-mutations.py",
        "scripts/verify-cloud-client.py", "Package.swift", "Package.resolved"})
    return {"commit": git("rev-parse", "HEAD").strip(), "tree": git("rev-parse", "HEAD^{tree}").strip(),
            "dirty": bool(git("status", "--porcelain=v1", "--untracked-files=all").strip()),
            "files": {path: sha256((ROOT / path).read_bytes()) for path in paths}}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True, help="new directory below verification-logs/")
    parser.add_argument("--skip-suite", action="store_true", help="run only mutants and restoration")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "verification-logs") or out.exists():
        parser.error("choose a new directory below verification-logs/; earlier evidence is preserved")
    before = snapshot()
    if before["dirty"]:
        parser.error("commit the source checkpoint before recording verification")
    out.mkdir(mode=0o700, parents=True)
    report = {"scope": "Local URLProtocol fixtures, guards and compiler probes; no live PostgREST, JWT, signup or Linux runtime",
              "source": before, "steps": {}, "mutants": [], "status": "fail"}

    def run(label, command, timeout):
        code, text = OWNED.run_owned([str(part) for part in command], timeout=timeout, cwd=ROOT)
        log = out / (label.replace(" ", "-") + ".log")
        log.write_text(text)
        log.chmod(0o600)
        step = {"exit": code, "command": [str(part) for part in command], "log": str(log.relative_to(ROOT)),
                "sha256": sha256(log.read_bytes())}
        report["steps"][label] = step
        return code, text

    try:
        with OWNED.interrupt_on_termination():
            if not args.skip_suite:
                for label, command, timeout in SUITE:
                    if run(label, command, timeout)[0] != 0:
                        raise RuntimeError(label + "_failed")
            # A marker counts only if the unmutated tree passes the same command.
            if run("baseline-tests", ["swift", "build", "--build-tests", "--force-resolved-versions", "--jobs", "4"], 900)[0] != 0:
                raise RuntimeError("baseline_build_failed")
            for name, path, old, new, (kind, target, markers) in MUTANTS:
                source = ROOT / path
                original = source.read_bytes()
                text = original.decode()
                if text.count(old) != 1:
                    raise RuntimeError("mutant_anchor_not_unique: " + name)
                mutated = text.replace(old, new).encode()
                entry = {"name": name, "path": path, "original": old, "mutated": new,
                         "mutatedFileSha256": sha256(mutated), "markers": markers}
                with OWNED.changed_source(source, original, mutated):
                    if kind == "swift":
                        code, output = run(name + " build", ["swift", "build", "--build-tests", "--force-resolved-versions",
                                                            "--jobs", "4"], 900)
                        if code == 0:
                            code, output = run(name, ["swift", "test", "--skip-build", "--filter", target], 300)
                    else:
                        code, output = run(name, target, 900)
                entry["restored"] = sha256(source.read_bytes()) == sha256(original)
                entry["exit"] = code
                entry["detected"] = code != 0 and all(marker in output for marker in markers) and entry["restored"]
                report["mutants"].append(entry)
                print(f"mutant {name}: {'DETECTED' if entry['detected'] else 'NOT DETECTED'}", flush=True)
            for label, command, timeout in RESTORED:
                if run(label, command, timeout)[0] != 0:
                    raise RuntimeError(label + "_failed")
        after = snapshot()
        report["sourceUnchanged"] = after == before
        if report["sourceUnchanged"] and all(entry["detected"] for entry in report["mutants"]):
            report["status"] = "pass"
    except BaseException as error:
        report["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        result = out / "result.json"
        result.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        result.chmod(0o600)
        print(result, flush=True)
    if report["status"] != "pass":
        raise SystemExit("cloud_client_verification_failed")
    print(f"PASS: cloud client suite, {len(MUTANTS)} detected mutants and exact restoration")


if __name__ == "__main__":
    main()
