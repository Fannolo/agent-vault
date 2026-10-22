#!/usr/bin/env python3
"""Run the opt-in, synthetic U5 composition with bounded, owned subprocesses.

Only the designated headless shell and loopback fixtures are used. Each Swift test retains
ChromiumPipe's pinned OwnedGroup handle, independently kills and awaits its browser, and has
an owned-pipe watchdog. This outer driver bounds builds/the runner through the existing
run_owned helper; it never searches for or signals processes by name or unpinned PID.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", required=True, type=Path, help="explicit synthetic chrome-headless-shell opt-in")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--filter", default="HeadlessContinuationE2ETests")
    args = parser.parse_args()
    binary = args.chromium.resolve(strict=True)
    if not binary.is_file() or binary.name != "chrome-headless-shell":
        parser.error("use the designated chrome-headless-shell fixture executable")
    logs = ROOT / "verification-logs"
    logs.mkdir(mode=0o700, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="u5-", dir=logs))
    os.environ["AGENT_VAULT_TEST_CHROMIUM"] = str(binary)
    os.environ.pop("AGENT_VAULT_KEYCHAIN_TEST", None)
    spec = importlib.util.spec_from_file_location("owned_u5", ROOT / "scripts/verify-webhost-link-mutations.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    commands = []
    if not args.skip_build:
        commands.append(("build", ["swift", "build", "--build-tests", "--force-resolved-versions", "-j", "4"], 600))
    commands.append(("e2e", ["swift", "test", "--skip-build", "--filter", args.filter], 240))
    for name, command, timeout in commands:
        code, output = helper.run_owned(command, timeout=timeout, cwd=ROOT)
        path = run / (name + ".log")
        with path.open("x") as log:
            os.fchmod(log.fileno(), 0o600)
            log.write(output)
        print(f"{name}: {'PASS' if code == 0 else 'FAIL'}; private log {path}", flush=True)
        if code != 0:
            return 2 if code is None else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
