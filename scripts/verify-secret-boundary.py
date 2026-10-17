#!/usr/bin/env python3
"""Bounded synthetic secret-boundary verification. Never accepts credentials."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CHROMIUM = Path('/Users/alessandro/Library/Caches/ms-playwright/chromium_headless_shell-1228/chrome-headless-shell-mac-arm64/chrome-headless-shell')


def main():
    if len(sys.argv) != 1 or not CHROMIUM.is_file():
        print('secret-boundary: FAIL (designated fixture unavailable or unexpected arguments)')
        return 1
    logs = ROOT / 'verification-logs'
    logs.mkdir(mode=0o700, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='secret-boundary-', dir=logs))
    home = run / 'home'
    home.mkdir(mode=0o700)
    temporary = run / 'tmp'
    temporary.mkdir(mode=0o700)
    # Do not read or copy the user's environment. Tests and the browser receive no
    # inherited tokens, credentials or native Keychain opt-in. Browser further fixes its env.
    os.environ.clear()
    os.environ.update({'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home),
                       'TMPDIR': str(temporary) + '/', 'AGENT_VAULT_TEST_CHROMIUM': str(CHROMIUM)})
    spec = importlib.util.spec_from_file_location('owned_boundary', ROOT / 'scripts/verify-webhost-link-mutations.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    commands = [
        ('build', ['/usr/bin/swift', 'build', '--build-tests', '--force-resolved-versions', '-j', '4'], 600),
        ('boundary', ['/usr/bin/swift', 'test', '--skip-build', '--filter', 'SecretBoundaryTests|SecretExposureDetectorTests'], 240),
    ]
    for name, command, timeout in commands:
        code, output = helper.run_owned(command, timeout=timeout, cwd=ROOT)
        with (run / (name + '.log')).open('x') as log:
            os.fchmod(log.fileno(), 0o600)
            log.write(output)
        print(f'{name}: {"PASS" if code == 0 else "FAIL"}; private logs retained', flush=True)
        if code != 0:
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
