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
    prove_rotation = sys.argv[1:] == ['--prove-rotation']
    if (sys.argv[1:] and not prove_rotation) or not CHROMIUM.is_file():
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
    def execute(name, command, timeout):
        code, output = helper.run_owned(command, timeout=timeout, cwd=ROOT)
        with (run / (name + '.log')).open('x') as log:
            os.fchmod(log.fileno(), 0o600)
            log.write(output)
        return code, output

    for name, command, timeout in commands:
        code, _ = execute(name, command, timeout)
        print(f'{name}: {"PASS" if code == 0 else "FAIL"}; private logs retained', flush=True)
        if code != 0:
            return 1
    if not prove_rotation:
        return 0

    # Closed deliberate failure control. Only this owned test source is changed;
    # restore its exact bytes even when a build/test fails or is interrupted.
    source = ROOT / 'Tests/AgentVaultHeadlessE2ETests/SecretBoundaryTests.swift'
    original = source.read_bytes()
    needle = b'let rotated = await model.rotate(account: account, secret: probe.password, username: "mfa-user")'
    if original.count(needle) != 1:
        print('rotation-control: FAIL (closed mutation precondition)')
        return 1
    detected = False
    try:
        source.write_bytes(original.replace(needle, b'let rotated = true // deliberate no-op rotation control'))
        code, _ = execute('noop-build', commands[0][1], 600)
        if code == 0:
            code, output = execute('noop-boundary', [
                '/usr/bin/swift', 'test', '--skip-build', '--filter',
                'realWorkflowKeepsFreshCanariesOutOfObservedOutputs'], 240)
            detected = code not in (0, None) and 'decoded login POST must use rotated B rather than enrolled A' in output
    finally:
        source.write_bytes(original)
    print(f'rotation-control: {"PASS" if detected else "FAIL"}; private logs retained', flush=True)
    # The final binary must correspond to restored source and pass the baseline again.
    restored = True
    for name, command, timeout in commands:
        code, _ = execute('restored-' + name, command, timeout)
        print(f'restored-{name}: {"PASS" if code == 0 else "FAIL"}; private logs retained', flush=True)
        if code != 0:
            restored = False
            break
    return 0 if detected and restored else 1



if __name__ == '__main__':
    sys.exit(main())
