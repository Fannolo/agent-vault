#!/usr/bin/env python3
"""Native proof for the standalone kernel. Every child uses the repository's run_owned.
No process-name kills; crash probes kill themselves. Timeout is always a failure.
Run from this checkout; Linux is the parent's independent CI responsibility.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
import signal
import sqlite3
import struct
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / 'Packages/VaultPersistence'
spec = importlib.util.spec_from_file_location('owned', ROOT / 'scripts/verify-webhost-link-mutations.py')
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)


def check(condition, name):
    if not condition:
        raise AssertionError('NAMED: ' + name)


def opaque(label, seed, size=512):
    out = b'AV-SYNTHETIC-OPAQUE/' + label.encode() + b'/'
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(label.encode() + struct.pack('>QQ', seed, counter)).digest()
        counter += 1
    return out[:size]


def digest(data):
    return hashlib.sha256(data).digest()


def image(root):
    # Read the actual bytes/rows after the kernel has applied recovery, not probe labels.
    with sqlite3.connect(str(root / 'vault.sqlite')) as db:
        head = db.execute('SELECT generation,state_id,state,object_count,object_bytes FROM head').fetchone()
        objects = dict((d, (g, b)) for d, g, b in db.execute('SELECT digest,generation,bytes FROM objects'))
    return head, objects


def pin(directory):
    raw = (directory / 'pin').read_bytes()
    check(len(raw) == 105 and raw[:8] == b'AVTPIN01' and digest(raw[:-32]) == raw[-32:], 'pin artifact checksum')
    return raw[8], raw[9:41], raw[41:73]


class Proof:
    def __init__(self, evidence, scratch):
        self.evidence, self.scratch = evidence, scratch
        self.counter = 0
        self.probe = scratch / 'debug/VaultPersistenceProbe'

    def run(self, command, name, expected=0, timeout=180):
        self.counter += 1
        code, output = owned.run_owned([str(x) for x in command], timeout=timeout, cwd=ROOT)
        (self.evidence / f'{self.counter:03}-{name}.log').write_text(f'COMMAND {command!r}\nEXIT {code}\n{output}')
        check(code is not None, name + ' did not time out')
        if expected is not None:
            check(code == expected, name + f' exit {code}, expected {expected}: {output[-3000:]}')
        return code, output

    def swift(self, verb, *args, name):
        return self.run(['swift', verb, '--package-path', PACKAGE, '--scratch-path', self.scratch,
                         '--disable-automatic-resolution', '-j', '4', *args], name, timeout=600)

    def build(self):
        self.swift('build', '--build-tests', name='build')

    def unit(self, target=None, expect_failure=None):
        args = ['--skip-build'] + (['--filter', target] if target else [])
        self.counter += 1
        command = ['swift', 'test', '--package-path', str(PACKAGE), '--scratch-path', str(self.scratch),
                   '--disable-automatic-resolution', '-j', '4', *args]
        code, output = owned.run_owned(command, timeout=180, cwd=ROOT)
        (self.evidence / f'{self.counter:03}-tests.log').write_text(f'EXIT {code}\n{output}')
        check(code is not None, 'unit tests did not time out')
        if expect_failure:
            check(code != 0 and expect_failure in output and 'Expectation failed' in output,
                  'control detected by ' + expect_failure)
        else:
            check(code == 0 and re.search(r'Test run with [1-9][0-9]* tests?.* passed', output), 'unit tests passed: ' + output[-3000:])
        return output

    def invoke(self, root, custody, *args, expected=0):
        return self.run([self.probe, args[0], root, custody, *args[1:]], 'probe-' + args[0], expected)

    def fresh(self):
        base = Path(tempfile.mkdtemp(prefix='fixture-', dir=self.evidence)).resolve()
        root, custody = base / 'vault', base / 'custody'
        root.mkdir(mode=0o700)
        custody.mkdir(mode=0o700)
        self.invoke(root, custody, 'create')
        return root, custody

    def race(self, control=False):
        root, custody = self.fresh()
        before = (root / 'vault.sqlite').read_bytes()
        # Each hold has a bounded lifetime. Every process gets its own canonical owned group.
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: owned.run_owned(
                [str(self.probe), 'hold', str(root), str(custody)], timeout=30, cwd=ROOT), range(4)))
        (self.evidence / ('race-control.json' if control else 'race.json')).write_text(json.dumps(results, indent=2))
        check(all(code is not None for code, _ in results), 'lease race did not time out')
        check(sum(code == 0 and 'OPEN 0' in out for code, out in results) == 1,
              'exactly one lease holder')
        check(sum(code == 3 and 'BUSY' in out for code, out in results) == 3, 'other processes busy')
        check((root / 'vault.sqlite').read_bytes() == before, 'lease race changes nothing')
        self.invoke(root, custody, 'info')

    def crash(self, cut):
        root, custody = self.fresh()
        self.invoke(root, custody, 'commit', 'none', '11', '2', '4096', '10')
        before_head, before_objects = image(root)
        _, out = self.invoke(root, custody, 'commit', cut, '20', '3', '4096', '10', expected=-signal.SIGKILL)
        new = cut in ['afterDatabaseCommit', 'afterStablePin', 'afterReturn']
        check(('ACK 2 ' in out) == (cut == 'afterReturn'), 'ack only after stable pin')
        old_id, new_id = digest(opaque('state', 11)), digest(opaque('state', 20))
        expected_pin = ((2, old_id, bytes(32)) if cut == 'beforePending' else
                        (3, old_id, new_id) if cut in ['afterPending', 'afterDatabaseCommit'] else
                        (2, new_id, bytes(32)))
        check(pin(custody) == expected_pin, 'pin artifact at ' + cut)
        journal = root / 'vault.sqlite-journal'
        if not new:
            check(journal.exists() and journal.stat().st_mode & 0o777 == 0o600, 'hot journal private')
        self.invoke(root, custody, 'info')
        head, objects = image(root)
        state = opaque('state', 20 if new else 11)
        expected_objects = dict(before_objects)
        if new:
            for i in range(3):
                obj = opaque(f'object-{i}', 20, 4096)
                expected_objects[digest(obj)] = (2, obj)
        check(head[:3] == (2 if new else 1, digest(state), state), 'atomic state row at ' + cut)
        check(objects == expected_objects, 'atomic object set at ' + cut)
        check(head[3:] == (len(objects), sum(len(row[1]) for row in objects.values())), 'atomic inventory totals')
        check(pin(custody) == (2, digest(state), bytes(32)), 'restart pin stable')
        names = set(x.name for x in root.iterdir())
        check(names <= {'lease', 'vault.sqlite', 'vault.sqlite-journal'}, 'no unexpected temp file')
        if journal.exists():
            check(journal.stat().st_mode & 0o777 == 0o600, 'remaining SQLite journal private')
        self.invoke(root, custody, 'commit', 'none', '30', '1', '64', '30')
        check(not journal.exists(), 'next successful write removes rollback journal')
        (self.evidence / f'crash-{cut}.json').write_text(json.dumps({
            'generation': head[0], 'state_sha256': head[1].hex(),
            'objects': {d.hex(): {'generation': g, 'length': len(b), 'sha256': digest(b).hex()}
                        for d, (g, b) in objects.items()}, 'pin_at_death': [x.hex() if isinstance(x, bytes) else x for x in expected_pin],
            'exact_frame_and_object_bytes_compared': True}, indent=2))

    def io_failure(self):
        root, custody = self.fresh()
        _, out = self.invoke(root, custody, 'fill', '40', str(512 * 1024), '16384')
        check('LIMIT ' in out and 'FAILED recoveryRequired(databaseCommit)' in out, 'real EFBIG failure')
        check('ACK' not in out, 'failed write never acknowledged')
        check('SECOND recoveryRequired(databaseCommit)' in out, 'write failure blocks admission')
        check(pin(custody) == (3, digest(opaque('state', 1)), digest(opaque('state', 40))), 'write failure leaves pending')
        self.invoke(root, custody, 'info')
        head, objects = image(root)
        check(head[:3] == (0, digest(opaque('state', 1)), opaque('state', 1)) and not objects,
              'failed write retains exact old image')
        check(pin(custody) == (2, head[1], bytes(32)), 'write failure restart aborts pending')

    def controls(self):
        lease = PACKAGE / 'Sources/VaultPersistence/PrivateFiles.swift'
        sql = PACKAGE / 'Sources/VaultPersistence/SQLiteConnection.swift'
        kernel = PACKAGE / 'Sources/VaultPersistence/VaultKernel.swift'
        controls = [
            ('omit-flock', lease, 'guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {',
             'guard true else {', None, 'exactly one lease holder'),
            ('create-fallback', sql, 'throw .locked(.missingDatabase)',
             'try PrivateFiles.createExclusive(path); throw .locked(.missingDatabase)', 'missingDatabaseWithEnrolledPinLocksWithoutCreating', 'NAMED: no database autocreated'),
            ('premature-ack', kernel, 'do { try custody.finish(next.id) } catch {',
             'do { /* defective control: acknowledge without stable pin */ } catch {',
             'pinFailuresNeverAcknowledge', 'NAMED: pin failure never acknowledged'),
        ]
        for name, path, old, new, target, assertion in controls:
            original = path.read_bytes()
            text = original.decode()
            count = text.count(old)
            check(count == (2 if name == 'create-fallback' else 1), 'mutation anchor ' + name)
            mutated = text.replace(old, new, 1).encode()
            with owned.changed_source(path, original, mutated):
                self.build()  # A build failure can never count as detecting a mutant.
                if target:
                    self.unit(target, assertion)
                else:
                    try:
                        self.race(control=True)
                    except AssertionError as error:
                        check(str(error) == 'NAMED: ' + assertion, 'lease named assertion')
                    else:
                        raise AssertionError('flock control survived')
            check(path.read_bytes() == original, 'exact restore ' + name)
            self.build()
            if target:
                self.unit(target)
            else:
                self.race()
            print('PASS control ' + name, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    check(not evidence.exists(), 'fresh evidence directory')
    evidence.mkdir(mode=0o700, parents=True)
    proof = Proof(evidence, args.scratch.resolve())
    for command, name in [(['swift', '--version'], 'swift-version'), (['uname', '-a'], 'os'), (['sw_vers'], 'os-version'),
                          (['xcrun', '--show-sdk-path'], 'sdk-path'), (['xcrun', '--show-sdk-version'], 'sdk-version')]:
        if os.uname().sysname == 'Darwin' or name not in ['sdk-path', 'sdk-version', 'os-version']:
            proof.run(command, name)
    proof.build()
    proof.unit()
    root, custody = proof.fresh()
    _, info = proof.invoke(root, custody, 'info')
    (evidence / 'sqlite-runtime.json').write_text(info)
    proof.race()
    for cut in ['beforePending', 'afterPending', 'afterDatabaseCommit', 'afterStablePin', 'afterReturn']:
        proof.crash(cut)
        print('PASS crash ' + cut, flush=True)
    proof.io_failure()
    if args.controls:
        proof.controls()
    proof.unit()
    sources = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in PACKAGE.rglob('*') if p.is_file() and '.build' not in p.parts}
    (evidence / 'source-sha256.json').write_text(json.dumps(sources, indent=2, sort_keys=True))
    (evidence / 'PASS').write_text('Native unit, owned crash/lease/write checks' + (' and three restored controls' if args.controls else '') + '\n')
    print('PASS ' + str(evidence), flush=True)


if __name__ == '__main__':
    with owned.interrupt_on_termination():
        main()
