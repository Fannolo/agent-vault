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
import shutil
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
    check(len(raw) == 185 and raw[:8] == b'AVTPIN03' and digest(raw[:-32]) == raw[-32:], 'pin artifact checksum/version')
    def entry(offset):
        return (struct.unpack('>Q', raw[offset:offset + 8])[0], raw[offset + 8:offset + 40],
                raw[offset + 40:offset + 72])
    return raw[8], entry(9), entry(81)


def logical_identity(head, objects):
    # Independent canonical encoder over actual/expected logical rows, not kernel output.
    generation, state_id, frame, count, size = head
    u64 = lambda n: struct.pack('>Q', n)
    data = b'AgentVault/VaultPersistence/Image/v1\0'
    data += u64(0x41565031) + u64(1) + u64(generation)
    data += u64(len(frame)) + frame + state_id + u64(count) + u64(size)
    for address, (admission, value) in sorted(objects.items()):
        check(digest(value) == address, 'independent object digest')
        data += address + u64(admission) + u64(len(value))
    return generation, state_id, digest(data)


def commit_id(seed, generation, objects=None):
    objects = objects or {}
    frame = opaque('state', seed)
    return logical_identity((generation, digest(frame), frame, len(objects),
                             sum(len(value) for _, value in objects.values())), objects)


ZERO_IMAGE = (0, bytes(32), bytes(32))


def source_hashes():
    return {str(p.relative_to(ROOT)): digest(p.read_bytes()).hex()
            for p in PACKAGE.rglob('*') if p.is_file() and '.build' not in p.parts}


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

    def freeze(self, root, custody, label):
        # Copy raw bytes BEFORE any SQLite open/recovery can rewrite the image or pin.
        frozen = self.evidence / ('frozen-' + label)
        frozen.mkdir(mode=0o700)
        paths = [root / 'vault.sqlite', root / 'vault.sqlite-journal', custody / 'pin']
        files = {}
        for path in paths:
            if not path.exists():
                continue
            raw = path.read_bytes()
            target = frozen / path.name
            target.write_bytes(raw)
            target.chmod(0o600)
            files[path.name] = {'sha256': digest(raw).hex(), 'length': len(raw),
                                'source_mode': oct(path.stat().st_mode & 0o7777)}
        (frozen / 'snapshot.json').write_text(json.dumps(files, indent=2, sort_keys=True))
        return str(frozen.relative_to(self.evidence))

    def crash(self, cut):
        root, custody = self.fresh()
        self.invoke(root, custody, 'commit', 'none', '11', '2', '4096', '10')
        before_head, before_objects = image(root)
        _, out = self.invoke(root, custody, 'commit', cut, '20', '3', '4096', '10', expected=-signal.SIGKILL)
        new = cut in ['afterDatabaseCommit', 'afterStablePin', 'afterReturn']
        check(('ACK 2 ' in out) == (cut == 'afterReturn'), 'ack only after stable pin')
        new_objects = dict(before_objects)
        for i in range(3):
            obj = opaque(f'object-{i}', 20, 4096)
            new_objects[digest(obj)] = (2, obj)
        old_id, new_id = commit_id(11, 1, before_objects), commit_id(20, 2, new_objects)
        expected_pin = ((2, old_id, ZERO_IMAGE) if cut == 'beforePending' else
                        (3, old_id, new_id) if cut in ['afterPending', 'afterDatabaseCommit'] else
                        (2, new_id, ZERO_IMAGE))
        check(pin(custody) == expected_pin, 'pin artifact at ' + cut)
        frozen = self.freeze(root, custody, cut)
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
        check(pin(custody) == (2, logical_identity(head, objects), ZERO_IMAGE), 'restart pin stable')
        names = set(x.name for x in root.iterdir())
        check(names <= {'lease', 'vault.sqlite', 'vault.sqlite-journal'}, 'no unexpected temp file')
        if journal.exists():
            check(journal.stat().st_mode & 0o777 == 0o600, 'remaining SQLite journal private')
        self.invoke(root, custody, 'commit', 'none', '30', '1', '64', '30')
        check(not journal.exists(), 'next successful write removes rollback journal')
        (self.evidence / f'crash-{cut}.json').write_text(json.dumps({
            'generation': head[0], 'state_sha256': head[1].hex(),
            'objects': {d.hex(): {'generation': g, 'length': len(b), 'sha256': digest(b).hex()}
                        for d, (g, b) in objects.items()}, 'pin_at_death': [expected_pin[0], *[{'generation': g, 'state_sha256': h.hex(), 'image_sha256': identity.hex()} for g, h, identity in expected_pin[1:]]],
            'frozen_before_recovery': frozen,
            'exact_frame_and_object_bytes_compared': True}, indent=2))

    def io_failure(self):
        root, custody = self.fresh()
        _, out = self.invoke(root, custody, 'fill', '40', str(512 * 1024), '16384')
        check('LIMIT ' in out and 'FAILED recoveryRequired(databaseCommit)' in out, 'real EFBIG failure')
        check('ACK' not in out, 'failed write never acknowledged')
        check('SECOND recoveryRequired(databaseCommit)' in out, 'write failure blocks admission')
        obj = opaque('object-0', 40, 512 * 1024)
        check(pin(custody) == (3, commit_id(1, 0), commit_id(40, 1, {digest(obj): (1, obj)})), 'write failure leaves pending')
        self.freeze(root, custody, 'EFBIG')
        self.invoke(root, custody, 'info')
        head, objects = image(root)
        check(head[:3] == (0, digest(opaque('state', 1)), opaque('state', 1)) and not objects,
              'failed write retains exact old image')
        check(pin(custody) == (2, logical_identity(head, objects), ZERO_IMAGE), 'write failure restart aborts pending')

    def abandoned_retry(self, mode, same_totals):
        base = Path(tempfile.mkdtemp(prefix='tiny-', dir=self.evidence)).resolve()
        root, custody = base / 'vault', base / 'custody'
        root.mkdir(mode=0o700)
        custody.mkdir(mode=0o700)
        label = mode + ('-same-totals' if same_totals else '-missing-X')
        self.invoke(root, custody, 'tiny-create')
        lease_inode = (root / 'lease').stat().st_ino
        d0 = (root / 'vault.sqlite').read_bytes()
        self.freeze(root, custody, label + '-D0')
        _, out = self.invoke(root, custody, 'tiny-commit', 'afterDatabaseCommit', 'B',
                             'Y' if same_totals else 'none', expected=-signal.SIGKILL)
        check('ACK' not in out, 'abandoned attempt never acknowledged')
        d1 = (root / 'vault.sqlite').read_bytes()
        self.freeze(root, custody, label + '-D1')
        abandoned = pin(custody)
        check(abandoned[0] == 3, 'abandoned pin pending')
        (root / 'vault.sqlite').write_bytes(d0)  # owner is dead; preserve inode/mode
        self.invoke(root, custody, 'info')
        check(pin(custody) == (2, abandoned[1], ZERO_IMAGE), 'D0 legitimately aborts pending')
        cut = 'afterDatabaseCommit' if mode == 'pending-finish' else 'none'
        _, out = self.invoke(root, custody, 'tiny-commit', cut, 'B', 'X',
                             expected=-signal.SIGKILL if mode == 'pending-finish' else 0)
        check(('ACK 1 ' in out) == (mode != 'pending-finish'), 'retry ACK boundary')
        head, objects = image(root)
        check(head[:3] == (1, digest(b'B'), b'B') and objects == {digest(b'X'): (1, b'X')},
              'exact tiny retry image')
        committed_id = logical_identity(head, objects)
        check(abandoned[2][:2] == committed_id[:2] and abandoned[2][2] != committed_id[2],
              'same Head different whole image')
        if mode == 'pending-abort':
            self.invoke(root, custody, 'tiny-commit', 'prepareFault', 'C', 'none', expected=5)
        self.freeze(root, custody, label + '-retry')
        expected_pin = pin(custody)
        check(expected_pin[2 if mode == 'pending-finish' else 1] == committed_id, 'custody binds X')
        check(not (root / 'vault.sqlite-journal').exists(), 'tiny restore has no hot journal')
        (root / 'vault.sqlite').write_bytes(d1)
        self.freeze(root, custody, label + '-restored-before-open')
        _, out = self.invoke(root, custody, 'info', expected=4)
        check('LOCKED locked(pinMismatch)' in out, 'replayed D1 refuses acknowledged object loss')
        check(pin(custody) == expected_pin and (root / 'lease').stat().st_ino == lease_inode,
              'mismatch preserves custody and lease')
        check((root / 'vault.sqlite').read_bytes() == d1, 'mismatch preserves replayed DB')
        (self.evidence / ('tiny-' + label + '.json')).write_text(json.dumps({
            'mode': mode, 'same_totals': same_totals, 'real_SIGKILL_after_SQL_COMMIT': True,
            'lease_inode_preserved': True, 'custody_never_restored': True, 'no_SQL_state_forgery': True,
            'old_image': abandoned[2][2].hex(), 'retry_image': committed_id[2].hex(),
            'retry_acknowledged': mode != 'pending-finish', 'result': 'locked(pinMismatch)'}, indent=2))

    def controls(self):
        lease = PACKAGE / 'Sources/VaultPersistence/PrivateFiles.swift'
        sql = PACKAGE / 'Sources/VaultPersistence/SQLiteConnection.swift'
        kernel = PACKAGE / 'Sources/VaultPersistence/VaultKernel.swift'
        controls = [
            ('omit-flock', lease, 'guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {',
             'guard true else {', None, 'exactly one lease holder'),
            ('create-fallback', sql, 'throw .locked(.missingDatabase)',
             'try PrivateFiles.createExclusive(path); throw .locked(.missingDatabase)', 'missingDatabaseWithEnrolledPinLocksWithoutCreating', 'NAMED: no database autocreated'),
            ('premature-ack', kernel, 'do { try custody.finish(stagedImage) } catch {',
             'do { /* defective control: acknowledge without stable pin */ } catch {',
             'pinFailuresNeverAcknowledge', 'NAMED: pin failure never acknowledged'),
            ('frame-only-stable-match', kernel, 'where pinned == found:',
             'where pinned.head.state == found.head.state:', 'reusedFrameCannotHideAcknowledgedObjects',
             'NAMED: reused frame cannot hide acknowledged objects'),
            ('frame-only-pending-match', kernel, 'where next == found:',
             'where next.head.state == found.head.state:', 'pendingCannotMatchOnlyFrameHash',
             'NAMED: pending compares generation and frame hash'),
            ('frame-only-pending-abort', kernel, 'where stable == found:',
             'where stable.head.state == found.head.state:', 'pendingCannotMatchOnlyFrameHash',
             'NAMED: pending compares generation and frame hash'),
            ('head-only-stable-match', kernel, 'where pinned == found:',
             'where pinned.head == found.head:', 'wholeImageStableRejectsAbandonedInventory',
             'NAMED: stable compares whole inventory'),
            ('head-only-pending-finish', kernel, 'where next == found:',
             'where next.head == found.head:', 'wholeImagePendingFinishRejectsAbandonedInventory',
             'NAMED: pending finish compares whole inventory'),
            ('head-only-pending-abort', kernel, 'where stable == found:',
             'where stable.head == found.head:', 'wholeImagePendingAbortRejectsAbandonedInventory',
             'NAMED: pending abort compares whole inventory'),
            ('omit-object-digest-binding', sql, 'identity.bytes(digest)',
             '/* defective control: inventory totals alone */', 'wholeImageStableRejectsAbandonedInventory',
             'NAMED: stable compares whole inventory'),
            ('omit-admission-generation-binding', sql, 'identity.integer(admission)',
             '/* defective control: omit admission metadata */', 'wholeImageBindsObjectAdmissionGeneration',
             'NAMED: custody rejects admission metadata substitution'),
            ('omit-old-image-recheck', kernel, 'verifiedRow == row, verifiedImage == image',
             'verifiedRow == row', 'liveInventorySubstitutionCannotBeAcknowledged',
             'NAMED: commit verifies previous whole image'),
            ('omit-read-corruption-latch', kernel, 'if case .locked = error { blocked = .integrity }',
             '/* defective control: read integrity error leaves admission open */',
             'sqliteObjectReadCorruptionBlocksOwner', 'NAMED: caught SQLite corruption blocks state'),
            ('omit-acl-check', lease, 'switch av_check_acl(descriptor, role == .ancestor ? 1 : 0) {',
             'switch Int32(0) {', 'darwinPrivateACLsRejected',
             'NAMED: private boundary rejects native extended ACL'),
            ('omit-ancestor-acl-check', lease, 'try validateDirectoryACL(ancestor, status: status, role: .ancestor)',
             '/* defective control: no ancestor ACL validation */', 'darwinAncestorACLWriteRejected',
             'NAMED: ancestor rejects native ACL write grant'),
        ]
        if os.uname().sysname != 'Darwin':
            controls = [c for c in controls if c[0] not in ['omit-acl-check', 'omit-ancestor-acl-check']]
        records = []
        for name, path, old, new, target, assertion in controls:
            first_log = self.counter + 1
            original = path.read_bytes()
            text = original.decode()
            count = text.count(old)
            check(count == (2 if name in ['create-fallback', 'omit-read-corruption-latch'] else 1), 'mutation anchor ' + name)
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
            records.append({'name': name, 'named_assertion': assertion,
                            'original_sha256': digest(original).hex(), 'mutant_sha256': digest(mutated).hex(),
                            'first_log': first_log, 'last_log': self.counter, 'exact_restore': True})
            (self.evidence / 'controls.json').write_text(json.dumps(records, indent=2))
            print('PASS control ' + name, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    original_sources = source_hashes()
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
    for mode in ['stable', 'pending-finish', 'pending-abort']:
        for same_totals in [False, True]:
            proof.abandoned_retry(mode, same_totals)
            print('PASS abandoned retry ' + mode + ' same_totals=' + str(same_totals), flush=True)
    if args.controls:
        proof.controls()
    proof.unit()
    check(source_hashes() == original_sources, 'final source equals measured source')
    (evidence / 'source-sha256.json').write_text(json.dumps(original_sources, indent=2, sort_keys=True))
    canonical = ROOT / 'scripts/verify-webhost-link-mutations.py'
    (evidence / 'canonical-runner-sha256.txt').write_text(digest(canonical.read_bytes()).hex() + '\n')
    binaries = [proof.probe]
    binaries += list(proof.scratch.glob('debug/*.xctest/Contents/MacOS/*'))
    if os.uname().sysname != 'Darwin':
        binaries += list(proof.scratch.glob('debug/*.xctest'))
    binary_dir = evidence / 'binaries'
    binary_dir.mkdir(mode=0o700)
    for binary in binaries:
        if not binary.is_file():
            continue
        shutil.copyfile(binary, binary_dir / binary.name)
        (binary_dir / binary.name).chmod(0o700)
    (evidence / 'PASS').write_text('Native unit, owned five crash cuts, lease race, EFBIG, six whole-image replay cases'
                                 + (' and restored omission controls' if args.controls else '') + '\n')
    # Includes retained fixture images, frozen death-time bytes, executables and logs.
    manifest = {str(p.relative_to(evidence)): digest(p.read_bytes()).hex()
                for p in evidence.rglob('*') if p.is_file()}
    (evidence / 'evidence-sha256.json').write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print('PASS ' + str(evidence), flush=True)


if __name__ == '__main__':
    with owned.interrupt_on_termination():
        main()
