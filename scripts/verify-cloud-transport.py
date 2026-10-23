#!/usr/bin/env python3
"""Exercise the migration in a fresh native PostgreSQL cluster, never a hosted database."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / 'supabase/migrations/20261023005836_vault_transport.sql'
SPEC = importlib.util.spec_from_file_location('cloud_owned', ROOT / 'scripts/verify-webhost-link-mutations.py')
OWNED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNED)
IDENTITY = "set role authenticated; set request.jwt.claims = " + """'{"sub":"11111111-1111-4111-8111-111111111111","is_anonymous":false}';"""
VAULT = "'cccccccc-cccc-4ccc-8ccc-cccccccccccc'"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--postgres-bin', type=Path, required=True)
    args = parser.parse_args()
    binary = args.postgres_bin.resolve(strict=True)
    for tool in ('initdb', 'postgres', 'pg_ctl', 'pg_isready', 'psql'):
        if not (binary / tool).is_file():
            raise SystemExit('postgres_tools_missing')
    output = ROOT / 'verification-logs/cloud-transport' / ('run-' + uuid.uuid4().hex)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    records = {}

    def run(label, command, timeout=30, required=True):
        code, text = OWNED.run_owned([str(x) for x in command], timeout=timeout, cwd=ROOT)
        log = output / (label + '.log')
        log.write_text(text)
        log.chmod(0o600)
        records[label] = {'exit': code, 'command': [str(x) for x in command],
                          'sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
        if required and code != 0:
            raise RuntimeError(label + '_failed')
        return code, text

    inputs = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (MIGRATION, Path(__file__), ROOT / 'deploy/tests/cloud_transport_bootstrap.sql',
                        ROOT / 'deploy/tests/cloud_transport_checks.sql')}
    report = {'status': 'fail', 'inputs': inputs, 'steps': records}
    try:
        run('version', [binary / 'postgres', '--version'])
        # Short canonical paths fit sockaddr_un on both macOS and Linux. Private parent prevents
        # other local users connecting to this deliberately password-free synthetic test cluster.
        with tempfile.TemporaryDirectory(prefix='avpg-') as temporary:
            directory = Path(temporary).resolve()
            directory.chmod(0o700)
            cluster, sockets = directory / 'db', directory / 's'
            sockets.mkdir(mode=0o700)
            run('initdb', [binary / 'initdb', '-D', cluster, '-U', 'av_transport_test',
                           '--auth-local=trust', '--auth-host=reject', '--no-locale', '--encoding=UTF8'])
            with ThreadPoolExecutor(max_workers=3) as pool:
                server = pool.submit(run, 'postgres', [binary / 'postgres', '-D', cluster,
                    '-k', sockets, '-c', 'listen_addresses=', '-c', 'unix_socket_permissions=0700'], 180, False)
                primary_failure = None
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        code, _ = run('ready', [binary / 'pg_isready', '-h', sockets, '-U', 'av_transport_test'], required=False)
                        if code == 0:
                            break
                        if server.done() or time.monotonic() >= deadline:
                            raise RuntimeError('postgres_not_ready')
                        time.sleep(0.05)

                    def sql(label, text=None, source=None, required=True):
                        if source is None:
                            source = directory / (label + '.sql')
                            source.write_text(text)
                            source.chmod(0o600)
                        return run(label, [binary / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At',
                                          '-h', sockets, '-U', 'av_transport_test', '-d', 'postgres', '-f', source], required=required)

                    sql('bootstrap', source=ROOT / 'deploy/tests/cloud_transport_bootstrap.sql')
                    sql('migration', source=MIGRATION)
                    sql('authorization', source=ROOT / 'deploy/tests/cloud_transport_checks.sql')

                    first = pool.submit(sql, 'cursor-first', IDENTITY + f"""
begin;
insert into vault.objects(vault_id, body) values ({VAULT}, '\\x0a');
select pg_advisory_xact_lock(731009);
select pg_sleep(2);
commit;
""")
                    deadline = time.monotonic() + 10
                    while True:
                        _, text = sql('cursor-lock', "select count(*) from pg_locks where locktype = 'advisory' and objid = 731009 and granted;")
                        if text.strip() == '1':
                            break
                        if first.done() or time.monotonic() >= deadline:
                            raise RuntimeError('cursor_first_not_held')
                        time.sleep(0.02)
                    second = pool.submit(sql, 'cursor-second', IDENTITY + f"insert into vault.objects(vault_id, body) values ({VAULT}, '\\x0b');")
                    sql('cursor-invisible', IDENTITY + f"select public.assert_true((select count(*) = 0 from vault.objects where vault_id = {VAULT}));")
                    time.sleep(0.1)
                    if second.done():
                        raise RuntimeError('cursor_later_commit_escaped')
                    first.result(timeout=20)
                    second.result(timeout=20)
                    sql('cursor-order', IDENTITY + f"select public.assert_true((select array_agg(encode(body, 'hex') order by seq) = array['0a','0b'] from vault.objects where vault_id = {VAULT}));")

                    races = [pool.submit(sql, 'head-race-' + name, IDENTITY + f"select vault.cas_head({VAULT}, null, sha256('\\x{body}'));", None, False)
                             for name, body in [('a', '0a'), ('b', '0b')]]
                    outcomes = [f.result(timeout=20) for f in races]
                    if sorted(x[0] for x in outcomes) != [0, 3] or not any('head_conflict' in x[1] for x in outcomes if x[0] == 3):
                        raise RuntimeError('head_race_not_conditional')
                    sql('head-race-final', IDENTITY + f"select public.assert_true((select revision = 1 from vault.heads where vault_id = {VAULT}));")
                    report['status'] = 'pass'
                except BaseException as error:
                    primary_failure = error
                    report['failure'] = str(error)
                    raise
                finally:
                    # pg_ctl acts on this invocation's cluster only; no process-name search or signal.
                    try:
                        stop_code, _ = run('stop', [binary / 'pg_ctl', '-D', cluster, '-m', 'immediate', '-w', 'stop'], required=False)
                        server_code, _ = server.result(timeout=20)
                        if stop_code != 0 or server_code != 0:
                            raise RuntimeError('postgres_cleanup_unconfirmed')
                        report['cleanup'] = 'owned_server_exited'
                    except BaseException as cleanup_error:
                        report['status'] = 'fail'
                        report['cleanup_error'] = str(cleanup_error)
                        if primary_failure is None:
                            raise
    except BaseException as error:
        report['status'] = 'fail'
        report['failure'] = str(error)
        raise
    finally:
        report['inputs_unchanged'] = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == digest
                                         for p, digest in inputs.items())
        if not report['inputs_unchanged']:
            report['status'] = 'fail'
        target = output / 'result.json'
        target.write_text(json.dumps(report, indent=2) + '\n')
        target.chmod(0o600)
    if report['status'] != 'pass':
        raise SystemExit('cloud_transport_failed')
    print('PASS: native PostgreSQL transport authorization, immutable objects, quotas and races')
    print(target)


if __name__ == '__main__':
    main()
