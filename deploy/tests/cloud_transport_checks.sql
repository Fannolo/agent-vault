set role authenticated;
set request.jwt.claims = '{"sub":"11111111-1111-4111-8111-111111111111","is_anonymous":false}';
insert into vault.vaults(id) values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), ('cccccccc-cccc-4ccc-8ccc-cccccccccccc');
select public.assert_true((select count(*) = 3 from vault.vaults));
select public.expect_failure($q$insert into vault.vaults(id, owner_id) values
    ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', '22222222-2222-4222-8222-222222222222')$q$, '42501');
insert into vault.objects(vault_id, body) values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\x01'),
    ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\x02');
insert into vault.objects(vault_id, body) values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\x01')
    on conflict (vault_id, digest) do nothing;
select public.assert_true((select count(*) = 2 and max(seq) = 2 from vault.objects));
select public.expect_failure($q$insert into vault.objects(vault_id, body, seq)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\x03', 999)$q$, '42501');
select public.expect_failure($q$insert into vault.objects(vault_id, body)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', ''::bytea)$q$, '22023');
insert into vault.objects(vault_id, body) values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    decode(repeat('ab', 1048576), 'hex'));
select public.expect_failure($q$insert into vault.objects(vault_id, body)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', decode(repeat('ab', 1048577), 'hex'))$q$, '22023');
select public.expect_failure('update vault.objects set body = ''\x03''', '42501');
select public.expect_failure('delete from vault.objects', '42501');
select public.expect_failure('update vault.vaults set owner_id = auth.uid()', '42501');
select public.expect_failure('delete from vault.vaults', '42501');
select public.expect_failure('select * from vault_private.usage', '42501');
select public.assert_true(vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, sha256('\x01')) = 1);
select public.assert_true(vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, sha256('\x01')) = 1);
select public.expect_failure($q$select vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, sha256('\x02'))$q$, '40001');
select public.assert_true(vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sha256('\x01'), sha256('\x02')) = 2);
select public.expect_failure($q$select vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sha256('\x02'), sha256('\xff'))$q$, '22023');
select public.expect_failure($q$select vault.cas_head('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', null, sha256('\x02'))$q$, '22023');
select public.expect_failure($q$insert into vault.heads(vault_id, head, revision)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', sha256('\x02'), 999)$q$, '42501');
select public.expect_failure('update vault.heads set revision = 999', '42501');
select public.expect_failure('delete from vault.heads', '42501');

-- Claims come from the API gateway in deployment; this cluster only tests SQL authorization.
set request.jwt.claims = '{"sub":"22222222-2222-4222-8222-222222222222","is_anonymous":false,"user_metadata":{"owner_id":"11111111-1111-4111-8111-111111111111"}}';
select public.assert_true((select count(*) = 0 from vault.vaults));
select public.assert_true((select count(*) = 0 from vault.objects));
select public.assert_true((select count(*) = 0 from vault.heads));
select public.expect_failure($q$insert into vault.objects(vault_id, body)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\x03')$q$, '42501');
select public.expect_failure($q$select vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sha256('\x02'), sha256('\x01'))$q$, '42501');
select public.expect_failure($q$select vault_private.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sha256('\x02'), sha256('\x01'))$q$, '42501');

set request.jwt.claims = '{"sub":"11111111-1111-4111-8111-111111111111","is_anonymous":true}';
select public.assert_true((select count(*) = 0 from vault.vaults));
select public.assert_true((select count(*) = 0 from vault.objects));
select public.assert_true((select count(*) = 0 from vault.heads));
select public.expect_failure($q$insert into vault.vaults(id) values ('dddddddd-dddd-4ddd-8ddd-dddddddddddd')$q$, '42501');
select public.expect_failure($q$select vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sha256('\x02'), sha256('\x01'))$q$, '42501');
set request.jwt.claims = '{}';
select public.assert_true((select count(*) = 0 from vault.objects));
select public.expect_failure($q$select vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, sha256('\x01'))$q$, '42501');
reset role;
set role anon;
select public.expect_failure('select * from vault.objects', '42501');
select public.expect_failure($q$select vault.cas_head('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', null, sha256('\x01'))$q$, '42501');
reset role;

-- Lower remaining quotas through the test superuser, then exercise the real user path.
update vault_private.usage set object_count = 10000, byte_count = 536870912
    where vault_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
set role authenticated;
set request.jwt.claims = '{"sub":"11111111-1111-4111-8111-111111111111","is_anonymous":false}';
insert into vault.objects(vault_id, body) values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\x01')
    on conflict (vault_id, digest) do nothing;
select public.expect_failure($q$insert into vault.objects(vault_id, body)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\x03')$q$, '54000');
reset role;
select public.assert_true((select next_seq = 2 and object_count = 10000 and byte_count = 536870912
    from vault_private.usage where vault_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'));
select public.assert_true((select bool_and(relrowsecurity) from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname in ('vault', 'vault_private') and c.relkind = 'r'));
select 'PASS: owner, anonymous, immutable retry, bounds, quota and conditional heads';
