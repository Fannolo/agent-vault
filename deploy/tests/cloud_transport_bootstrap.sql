-- Only for a fresh, invocation-owned native PostgreSQL cluster. Never a hosted project.
create role anon nologin;
create role authenticated nologin;
create schema auth;
create table auth.users(id uuid primary key);
create function auth.jwt() returns jsonb language sql stable as $$
    select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb;
$$;
create function auth.uid() returns uuid language sql stable as $$
    select (auth.jwt()->>'sub')::uuid;
$$;
grant usage on schema auth to anon, authenticated;
grant execute on function auth.uid(), auth.jwt() to anon, authenticated;
insert into auth.users values ('11111111-1111-4111-8111-111111111111'),
    ('22222222-2222-4222-8222-222222222222');

create function public.assert_true(p_condition boolean) returns void language plpgsql as $$
begin
    if p_condition is distinct from true then raise exception 'assertion_failed'; end if;
end;
$$;
create function public.expect_failure(p_sql text, p_state text) returns void language plpgsql as $$
begin
    begin
        execute p_sql;
    exception when others then
        if sqlstate = p_state then return; end if;
        raise;
    end;
    raise exception 'expected_failure_missing';
end;
$$;
