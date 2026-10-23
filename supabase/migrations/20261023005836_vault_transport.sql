-- Opaque transport only. Clients must verify ciphertext, authority and checkpoints.
-- Apply only to a dedicated project. No existing Bite application schema is used.
begin;

create schema vault;
create schema vault_private;
revoke all on schema vault, vault_private from public, anon, authenticated;
grant usage on schema vault, vault_private to authenticated;
alter default privileges in schema vault revoke all on tables from public, anon, authenticated;
alter default privileges in schema vault revoke execute on functions from public, anon, authenticated;
alter default privileges in schema vault_private revoke all on tables from public, anon, authenticated;
alter default privileges in schema vault_private revoke execute on functions from public, anon, authenticated;

create table vault.vaults (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null default auth.uid() references auth.users(id),
    created_at timestamptz not null default now()
);
create index vaults_owner on vault.vaults(owner_id);

create table vault_private.usage (
    vault_id uuid primary key references vault.vaults(id),
    next_seq bigint not null default 0 check (next_seq >= 0),
    object_count bigint not null default 0 check (object_count between 0 and 10000),
    byte_count bigint not null default 0 check (byte_count between 0 and 536870912)
);

create table vault.objects (
    vault_id uuid not null references vault.vaults(id),
    body bytea not null check (octet_length(body) between 1 and 1048576),
    digest bytea generated always as (sha256(body)) stored,
    seq bigint not null check (seq > 0),
    created_at timestamptz not null default now(),
    primary key (vault_id, digest),
    unique (vault_id, seq)
);

create table vault.heads (
    vault_id uuid primary key references vault.vaults(id),
    head bytea not null check (octet_length(head) = 32),
    revision bigint not null check (revision > 0),
    foreign key (vault_id, head) references vault.objects(vault_id, digest)
);

alter table vault.vaults enable row level security;
alter table vault.objects enable row level security;
alter table vault.heads enable row level security;
alter table vault_private.usage enable row level security;

create policy real_user on vault.vaults as restrictive to authenticated
    using ((select auth.uid()) is not null and (select auth.jwt()->>'is_anonymous') is distinct from 'true')
    with check ((select auth.uid()) is not null and (select auth.jwt()->>'is_anonymous') is distinct from 'true');
create policy real_user on vault.objects as restrictive to authenticated
    using ((select auth.uid()) is not null and (select auth.jwt()->>'is_anonymous') is distinct from 'true')
    with check ((select auth.uid()) is not null and (select auth.jwt()->>'is_anonymous') is distinct from 'true');
create policy real_user on vault.heads as restrictive to authenticated
    using ((select auth.uid()) is not null and (select auth.jwt()->>'is_anonymous') is distinct from 'true');

create policy owner on vault.vaults to authenticated
    using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));
create policy owner on vault.objects to authenticated
    using (exists (select 1 from vault.vaults v where v.id = vault_id and v.owner_id = (select auth.uid())))
    with check (exists (select 1 from vault.vaults v where v.id = vault_id and v.owner_id = (select auth.uid())));
create policy owner on vault.heads for select to authenticated
    using (exists (select 1 from vault.vaults v where v.id = vault_id and v.owner_id = (select auth.uid())));

-- Privileged implementations have no dynamic SQL and never trust user metadata.
create function vault_private.initialize_usage() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
    if auth.uid() is null or new.owner_id is distinct from auth.uid()
       or auth.jwt()->>'is_anonymous' = 'true' then
        raise exception using errcode = '42501', message = 'vault_denied';
    end if;
    insert into vault_private.usage(vault_id) values (new.id);
    return new;
end;
$$;
revoke all on function vault_private.initialize_usage() from public, anon, authenticated;
create trigger initialize_usage after insert on vault.vaults
    for each row execute function vault_private.initialize_usage();

create function vault_private.admit_object() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
    previous vault.objects%rowtype;
    allocated bigint;
begin
    if auth.uid() is null or auth.jwt()->>'is_anonymous' = 'true'
       or not exists (select 1 from vault.vaults where id = new.vault_id and owner_id = auth.uid()) then
        raise exception using errcode = '42501', message = 'vault_denied';
    end if;
    if new.body is null or octet_length(new.body) not between 1 and 1048576 then
        raise exception using errcode = '22023', message = 'object_size';
    end if;
    -- Held until commit. A later sequence cannot become visible before this transaction.
    perform 1 from vault_private.usage where vault_id = new.vault_id for update;
    select * into previous from vault.objects
        where vault_id = new.vault_id and digest = pg_catalog.sha256(new.body);
    if found then
        if previous.body <> new.body then
            raise exception using errcode = '22023', message = 'digest_conflict';
        end if;
        -- Exact-byte retry succeeds even at quota. Caller must use ON CONFLICT DO NOTHING.
        new.seq := previous.seq;
        return new;
    end if;
    update vault_private.usage
        set next_seq = next_seq + 1, object_count = object_count + 1,
            byte_count = byte_count + octet_length(new.body)
        where vault_id = new.vault_id and object_count < 10000
            and byte_count <= 536870912 - octet_length(new.body)
        returning next_seq into allocated;
    if not found then
        raise exception using errcode = '54000', message = 'vault_quota';
    end if;
    new.seq := allocated;
    return new;
end;
$$;
revoke all on function vault_private.admit_object() from public, anon, authenticated;
create trigger admit_object before insert on vault.objects
    for each row execute function vault_private.admit_object();

create function vault_private.cas_head(p_vault uuid, p_expected bytea, p_new bytea)
returns bigint language plpgsql security definer set search_path = '' as $$
declare
    current_head bytea;
    current_revision bigint;
begin
    if auth.uid() is null or auth.jwt()->>'is_anonymous' = 'true' then
        raise exception using errcode = '42501', message = 'vault_denied';
    end if;
    perform 1 from vault.vaults where id = p_vault and owner_id = auth.uid() for update;
    if not found then
        raise exception using errcode = '42501', message = 'vault_denied';
    end if;
    if p_new is null or octet_length(p_new) <> 32
       or (p_expected is not null and octet_length(p_expected) <> 32)
       or not exists (select 1 from vault.objects where vault_id = p_vault and digest = p_new) then
        raise exception using errcode = '22023', message = 'head_invalid';
    end if;
    select head, revision into current_head, current_revision from vault.heads where vault_id = p_vault;
    if current_head = p_new then return current_revision; end if;
    if current_head is distinct from p_expected then
        raise exception using errcode = 'PT409', message = 'head_conflict';
    end if;
    current_revision := coalesce(current_revision, 0) + 1;
    insert into vault.heads(vault_id, head, revision) values (p_vault, p_new, current_revision)
        on conflict (vault_id) do update set head = excluded.head, revision = excluded.revision;
    return current_revision;
end;
$$;
revoke all on function vault_private.cas_head(uuid, bytea, bytea) from public, anon, authenticated;
grant execute on function vault_private.cas_head(uuid, bytea, bytea) to authenticated;

create function vault.cas_head(p_vault uuid, p_expected bytea, p_new bytea)
returns bigint language sql security invoker set search_path = '' as $$
    select vault_private.cas_head(p_vault, p_expected, p_new);
$$;
revoke all on function vault.cas_head(uuid, bytea, bytea) from public, anon, authenticated;
grant execute on function vault.cas_head(uuid, bytea, bytea) to authenticated;

revoke all on all tables in schema vault, vault_private from public, anon, authenticated;
grant select on vault.vaults, vault.objects, vault.heads to authenticated;
grant insert(id) on vault.vaults to authenticated;
grant insert(vault_id, body) on vault.objects to authenticated;

commit;
