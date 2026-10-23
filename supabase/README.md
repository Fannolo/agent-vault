# Opaque cloud transport

This migration is a server-side transport component. It does not implement signup,
token custody, device enrollment, a client sync engine or the successor vault format.
No remote project has been provisioned. Paid provisioning was declined; existing Bite
projects must not receive this migration.

The dedicated deployment exposes the `vault` schema through PostgREST. Do not expose
`vault_private`. Clients use their own authenticated session and the publishable API key;
no administrative key belongs in a client, app bundle, MCP process or CI.

## Contract

- Create a vault with `POST /rest/v1/vaults`, supplying only `id` or using its default.
  `owner_id` comes from `auth.uid()`. Editable metadata is never authority.
- Put an opaque object with `POST /rest/v1/objects`, supplying `vault_id` and `body`.
  Use `Prefer: resolution=ignore-duplicates` with `on_conflict=vault_id,digest` for
  exact-byte retries. PostgREST bytea values use the PostgreSQL hex representation.
  Each object is 1–1,048,576 bytes; this transport bound is not a reviewed storage format.
- Read changes with `vault_id=eq.ID&seq=gt.CURSOR&order=seq&limit=500`.
  Sequence allocation holds a per-vault row lock until commit. A later sequence cannot
  commit while an earlier allocation remains uncommitted. Aborted inserts do not consume
  quota. The unique `(vault_id, seq)` index supports the cursor query.
- Read the current `heads` row. Call `POST /rest/v1/rpc/cas_head` with `p_vault`,
  `p_expected` (null for first head) and `p_new` (an existing object's 32-byte digest).
  A conflicting expected head raises `PT409` (`head_conflict`), mapped by PostgREST to
  HTTP 409; an exact current-head retry returns its revision.
  The private implementation checks owner and non-anonymous identity explicitly and
  locks the vault row. Clients have no direct head insert/update/delete privilege.
- Objects cannot be updated or deleted by client roles. Tombstones must be signed
  immutable objects in the reviewed successor format, not server deletion.

Every table has RLS. Anonymous users have no schema access. Anonymous authenticated
sessions and absent subjects are refused. Each vault permits 10,000 objects and
512 MiB total payload. Exact retries work even at quota. There is no account-wide
vault-count or storage quota yet; deployment needs an abuse/billing policy.

The server learns object sizes, times, vault ownership and transport account identity.
It can withhold or serve stale/forked data. Clients must verify digest, signatures,
membership and pinned checkpoints independently; neither cursor nor CAS proves freshness.
The client must reject unsupported formats and oversize objects before use. This schema
stores no plaintext credentials, device grants or membership authority.

## Native verification

Install PostgreSQL 16 or 17 without starting a global service, then run:

```sh
python3 -I scripts/verify-cloud-transport.py --postgres-bin /path/to/postgres/bin
```

The runner creates a private temporary cluster and Unix socket, with TCP disabled.
It tests owner and cross-user reads, editable-metadata spoofing, anonymous and missing
subjects, immutable writes, field privileges, size/quota boundaries, retry at quota,
conditional-head races and commit-ordered cursors. It stops only its own server and
records exit confirmation, input hashes and logs under ignored `verification-logs/`.
The local baseline used PostgreSQL 17.11. Hosted Linux CI at `b277e4a` passed with
PostgreSQL 16.15 in [run 39884513327](https://github.com/Fannolo/agent-vault/actions/runs/39884513327).
Both receipts record unchanged SQL/runner inputs and confirmed owned-server exit.

The canonical process owner now observes Linux exits through pidfds and reads `/proc`
membership only for the unreaped leader's pinned process group. It never signals a PID
discovered by that scan. macOS retains kqueue. Shared ownership tests check timeout,
descendant cleanup, unrelated-process survival, stopped-child behavior and retention of
the unreaped leader. That run passed all 16 ownership tests on Linux; the native run
passed with one Linux-only test skipped. An unreadable or undecodable `/proc` record
conservatively counts as possible live membership, even for an unrelated process.
This can cause unnecessary signals to the pinned owned group and two cleanup grace
periods; it never authorizes signalling the discovered process. A pidfd-open error
propagates directly and does not fall through to the macOS kqueue path.

`cloud_transport_bootstrap.sql` supplies synthetic `auth.users`, `auth.uid()` and
`auth.jwt()` in that fresh cluster only. Claims are injected by the tests. These checks
do not test Supabase JWT validation, PostgREST behavior, signup, email delivery, project
settings or hosted advisors. Hosted acceptance still requires a dedicated approved
project, anonymous sign-in disabled, signup initially closed, redirect/PKCE configuration,
two real test users, advisor review and SMTP before public signup.

The migration filename was created with Supabase CLI 2.109.1. Native SQL execution avoids
starting the Docker-dependent local Supabase stack while OrbStack must remain stopped.

References: [RLS](https://supabase.com/docs/guides/database/postgres/row-level-security),
[database functions](https://supabase.com/docs/guides/database/functions),
[runner PostgreSQL inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).
