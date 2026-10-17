# Installation

`deploy/ipc/agentvault_installer.py` installs the broker, bridge and human app with a
dedicated broker account. It replaces the earlier shell templates.

**Status:** the installer has passed sandbox tests only. Nobody has run it as root. Do not
enroll production passwords or PINs until the gates in
[IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) pass. See [Unproven](#unproven).

## What it installs

| Item | Path | Owner and mode |
| --- | --- | --- |
| Broker daemon | `/Library/PrivilegedHelperTools/dev.agentvault.broker` | root:wheel 0755 |
| MCP bridge | `/Library/AgentVault/agent-vault-bridge` | root:wheel 0755 |
| Human app | `/Applications/AgentVault.app` | root:wheel, 0755 directories |
| Configuration | `/Library/Application Support/AgentVault/config.json` | root:wheel 0644 in a root:wheel 0755 directory |
| LaunchDaemon | `/Library/LaunchDaemons/dev.agentvault.broker.plist` | root:wheel 0644 |
| Private data | `/private/var/db/agent-vault` | `_agentvault` 0700 |
| Seeds | `keychain.password`, `state-integrity.key` | `_agentvault` 0400, 32 random bytes each |
| Account | Hidden `_agentvault` user and group | UID = GID in 200–399, shell `/usr/bin/false`, home `/var/empty`, password `*` |
| Installer state | `/private/var/db/agent-vault-install` | root:wheel 0700: lock, account journal, snapshots |

The configuration has the form `{"ipc": {...}, "approvalPublicKey": "<base64 X9.63>"}`.
Each of the three code requirements pins an Apple anchor, the Developer ID OIDs, team
`3JWAQ92CB4`, an identifier (`dev.agentvault.broker`, `dev.agentvault.bridge` or
`dev.agentvault.app`) and the program's cdhash. The installer reads each cdhash from its
own copy of the signed program.

The LaunchDaemon has `Program` and no arguments. It runs as `_agentvault` in the system
domain, with umask 077 and the two Mach services `dev.agentvault.broker.read` and
`dev.agentvault.broker.admin`.

## How an installation runs

1. The installer takes the installer lock in `/private/var/db/agent-vault-install`. A
   second installer is refused. Leftover files from an interrupted run are deleted there,
   and nowhere else.
2. It copies the three programs into that root-only directory. It does not follow links
   and refuses anything other than regular files and directories. Every later step uses
   this copy. A change to the source directory after this point has no effect.
3. With `codesign`, it checks each copy for these properties:
   - a valid strict signature
   - the expected identifier
   - team `3JWAQ92CB4`
   - the hardened runtime
   - no `get-task-allow` entitlement
   - exact role entitlements: broker and bridge have none; the app has either none
     for a review build or exactly its Bite app/team identity and private Keychain group
   - the Developer ID requirement with the copy's own cdhash
4. It plans every change and refuses before any change if one of these checks fails:
   - The account attributes, the UID/GID collisions or the client UID are wrong.
   - A directory on any target path is not owned by root or is writable by group or
     others. `/Applications` is the one exception: it may be writable by group `admin`.
   - An existing item is a link, has extra hard links, has the wrong owner or mode, or is
     not this installer's code.
   - The configuration would change without the confirmation that the change needs (see
     [Upgrades and identity changes](#upgrades-and-identity-changes)).
5. It creates the account. Before the first `dscl` write, it records the chosen UID in
   the account journal.
6. If the private directory is absent, the installer builds it in staging together with
   both seeds and moves it into place with one exclusive rename. The installer never
   rewrites existing seeds. It creates a missing seed only when the directory holds
   nothing else. It never writes through a name inside the broker-owned directory.
7. It moves each verified program into place with an exclusive rename, or an atomic swap
   when an older version is present. The swapped-out version is deleted in staging.
8. It writes the configuration and the plist in staging and renames each into place.
9. It verifies the installed result. If anything changed, or if an earlier run was
   interrupted, it stops its own job, `system/dev.agentvault.broker`, and bootstraps it
   again. It does not touch other jobs.

Every file operation opens the path one component at a time with `O_NOFOLLOW` and works
on directory descriptors. A swapped symlink therefore cannot redirect a root write.

If a run stops partway, run the same command again. Each step either finds its result
already in place or completes it. The tests interrupt every mutation in turn and check
that the next run converges.

## Install

You need these:

- A signed release directory from `scripts/build-release.py`. It contains
  `AgentVault.app`, `agent-vault-bridge`, `agent-vault-broker` and `deployment/`.
- The client UID. This is the UID of the user who runs the bridge and the app (`id -u`).
  It must be 501 or higher.
- The approval public key, exported as that user:

  ```sh
  AgentVault.app/Contents/MacOS/AgentVault --print-approval-public-key > approval-key.json
  ```

  Open the app's Approval Key screen and independently compare its displayed SHA-256
  fingerprint with the export. Pass the fingerprint read from the app as
  `--approval-key-sha256`, rather than copying it from the file you are checking. The installer
  recomputes the fingerprint from the key and refuses a mismatch. It also refuses fixture
  keys, keys without user presence and points that are not on P-256.

1. Check the release against `manifest.json` and with
   `codesign --verify --strict --verbose=2`.
2. Copy the installer to a directory that only root can write:

   ```sh
   sudo mkdir -m 0700 /private/var/root/agentvault-installer
   sudo cp deployment/agentvault_installer.py /private/var/root/agentvault-installer/
   ```

   Root runs this file. It must not stay in a directory that another user can change.
3. Do a dry run as yourself. This makes no change to the system:

   ```sh
   mkdir -m 0700 /tmp/av-sandbox
   /usr/bin/python3 -I -O deployment/agentvault_installer.py --sandbox /tmp/av-sandbox \
       sandbox-init --client-uid "$(id -u)"
   /usr/bin/python3 -I -O deployment/agentvault_installer.py --sandbox /tmp/av-sandbox \
       install --payload . --client-uid "$(id -u)" \
       --approval-key-file approval-key.json --approval-key-sha256 <fingerprint>
   ```

   The sandbox runs the real `codesign` checks on its own copy of the programs. The
   accounts and launchd in the sandbox are simulated.
4. Install:

   ```sh
   sudo AGENT_VAULT_INSTALL=dedicated-account /usr/bin/python3 -I -O \
       /private/var/root/agentvault-installer/agentvault_installer.py install \
       --payload "$PWD" --client-uid "$(id -u)" \
       --approval-key-file approval-key.json --approval-key-sha256 <fingerprint>
   ```

5. Verify:

   ```sh
   sudo AGENT_VAULT_INSTALL=dedicated-account /usr/bin/python3 -I -O \
       /private/var/root/agentvault-installer/agentvault_installer.py verify
   ```

`-I` keeps Python from importing modules from the current or script directory. No
security check uses `assert`, so `-O` removes no guard.

## Upgrades and identity changes

A configuration change needs explicit confirmation from root. A retry never replaces a
value silently.

| Change | Required option |
| --- | --- |
| New signed programs, so new cdhash pins | `--upgrade` |
| Different approval public key | `--replace-approval-key <SHA-256 of the current key>` |
| Different client UID | `--replace-client-uid <current UID>` |
| Configured broker UID differs from `_agentvault` | Refused. Repair by hand. |

On refusal, the installer prints the exact option and value that it expects.

An upgrade keeps the account, the private directory and the seeds byte for byte. It then
restarts the daemon.

## Uninstall

```sh
sudo AGENT_VAULT_INSTALL=dedicated-account /usr/bin/python3 -I -O \
    /private/var/root/agentvault-installer/agentvault_installer.py uninstall
```

Uninstall stops `system/dev.agentvault.broker`. It then removes the plist, the three
programs and the configuration. It removes a program only if that program matches the
cdhash pinned in the configuration, and refuses before any change otherwise. It keeps
`/private/var/db/agent-vault`, the `_agentvault` account and the installer state
directory.

To delete these after uninstall, run the following commands by hand. They are deliberate,
irreversible steps:

```sh
sudo rm -rf /private/var/db/agent-vault /private/var/db/agent-vault-install
sudo dscl . -delete /Users/_agentvault
sudo dscl . -delete /Groups/_agentvault
```

## Refusals that need a person

The installer refuses each of these cases and does not repair them:

- An existing item at a target path that is not this installer's: a link, a file with
  extra hard links, the wrong owner or mode, foreign code, or a plist with another label.
  Inspect the item and move it away by hand.
- An installed program whose signature no longer verifies, for example a modified app
  in `/Applications`. Remove that program and run the installer again.
- A private directory that holds broker state but is missing a seed. A new seed would not
  decrypt the existing state. Restore the seed from a backup, or remove the directory to
  start empty.
- A partial `_agentvault` record without a matching journal, or account attributes that
  conflict with the expected ones.
- An interrupted upgrade followed by `uninstall`. The installed programs no longer match
  the old pins. Finish the upgrade first.

## Developer verification

```sh
python3 scripts/verify-installer.py --signed-payload dist/AgentVault-review
```

The script never runs as root. It does these steps:

1. It runs `deploy/tests/test_installer.py` twice, with and without `-O`, in isolated
   mode.
2. It disables one guard at a time in a temporary copy of the installer and requires the
   matching test to fail.
3. With `--signed-payload`, it runs the CLI in a sandbox against a copy of the signed
   programs. It checks that the pins equal the cdhashes that `codesign` reports. It also
   checks that `verify` passes, that a second install reports no change, and that
   `uninstall` removes only the installed items.

The tests also cover these properties:

- Sandbox mode refuses to run as root and works only below a marked private directory.
- Only the file-system classes call mutating `os` functions.
- Only `run_command` starts processes, and it allows only `codesign`, `dscl` and
  `launchctl`.

`config.json.template` and `dev.agentvault.broker.plist.template` are reviewed
references. A test requires the installer's output to equal them, and the Swift
`ConfigurationTests` validate the configuration template with `IPCConfiguration`.

## Unproven

- The live path has never run: no root run, no real `dscl` account creation and no
  `launchctl bootstrap`. The sandbox simulates ownership, accounts and launchd.
- The daemon's start as `_agentvault` and its system-domain Mach lookup have not been
  observed.
- Code requirements are evaluated against the host-native slice's cdhash. A universal
  build running under a different architecture would not match.
- `/Applications` is writable by administrators. The installer verifies the app it
  placed. Later replacement is caught only by the admin service's cdhash pin.
- The approval key's protection is the app's own claim in the export. The installer
  cannot attest hardware protection.
- The app displays the public-key fingerprint, but the installer cannot establish that
  the operator compared that display with the export. This is a trusted installation step.
