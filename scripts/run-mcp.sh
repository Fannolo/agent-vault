#!/bin/sh
set -eu
vault_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
vault_binary="$vault_root/.build/release/agent-vault"
if [ ! -x "$vault_binary" ]; then
  echo "Agent Vault: build first with swift build -c release" >&2
  exit 1
fi
if [ -z "${AGENT_VAULT_CLIENT_ID:-}" ]; then
  echo "Agent Vault: configure AGENT_VAULT_CLIENT_ID from a development client enrollment" >&2
  exit 1
fi
exec "$vault_binary" mcp --client-id "$AGENT_VAULT_CLIENT_ID" --development
