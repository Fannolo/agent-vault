#!/bin/sh
set -eu
vault_binary="/Library/AgentVault/agent-vault-bridge"
if [ ! -x "$vault_binary" ]; then
  echo "Agent Vault: the signed bridge has not been installed" >&2
  exit 1
fi
exec "$vault_binary" mcp
