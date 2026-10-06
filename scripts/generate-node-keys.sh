#!/bin/bash
# generate-node-keys.sh — Generate unique libp2p node keys for each validator
#
# Usage:
#   ./scripts/generate-node-keys.sh              # Generate 3 keys (alice, bob, charlie)
#   ./scripts/generate-node-keys.sh <name>        # Generate 1 key for <name>
#
# Output: keys/<name>.key (64-char hex, gitignored)
#
# These are Ed25519 libp2p identity keys. With PQC transport enabled,
# PeerIds are derived from Falcon-1024 instead, but the node-key is
# still used as the Ed25519 fallback identity.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
KEY_DIR="${REPO_DIR}/keys"

mkdir -p "$KEY_DIR"

# Ensure keys/ is gitignored
if ! grep -q '^keys/' "${REPO_DIR}/.gitignore" 2>/dev/null; then
    echo 'keys/' >> "${REPO_DIR}/.gitignore"
    echo "Added keys/ to .gitignore"
fi

generate_key() {
    local name="$1"
    local key_file="${KEY_DIR}/${name}.key"

    if [ -f "$key_file" ]; then
        echo "  ${name}: key already exists at ${key_file} (skipping)"
        return 0
    fi

    # Generate 32 random bytes as hex (64 chars)
    local key
    key=$(openssl rand -hex 32)

    echo "$key" > "$key_file"
    chmod 600 "$key_file"
    echo "  ${name}: generated ${key_file}"
}

if [ $# -ge 1 ]; then
    echo "Generating node key for: $1"
    generate_key "$1"
else
    echo "Generating node keys for all validators..."
    generate_key "alice"
    generate_key "bob"
    generate_key "charlie"
fi

echo ""
echo "Keys stored in: ${KEY_DIR}/"
echo ""
echo "To use in docker-compose, set NODE_KEY env var:"
echo "  NODE_KEY=\$(cat keys/alice.key) docker-compose up alice"
echo ""
echo "Or mount as a Docker secret / --node-key-file in production."
