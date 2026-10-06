#!/bin/bash
# devnet-up-v2.sh — 3-validator QH devnet on a single amd64 host.
#
# Uses a freshly-generated chainspec from /tmp/qh-devnet/devnet-raw.json
# and pre-populates each container's SPHINCS+ keystore with its validator
# secret before the node boots.
#
# Designed for Alice (has cycles + amd64). Does not interfere with the
# production validator container (different volumes, ports, docker network).
#
# Ports (host-side, bound to 127.0.0.1 so not internet-exposed):
#   RPC:        127.0.0.1:9970 (v1), 9971 (v2), 9972 (v3)
#   P2P:        30340, 30341, 30342 (all interfaces; OK for localhost-only devnet)
#   Prometheus: 9620, 9621, 9622

set -euo pipefail

IMAGE="sylvaincormier/quantumharmony-node:v43-real-keygen"
NET="qh-devnet"
CHAINSPEC="/tmp/qh-devnet/devnet-raw.json"
KEYS_DIR="/tmp/qh-devnet"
CHAIN_ID="qh_devnet"

if [ ! -f "$CHAINSPEC" ]; then
    echo "ERROR: $CHAINSPEC not found; run build-devnet-chainspec.py + build-spec --raw first"
    exit 1
fi

# --- Clean slate ---
for name in 1 2 3; do
    c="qh-devnet-v$name"
    if docker ps -a --format '{{.Names}}' | grep -q "^$c$"; then
        echo "Removing existing $c"
        docker rm -f "$c" >/dev/null
    fi
    docker volume rm -f "$c-data" 2>/dev/null || true
done
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

# --- Pre-populate keystore in each volume before booting ---
# Uses an alpine helper to write the key file in the volume.
inject_key() {
    local n=$1 vol=$2
    local secret_hex
    local pubkey_hex
    secret_hex=$(jq -r .secret_key "$KEYS_DIR/validator-$n/key.json")
    pubkey_hex=$(jq -r .public_key "$KEYS_DIR/validator-$n/key.json")
    # substrate keystore filename: 61757261 (= "aura" ascii) + pubkey_hex
    local fname="61757261${pubkey_hex#0x}"
    local content="\"$secret_hex\""
    echo "  validator-$n: injecting key (pubkey ${pubkey_hex:2:12}...)"
    docker run --rm -v "$vol:/data" alpine sh -c "
        mkdir -p /data/chains/$CHAIN_ID/keystore &&
        printf '%s' '$content' > /data/chains/$CHAIN_ID/keystore/$fname
    "
}

launch() {
    local n=$1 rpc_port=$2 p2p_port=$3 prom_port=$4
    local c="qh-devnet-v$n"
    local vol="$c-data"
    echo "== $c: create volume + inject key + launch =="
    docker volume create "$vol" >/dev/null
    inject_key "$n" "$vol"

    docker run -d --name "$c" --restart=no \
        --network "$NET" \
        --hostname "v$n" \
        -v "$vol:/data" \
        -v "$CHAINSPEC:/config/chainspec.json:ro" \
        -p "127.0.0.1:$rpc_port:9944" \
        -p "$p2p_port:30333" \
        -p "127.0.0.1:$prom_port:9615" \
        -e DISABLE_PQC_TRANSPORT=1 \
        -e DISABLE_QUANTUM_P2P=1 \
        "$IMAGE" \
        --chain=/config/chainspec.json \
        --name "validator-$n" --validator \
        --base-path=/data \
        --node-key=$(printf "%064d" $n) \
        --rpc-external --rpc-cors=all --rpc-methods=Unsafe \
        --port=30333 --rpc-port=9944 \
        --prometheus-external --prometheus-port=9615 \
        >/dev/null
}

launch 1 9970 30340 9620
launch 2 9971 30341 9621
launch 3 9972 30342 9622

echo
echo "== waiting 30s for block production... =="
sleep 30

for n in 1 2 3; do
    port=$((9969 + n))
    c="qh-devnet-v$n"
    echo "--- $c (RPC 127.0.0.1:$port) ---"
    if ! docker ps --filter "name=$c" --format '{{.Status}}' | grep -q Up; then
        echo "  NOT RUNNING"
        docker logs --tail 8 "$c" 2>&1 | sed 's/^/    /' | tail -5
        continue
    fi
    curl -s -m 5 -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' \
        "http://127.0.0.1:$port" | head -c 200
    echo
    curl -s -m 5 -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":2}' \
        "http://127.0.0.1:$port" | grep -oE '"number":"0x[0-9a-f]+"' | head -1
done

echo
echo "== if blocks are advancing (number > 0x0), M2 devnet is up =="
echo "== cleanup: docker rm -f qh-devnet-v1 qh-devnet-v2 qh-devnet-v3 =="
