#!/bin/bash
# devnet-n.sh — N-validator native QH devnet for validator-scaling load tests.
#
# Runs N quantumharmony-node processes on ONE machine (no Docker), each with
# its own base-path, SPHINCS+ keystore, and ports. Never touches live
# validators; everything lives under $BASE and is torn down with `down`.
#
# Usage:
#   ./scripts/devnet-n.sh up <N>          # generate keys+spec, launch N nodes
#   ./scripts/devnet-n.sh status          # best/finalized per node
#   ./scripts/devnet-n.sh sample <csv> [interval_s]   # append metrics rows
#   ./scripts/devnet-n.sh down            # kill nodes, keep data for autopsy
#   ./scripts/devnet-n.sh clean           # kill nodes + delete $BASE
#
# Ports (localhost only), collision-free to N=2000:
#   node i: rpc=$((20000+i)) p2p=$((22000+i)) prom=$((24000+i))
#
# Env overrides: BASE, BIN, SKIP_GEN=1 (use pre-generated keys+chainspec in $BASE)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$REPO_DIR/target/release/quantumharmony-node}"
GEN="${GEN:-$REPO_DIR/target/release/generate-devnet-chain-spec}"
BASE="${BASE:-/tmp/qh-devnet-n}"
CHAIN_ID="qh_devnet"
CHAINSPEC="$BASE/devnet-chainspec-raw.json"

rpc_port()  { echo $((20000 + $1)); }
p2p_port()  { echo $((22000 + $1)); }
prom_port() { echo $((24000 + $1)); }

rpc() { # rpc <node_i> <method> [params_json]
    curl -s -m 5 -H 'Content-Type: application/json' \
        -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"$2\",\"params\":${3:-[]}}" \
        "http://127.0.0.1:$(rpc_port "$1")"
}

node_count() { ls -d "$BASE"/node-* 2>/dev/null | wc -l | tr -d ' '; }

cmd_up() {
    local n="${1:?usage: devnet-n.sh up <N>}"
    [ -x "$BIN" ] || { echo "ERROR: node binary not found at $BIN"; exit 1; }
    [ -x "$GEN" ] || { echo "ERROR: generate-devnet-chain-spec not built ($GEN)"; exit 1; }

    # bracketed pattern so the guard can't match its own invocation chain
    if pgrep -f "[q]h-devnet-n-node" >/dev/null 2>&1; then
        echo "ERROR: devnet processes already running — 'down' or 'clean' first"
        exit 1
    fi
    if [ "${SKIP_GEN:-}" = "1" ]; then
        [ -f "$CHAINSPEC" ] || { echo "ERROR: SKIP_GEN=1 but $CHAINSPEC missing"; exit 1; }
        [ -d "$BASE/validator-$n" ] || { echo "ERROR: SKIP_GEN=1 but validator-$n keys missing in $BASE"; exit 1; }
        # remove only node state, keep keys + chainspec
        rm -rf "$BASE"/node-*
        echo "== using pre-generated keys + chainspec in $BASE =="
    else
        rm -rf "$BASE"
        mkdir -p "$BASE"
        echo "== generating $n SPHINCS+ validator keys + chainspec =="
        "$GEN" "$n" "$BASE"
    fi

    echo "== launching node 1 (bootnode) =="
    launch_node 1 ""

    # Wait for node 1 RPC, then read its peer id for bootnode wiring
    local peer_id=""
    for _ in $(seq 1 30); do
        peer_id=$(rpc 1 system_localPeerId 2>/dev/null | jq -r '.result // empty') && [ -n "$peer_id" ] && break
        sleep 1
    done
    [ -n "$peer_id" ] || { echo "ERROR: node 1 RPC never came up; see $BASE/node-1/node.log"; exit 1; }
    echo "   bootnode peer id: $peer_id"
    local bootnode="/ip4/127.0.0.1/tcp/$(p2p_port 1)/p2p/$peer_id"

    for i in $(seq 2 "$n"); do
        launch_node "$i" "$bootnode"
    done

    echo "== $n nodes launched; waiting 30s for block production =="
    sleep 30
    cmd_status
}

launch_node() {
    local i=$1 bootnode=$2
    local dir="$BASE/node-$i"
    local keystore="$dir/chains/$CHAIN_ID/keystore"
    mkdir -p "$keystore"

    # Inject SPHINCS+ aura key: filename = 61757261 ("aura") + pubkey hex,
    # content = JSON-quoted 0x-prefixed full secret key.
    local pub sec
    pub=$(jq -r .public_key "$BASE/validator-$i/key.json")
    sec=$(jq -r .secret_key "$BASE/validator-$i/key.json")
    printf '"%s"' "$sec" > "$keystore/61757261${pub#0x}"

    local extra=()
    [ -n "$bootnode" ] && extra+=(--bootnodes "$bootnode")

    DISABLE_PQC_TRANSPORT=1 DISABLE_QUANTUM_P2P=1 \
    "$BIN" \
        --chain "$CHAINSPEC" \
        --validator \
        --name "qh-devnet-n-node-$i" \
        --base-path "$dir" \
        --node-key "$(printf '%064x' "$i")" \
        --port "$(p2p_port "$i")" \
        --out-peers 128 --in-peers 256 \
        --pool-type single-state \
        --rpc-port "$(rpc_port "$i")" \
        --rpc-cors=all --rpc-methods=Unsafe \
        --prometheus-port "$(prom_port "$i")" \
        --no-telemetry \
        ${extra[@]+"${extra[@]}"} \
        > "$dir/node.log" 2>&1 &
    echo "$!" > "$dir/node.pid"
    echo "   node-$i up (pid $(cat "$dir/node.pid"), rpc $(rpc_port "$i"))"
}

cmd_status() {
    local n; n=$(node_count)
    [ "$n" -gt 0 ] || { echo "no devnet at $BASE"; exit 1; }
    printf '%-8s %-6s %-10s %-11s %-5s %s\n' node alive best finalized lag peers
    for i in $(seq 1 "$n"); do
        local alive="no" best="-" fin="-" lag="-" peers="-"
        if kill -0 "$(cat "$BASE/node-$i/node.pid" 2>/dev/null)" 2>/dev/null; then alive=yes; fi
        local h f p
        h=$(rpc "$i" chain_getHeader | jq -r '.result.number // empty' 2>/dev/null)
        if [ -n "$h" ]; then
            best=$((h))
            f=$(rpc "$i" chain_getFinalizedHead | jq -r '.result // empty')
            if [ -n "$f" ]; then
                fh=$(rpc "$i" chain_getHeader "[\"$f\"]" | jq -r '.result.number // empty')
                [ -n "$fh" ] && fin=$((fh)) && lag=$((best - fin))
            fi
            peers=$(rpc "$i" system_health | jq -r '.result.peers // "-"')
        fi
        printf '%-8s %-6s %-10s %-11s %-5s %s\n' "node-$i" "$alive" "$best" "$fin" "$lag" "$peers"
    done
}

sample_one() { # $1=node index, $2=ts, $3=csv — one CSV line, tolerant of dead RPC
    local i=$1 ts=$2 csv=$3
    local pid best="" fin="" lag="" peers="" cpu="" rss=""
    pid=$(cat "$BASE/node-$i/node.pid" 2>/dev/null || echo "")
    local h f fh
    h=$(rpc "$i" chain_getHeader | jq -r '.result.number // empty' 2>/dev/null)
    [ -n "$h" ] && best=$((h))
    f=$(rpc "$i" chain_getFinalizedHead | jq -r '.result // empty' 2>/dev/null)
    if [ -n "$f" ]; then
        fh=$(rpc "$i" chain_getHeader "[\"$f\"]" | jq -r '.result.number // empty')
        [ -n "$fh" ] && fin=$((fh)) && [ -n "$best" ] && lag=$((best - fin))
    fi
    peers=$(rpc "$i" system_health | jq -r '.result.peers // empty' 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        read -r cpu rss <<< "$(ps -o %cpu= -o rss= -p "$pid" 2>/dev/null | awk '{printf "%s %.0f", $1, $2/1024}')"
    fi
    echo "$ts,node-$i,$best,$fin,$lag,$peers,$cpu,$rss" >> "$csv"
}

cmd_sample() { # parallel sampler: whole pass in ~2×RPC-timeout regardless of N
    local csv="${1:?usage: devnet-n.sh sample <out.csv> [interval_s]}"
    local interval="${2:-10}"
    local n; n=$(node_count)
    [ -f "$csv" ] || echo "ts,node,best,finalized,lag,peers,cpu_pct,rss_mb" > "$csv"
    while true; do
        local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        for i in $(seq 1 "$n"); do
            sample_one "$i" "$ts" "$csv" &
            [ $((i % 64)) -eq 0 ] && wait
        done
        wait
        sleep "$interval"
    done
}

cmd_sample_old_serial() {
    local csv="${1:?usage}"
    local interval="${2:-10}"
    local n; n=$(node_count)
    [ -f "$csv" ] || echo "ts,node,best,finalized,lag,peers,cpu_pct,rss_mb" > "$csv"
    while true; do
        local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        for i in $(seq 1 "$n"); do
            local pid best="" fin="" lag="" peers="" cpu="" rss=""
            pid=$(cat "$BASE/node-$i/node.pid" 2>/dev/null || echo "")
            local h f fh
            h=$(rpc "$i" chain_getHeader | jq -r '.result.number // empty' 2>/dev/null)
            [ -n "$h" ] && best=$((h))
            f=$(rpc "$i" chain_getFinalizedHead | jq -r '.result // empty' 2>/dev/null)
            if [ -n "$f" ]; then
                fh=$(rpc "$i" chain_getHeader "[\"$f\"]" | jq -r '.result.number // empty')
                [ -n "$fh" ] && fin=$((fh)) && [ -n "$best" ] && lag=$((best - fin))
            fi
            peers=$(rpc "$i" system_health | jq -r '.result.peers // empty' 2>/dev/null)
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                read -r cpu rss <<< "$(ps -o %cpu= -o rss= -p "$pid" | awk '{printf "%s %.0f", $1, $2/1024}')"
            fi
            echo "$ts,node-$i,$best,$fin,$lag,$peers,$cpu,$rss" >> "$csv"
        done
        sleep "$interval"
    done
}

cmd_down() {
    local n; n=$(node_count)
    for i in $(seq 1 "$n"); do
        local pid; pid=$(cat "$BASE/node-$i/node.pid" 2>/dev/null || echo "")
        [ -n "$pid" ] && kill "$pid" 2>/dev/null && echo "killed node-$i (pid $pid)" || true
    done
    pkill -f "qh-devnet-n-node" 2>/dev/null || true
    echo "data kept at $BASE (use 'clean' to delete)"
}

cmd_clean() {
    cmd_down || true
    sleep 1
    rm -rf "$BASE"
    echo "removed $BASE"
}

cmd_start() { # restart a single stopped node, wiring it to node 1 as bootnode
    local i="${1:?usage: devnet-n.sh start <i>}"
    local peer_id
    peer_id=$(rpc 1 system_localPeerId | jq -r '.result // empty')
    [ -n "$peer_id" ] || { echo "ERROR: node 1 RPC unreachable"; exit 1; }
    launch_node "$i" "/ip4/127.0.0.1/tcp/$(p2p_port 1)/p2p/$peer_id"
}

case "${1:-}" in
    up)      shift; cmd_up "$@" ;;
    start)   shift; cmd_start "$@" ;;
    status)  cmd_status ;;
    sample)  shift; cmd_sample "$@" ;;
    down)    cmd_down ;;
    clean)   cmd_clean ;;
    *)       grep '^#' "$0" | head -20; exit 1 ;;
esac
