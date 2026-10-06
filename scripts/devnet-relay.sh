#!/bin/bash
# devnet-relay.sh — a 4 validator QuantumHarmony devnet in which every peer to
# peer edge crosses a PQTG post-quantum relay instead of a plain TCP socket.
#
# Topology. This is the shape a real deployment would take, not a demo shortcut:
# each node runs one relay SERVER in front of its own p2p port, and one relay
# CLIENT per peer it dials. Nodes are started --reserved-only with the reserved
# addresses pointing at their local relay clients, so a node cannot reach a peer
# except through a post-quantum tunnel.
#
#   node i  --plaintext-->  relay client (i -> j)  ==PQ==>  relay server j  -->  node j p2p
#
# For N=4 that is 4 relay servers and 12 relay clients, one per ordered pair.
# Every block, every Aura seal and every coherence vote between any two
# validators is inside an AES-256-GCM record keyed by ML-KEM-768, with the
# handshake transcript signed by Falcon-512.
#
# Isolated from production: own base path, own ports, own chainspec, own keys.
#
# Ports (all loopback):
#   node i:  rpc 20100+i   p2p 22100+i   prometheus 24100+i
#   relay server for node j:      41000+j
#   relay client on i toward j:   43000 + 10*i + j
#
# Usage: devnet-relay.sh up | status | proof | logs | down | clean

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$REPO_DIR/target/release/quantumharmony-node}"
GEN="${GEN:-$REPO_DIR/target/release/generate-devnet-chain-spec}"
RELAY="${RELAY:-$HOME/paraxiom/pq-transport-gateway/target/release/examples/relay_wan}"
BASE="${BASE:-/tmp/qh-devnet-relay}"
CHAIN_ID="qh_devnet"
CHAINSPEC="$BASE/devnet-chainspec-raw.json"
N="${N:-4}"

rpc_port()      { echo $((20100 + $1)); }
p2p_port()      { echo $((22100 + $1)); }
prom_port()     { echo $((24100 + $1)); }
relay_server()  { echo $((41000 + $1)); }
relay_client()  { echo $((43000 + 10 * $1 + $2)); }

rpc() {
    curl -s -m 5 -H 'Content-Type: application/json' \
        -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"$2\",\"params\":${3:-[]}}" \
        "http://127.0.0.1:$(rpc_port "$1")"
}

inject_key() {
    local i=$1
    local keystore="$BASE/node-$i/chains/$CHAIN_ID/keystore"
    mkdir -p "$keystore"
    local pub sec
    pub=$(jq -r .public_key "$BASE/validator-$i/key.json")
    sec=$(jq -r .secret_key "$BASE/validator-$i/key.json")
    printf '"%s"' "$sec" > "$keystore/61757261${pub#0x}"
}

launch_node() {
    local i=$1; shift
    local dir="$BASE/node-$i"
    DISABLE_PQC_TRANSPORT=1 DISABLE_QUANTUM_P2P=1 \
    "$BIN" \
        --chain "$CHAINSPEC" \
        --validator \
        --name "qh-relay-devnet-node-$i" \
        --base-path "$dir" \
        --node-key "$(printf '%064x' "$i")" \
        --port "$(p2p_port "$i")" \
        --out-peers 128 --in-peers 256 \
        --pool-type single-state \
        --rpc-port "$(rpc_port "$i")" \
        --rpc-cors=all --rpc-methods=Unsafe \
        --prometheus-port "$(prom_port "$i")" \
        --no-telemetry \
        "$@" \
        >> "$dir/node.log" 2>&1 &
    echo "$!" > "$dir/node.pid"
}

# Each relay process keeps its Falcon identity in its working directory, so
# every one of them gets its own directory or they would race on the same file.
spawn_relay() {
    local name=$1; shift
    local dir="$BASE/relay/$name"
    mkdir -p "$dir"
    ( cd "$dir" && exec "$RELAY" "$@" > "$dir/log" 2>&1 ) &
    echo "$!" > "$BASE/relay/$name.pid"
}

wait_for_rpc() {
    local i=$1 tries=${2:-40} out=""
    for _ in $(seq 1 "$tries"); do
        out=$(rpc "$i" system_localPeerId 2>/dev/null | jq -r '.result // empty')
        [ -n "$out" ] && { echo "$out"; return 0; }
        sleep 1
    done
    return 1
}

cmd_up() {
    [ -x "$BIN" ]   || { echo "ERROR: node binary missing at $BIN"; exit 1; }
    [ -x "$GEN" ]   || { echo "ERROR: chainspec generator missing at $GEN"; exit 1; }
    [ -x "$RELAY" ] || { echo "ERROR: relay binary missing at $RELAY"; exit 1; }
    if pgrep -f "[q]h-relay-devnet-node" >/dev/null 2>&1; then
        echo "ERROR: a relay devnet is already running — 'down' first"; exit 1
    fi

    rm -rf "$BASE"; mkdir -p "$BASE/relay"
    echo "== generating $N SPHINCS+ validator keys + chainspec =="
    "$GEN" "$N" "$BASE" | tail -2

    # Phase 1. Peer ids are derived from --node-key, which is fixed here, but
    # read them from the nodes rather than deriving them by hand so the mesh is
    # wired from what the nodes actually report.
    echo "== phase 1: reading peer ids =="
    declare -a PEER
    for i in $(seq 1 "$N"); do
        inject_key "$i"
        launch_node "$i"
    done
    for i in $(seq 1 "$N"); do
        PEER[$i]=$(wait_for_rpc "$i") || { echo "ERROR: node $i RPC never came up"; exit 1; }
        echo "   node-$i  ${PEER[$i]}"
    done
    for i in $(seq 1 "$N"); do kill "$(cat "$BASE/node-$i/node.pid")" 2>/dev/null; done
    sleep 2

    # Phase 2. One relay server per node, one relay client per ordered pair.
    # Each server's identity is created up front so every client starts PINNED
    # to the server it dials: an unpinned relay client verifies the server's
    # signature under a key the server itself sent, which authenticates nobody
    # (PQTG Verifpal finding F2, formal/VERIFICATION-RESULTS-2026-09-12.md).
    echo "== phase 2: starting $N relay servers and $((N * (N - 1))) relay clients, pinned both ways =="
    # Both directions are authenticated (relay-2): each client pins its
    # server's fingerprint, and each server allow-lists the fingerprints of the
    # clients that dial it (PQTG Verifpal finding R1: an un-allow-listed relay
    # server is an open door to its backend). So every identity is created up
    # front, clients first.
    declare -a CLIENT_PIN RELAY_PIN
    for i in $(seq 1 "$N"); do
        for j in $(seq 1 "$N"); do
            [ "$i" = "$j" ] && continue
            mkdir -p "$BASE/relay/client-$i-to-$j"
            CLIENT_PIN[$((10 * i + j))]=$( cd "$BASE/relay/client-$i-to-$j" && "$RELAY" fingerprint relay_wan_client.key | tail -1 )
        done
    done
    for j in $(seq 1 "$N"); do
        mkdir -p "$BASE/relay/server-$j"
        RELAY_PIN[$j]=$( cd "$BASE/relay/server-$j" && "$RELAY" fingerprint relay_wan_server.key | tail -1 )
        allow=()
        for i in $(seq 1 "$N"); do
            [ "$i" = "$j" ] && continue
            allow+=(--client "${CLIENT_PIN[$((10 * i + j))]}")
        done
        spawn_relay "server-$j" server "127.0.0.1:$(relay_server "$j")" "127.0.0.1:$(p2p_port "$j")" "${allow[@]}"
        echo "   relay server-$j  ${RELAY_PIN[$j]}  (allow-lists $((N - 1)) clients)"
    done
    sleep 2
    for i in $(seq 1 "$N"); do
        for j in $(seq 1 "$N"); do
            [ "$i" = "$j" ] && continue
            spawn_relay "client-$i-to-$j" client \
                "127.0.0.1:$(relay_client "$i" "$j")" "127.0.0.1:$(relay_server "$j")" \
                --pin "${RELAY_PIN[$j]}"
        done
    done
    sleep 3
    echo "   relay processes: $(pgrep -f "[r]elay_wan" | wc -l | tr -d " ")"

    echo "== phase 3: relaunching nodes, reserved-only, every peer behind a relay =="
    for i in $(seq 1 "$N"); do
        local reserved=()
        for j in $(seq 1 "$N"); do
            [ "$i" = "$j" ] && continue
            reserved+=(--reserved-nodes "/ip4/127.0.0.1/tcp/$(relay_client "$i" "$j")/p2p/${PEER[$j]}")
        done
        launch_node "$i" "${reserved[@]}" --reserved-only
        echo "   node-$i up, $((N - 1)) peers all behind relays"
    done

    echo "== waiting 45s for block production and finality =="
    sleep 45
    cmd_status
}

cmd_status() {
    printf '%-8s %-6s %-8s %-11s %-5s %s\n' node alive best finalized lag peers
    for i in $(seq 1 "$N"); do
        local alive="no" best="-" fin="-" lag="-" peers="-" h f fh
        kill -0 "$(cat "$BASE/node-$i/node.pid" 2>/dev/null)" 2>/dev/null && alive=yes
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
        printf '%-8s %-6s %-8s %-11s %-5s %s\n' "node-$i" "$alive" "$best" "$fin" "$lag" "$peers"
    done
}

# The claim this devnet exists to support: no validator reaches another
# validator except through a relay. Checked against live sockets, and strictly:
# a connection is acceptable only if the process at the OTHER end is a relay.
# An earlier, looser version of this check passed a stray node straight through,
# so it now resolves both ends of every connection before saying anything.
cmd_proof() {
    lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | tail -n +2 | python3 -c '
import re, sys

# name -> set of local "ip:port" endpoints that process owns
owners = {}
conns = []
for line in sys.stdin:
    f = line.split()
    if len(f) < 9:
        continue
    cmd, pid, name = f[0], f[1], f[-2] if f[-1].startswith("(") else f[-1]
    m = re.match(r"(\S+?)->(\S+)$", name)
    if not m:
        continue
    local, remote = m.group(1), m.group(2)
    owners.setdefault(local, []).append((cmd, pid))
    conns.append((cmd, pid, local, remote))

P2P = re.compile(r":(221\d\d)$")
bad, relayed = [], 0
for cmd, pid, local, remote in conns:
    lm, rm = P2P.search(local), P2P.search(remote)
    if not (lm or rm):
        continue                      # not a validator p2p socket
    if cmd.startswith("relay_wan"):
        relayed += 1
        continue                      # a relay talking to a p2p port is the point
    peer = remote if lm else local
    who = owners.get(peer, [])
    if any(c.startswith("relay_wan") for c, _ in who):
        relayed += 1
    elif not who:
        bad.append((cmd, pid, local, remote, "peer process not found"))
    else:
        bad.append((cmd, pid, local, remote, "peer is " + who[0][0] + " pid " + who[0][1]))

print("connections into validator p2p ports that cross a relay: %d" % relayed)
if bad:
    print("UNRELAYED CONNECTIONS: %d" % len(bad))
    for cmd, pid, local, remote, why in bad:
        print("   BAD  %s pid %s  %s -> %s  (%s)" % (cmd, pid, local, remote, why))
    print("RESULT: claim NOT supported")
    sys.exit(1)
print("RESULT: every validator to validator connection crosses a PQTG relay")
'
    local rc=$?
    echo "relay processes alive: $(pgrep -f "[r]elay_wan" | wc -l | tr -d ' ')"
    return $rc
}

# A long run, sampled once a minute into a CSV. What it is looking for:
#   ratchets   the silent rekey at 65,536 records per direction, the exact path
#              qssh failed at 508 times out of 508. Zero here after many hours
#              means the traffic estimate was wrong, which is worth knowing too.
#   fds/rss    a slow leak in the relays is invisible in an hour
#   reaped     whether the ten minute idle reaper ever kills a healthy link
#   finality   whether it keeps up, not just whether it started
cmd_soak() {
    local hours="${2:-24}"
    local out="$BASE/soak.csv"
    local endat=$(( $(date +%s) + hours * 3600 ))

    [ -f "$out" ] || echo "ts,elapsed_min,best,finalized,lag,peers_min,nodes_agree,supermajorities,ratchets,relay_procs,relay_rss_mb,relay_fds,node_rss_mb,relay_warns,reaped,disk_mb" > "$out"
    local started; started=$(date +%s)
    echo "soak started, sampling every 60s until $(date -r "$endat" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "+${hours}h")"
    echo "csv: $out"

    while [ "$(date +%s)" -lt "$endat" ]; do
        local best="" fin="" lag="" peers_min=999 agree=1 first_fin=""
        for i in $(seq 1 "$N"); do
            local h f fh p
            h=$(rpc "$i" chain_getHeader | jq -r '.result.number // empty' 2>/dev/null)
            [ -z "$h" ] && { agree=0; continue; }
            f=$(rpc "$i" chain_getFinalizedHead | jq -r '.result // empty')
            fh=$(rpc "$i" chain_getHeader "[\"$f\"]" | jq -r '.result.number // empty' 2>/dev/null)
            p=$(rpc "$i" system_health | jq -r '.result.peers // 0')
            [ "$p" -lt "$peers_min" ] 2>/dev/null && peers_min=$p
            best=$((h)); [ -n "$fh" ] && fin=$((fh))
            if [ -z "$first_fin" ]; then first_fin="$fh"; elif [ "$first_fin" != "$fh" ]; then agree=0; fi
        done
        [ -n "$best" ] && [ -n "$fin" ] && lag=$((best - fin))

        local pids rss fds procs nrss
        pids=$(pgrep -f "[r]elay_wan" | tr '\n' ',' | sed 's/,$//')
        procs=$(pgrep -f "[r]elay_wan" | wc -l | tr -d ' ')
        rss=$(ps -o rss= -p "$pids" 2>/dev/null | awk '{s+=$1} END {printf "%.1f", s/1024}')
        fds=$(lsof -p "$pids" 2>/dev/null | wc -l | tr -d ' ')
        nrss=$(ps -o rss= -p "$(pgrep -f "[q]h-relay-devnet-node" | tr '\n' ',' | sed 's/,$//')" 2>/dev/null | awk '{s+=$1} END {printf "%.1f", s/1024}')

        local ratchets warns reaped supers disk
        ratchets=$(grep -h "RATCHET" "$BASE"/relay/*/log 2>/dev/null | wc -l | tr -d ' ')
        warns=$(grep -hciE "warn|error" "$BASE"/relay/*/log 2>/dev/null | awk '{s+=$1} END {print s+0}')
        reaped=$(grep -h "idle for" "$BASE"/relay/*/log 2>/dev/null | wc -l | tr -d ' ')
        supers=$(grep -h "Supermajority achieved" "$BASE"/node-*/node.log 2>/dev/null | wc -l | tr -d ' ')
        disk=$(du -sm "$BASE" 2>/dev/null | cut -f1)

        printf '%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$(date '+%Y-%m-%dT%H:%M:%S')" "$((($(date +%s) - started) / 60))" \
            "${best:--}" "${fin:--}" "${lag:--}" "$peers_min" "$agree" \
            "$supers" "$ratchets" "$procs" "$rss" "$fds" "$nrss" "$warns" "$reaped" "${disk:--}" >> "$out"
        sleep 60
    done
    echo "soak finished at $(date '+%Y-%m-%d %H:%M')"
}

cmd_logs() { tail -n "${2:-20}" "$BASE"/node-*/node.log; }

cmd_down() {
    for i in $(seq 1 "$N"); do
        [ -f "$BASE/node-$i/node.pid" ] && kill "$(cat "$BASE/node-$i/node.pid")" 2>/dev/null
    done
    for f in "$BASE"/relay/*.pid; do
        [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null
    done
    pkill -f "[r]elay_wan (server|client) 127.0.0.1:4" 2>/dev/null
    sleep 1
    echo "stopped; data kept at $BASE"
}

cmd_clean() { cmd_down; rm -rf "$BASE"; echo "removed $BASE"; }

case "${1:-}" in
    up) cmd_up ;;
    soak) cmd_soak "$@" ;;
    status) cmd_status ;;
    proof) cmd_proof ;;
    logs) cmd_logs "$@" ;;
    down) cmd_down ;;
    clean) cmd_clean ;;
    *) echo "usage: $0 up|soak [hours]|status|proof|logs|down|clean"; exit 1 ;;
esac
