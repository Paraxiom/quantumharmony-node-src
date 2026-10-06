#!/bin/bash
# failopen-isolation.sh — does the PQTG relay mesh fail OPEN or fail CLOSED?
#
# devnet-relay.sh stands up a 4-validator devnet where every peer edge crosses a
# PQTG relay and nodes run --reserved-only with the reserved address pointing at
# a local relay client. The open question (PQTG-FAIL-OPEN-FIX-2026-09-11.md) is
# whether, when a relay dies, the validator re-forms its peer link DIRECTLY
# (plaintext, fail-open) or the link stays dropped (fail-closed).
#
# This harness answers it empirically instead of assuming:
#   1. bring the mesh up (delegated to devnet-relay.sh, the proven path)
#   2. prove the baseline: every validator<->validator connection crosses a relay
#   3. snapshot peer counts
#   4. kill EVERY relay in and out of node-N (server-N + client-*-to-N + client-N-to-*),
#      leaving all node processes running
#   5. wait, then re-snapshot peers and re-run proof
#      - a BAD (unrelayed) connection into node-N's p2p port => FAIL-OPEN
#      - node-N peers -> 0 with no direct connection => FAIL-CLOSED
#
# Loopback only. Ports (2010x/2210x/41xxx/43xxx) are disjoint from the
# production RPC canary (:9970/:9971); this harness never touches those.
#
# Usage: failopen-isolation.sh run | down | clean

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEVNET="$HERE/devnet-relay.sh"
BASE="${BASE:-/tmp/qh-devnet-relay}"
N="${N:-4}"
TARGET="${TARGET:-$N}"            # which node to isolate by killing its relays
WAIT_AFTER="${WAIT_AFTER:-40}"    # seconds to watch for a direct re-form
OUT="${OUT:-$HERE/../docs/ops/failopen-isolation-evidence.txt}"

rpc_port() { echo $((20100 + $1)); }
rpc() {
    curl -s -m 5 -H 'Content-Type: application/json' \
        -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"$2\",\"params\":${3:-[]}}" \
        "http://127.0.0.1:$(rpc_port "$1")"
}
peers() { rpc "$1" system_health | jq -r '.result.peers // "-"' 2>/dev/null; }
best()  { rpc "$1" chain_getHeader | jq -r '.result.number // "-"' 2>/dev/null; }

log() { echo "$@" | tee -a "$OUT"; }

kill_relays_for() {
    local n=$1 f
    for f in "$BASE/relay/server-$n.pid" "$BASE"/relay/client-"$n"-to-*.pid "$BASE"/relay/client-*-to-"$n".pid; do
        [ -e "$f" ] || continue
        kill "$(cat "$f")" 2>/dev/null && log "   killed $(basename "$f" .pid)"
        rm -f "$f"
    done
}

snapshot_peers() {
    local i
    for i in $(seq 1 "$N"); do
        log "   node-$i  best=$(best "$i")  peers=$(peers "$i")"
    done
}

cmd_run() {
    : > "$OUT"
    log "== PQTG fail-open isolation test =="
    log "host: $(hostname)  target-to-isolate: node-$TARGET  N=$N"
    log ""

    log "-- guard: the only relay_wan that should survive is the production canary --"
    pgrep -fl "[r]elay_wan" | tee -a "$OUT" || true
    log ""

    log "-- bringing up mesh (devnet-relay.sh clean && up) --"
    "$DEVNET" clean >/dev/null 2>&1
    "$DEVNET" up 2>&1 | tee -a "$OUT"
    log ""

    log "-- BASELINE proof: expect every validator<->validator conn crosses a relay --"
    "$DEVNET" proof 2>&1 | tee -a "$OUT"; local pre_rc=${PIPESTATUS[0]}
    log "   baseline proof rc=$pre_rc (0 = all relayed)"
    log ""

    log "-- peers BEFORE relay kill --"
    snapshot_peers
    log ""

    log "-- killing EVERY relay in/out of node-$TARGET, nodes stay running --"
    kill_relays_for "$TARGET"
    log "   relay procs alive now: $(pgrep -f "[r]elay_wan" | wc -l | tr -d ' ')"
    log "-- waiting ${WAIT_AFTER}s to see whether node-$TARGET re-forms peers --"
    sleep "$WAIT_AFTER"
    log ""

    log "-- peers AFTER relay kill --"
    snapshot_peers
    log ""

    log "-- proof AFTER kill: BAD/unrelayed conn = FAIL-OPEN; clean = fail-closed --"
    "$DEVNET" proof 2>&1 | tee -a "$OUT"; local post_rc=${PIPESTATUS[0]}
    log "   post-kill proof rc=$post_rc (nonzero = a direct connection exists)"
    log ""

    local tp
    tp=$(peers "$TARGET")
    log "== VERDICT =="
    if [ "$post_rc" -ne 0 ]; then
        log "FAIL-OPEN CONFIRMED: a direct (unrelayed) validator connection formed after the relay died."
    elif [ "$tp" = "0" ]; then
        log "FAIL-CLOSED: node-$TARGET dropped to 0 peers and formed no direct connection."
        log "  => the --reserved-only + relay config does NOT silently re-form direct on this host."
        log "  The production fail-open risk is then specific to the prod topology"
        log "  (0.0.0.0 publish + public-IP bootnodes), not this devnet config."
    else
        log "INCONCLUSIVE: node-$TARGET still shows peers=$tp with no unrelayed conn detected."
        log "  Check the relays really died and whether proof missed the socket. Re-run."
    fi
    log ""
    log "evidence: $OUT"
    log "teardown: $0 down   (leaves data)    $0 clean   (removes $BASE)"
}

case "${1:-}" in
    run)   cmd_run ;;
    down)  "$DEVNET" down ;;
    clean) "$DEVNET" clean ;;
    *) echo "usage: $0 run|down|clean"; exit 1 ;;
esac
