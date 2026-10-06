#!/bin/bash
# partition-test.sh — the test d4c6da7 says must pass before any validator window.
#
#   "partition one authoring validator 10 minutes, heal, assert it does not
#    locally finalize on the losing branch and rejoins without a reseed"
#
# The bug: the gadget votes on every election block it imports, so an honest
# node holding both siblings of a fork voted for BOTH and receivers counted
# both. A minority branch could therefore assemble an apparent supermajority.
# That is the mechanism behind all three Charlie forks.
#
# A partition manufactures exactly that state. The isolated validator keeps
# authoring its own branch; on heal it imports the majority branch and now holds
# both at the same heights. Pre-fix it votes twice. Post-fix the equivocation
# ledger admits one vote per authority per height.
#
# Run the SAME scenario against both binaries. A result only means something if
# it fails pre-fix and passes post-fix.
#
#   ./partition-test.sh run <path-to-binary> <label> [partition_minutes]
#   ./partition-test.sh down | clean
#
# Isolated from everything else: own base path, own ports, own chainspec.
# Ports: rpc 20200+i, p2p 22200+i, prometheus 24200+i, forwarder 45000+10i+j

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GEN="${GEN:-$REPO/.partition-test-bins/generate-devnet-chain-spec}"
FWD="$REPO/scripts/tcp_forward.py"
BASE="${BASE:-/tmp/qh-partition-test}"
CHAIN_ID="qh_devnet"
CHAINSPEC="$BASE/devnet-chainspec-raw.json"
N="${N:-4}"
# Which nodes end up on the far side of the cut. A 2-2 split is the one that
# discriminates. At N=4 quorum is 3, so a lone partitioned validator's branch
# gets exactly one vote and can never reach quorum, whatever the gadget does.
# Split 2-2 and neither side reaches 3 while apart; on heal, a node that votes
# for both branches gives each of them a third vote, and both "finalize". That
# is the Charlie mechanism. GROUP_B is settable: "4" reproduces the weaker test
# the commit message names, "3 4" reproduces the fork.
GROUP_B="${GROUP_B:-}"
# EQUIVOCATOR: node id to arm with the devnet-only equivocation witness, or ""
# for a plain partition. The witness emits a SECOND genuinely signed vote from a
# real authority for a REAL competing block at the same height, which is the
# precise condition finality_unique's honest_single hypothesis forbids. A plain
# 2-2 partition does NOT reproduce the bug: fork choice discards the losing
# branch wholesale and no node ever finalizes on it (measured, 2026-09-09).
# At N=4 quorum is 3, so one equivocator is f=1 and MUST be survivable.
EQUIVOCATOR="${EQUIVOCATOR:-}"

# Default split: half the set, rounded down, on the far side. At N=4 that is
# {3,4} against {1,2}; at N=3 it is {3} alone against {1,2}. N=3 is the case
# that matters, because quorum there is 2: an honest node that imported both
# siblings votes for both, and its second vote is the only thing a losing branch
# needs to reach quorum. No Byzantine node required. That is the "structural
# equivocation" behind all three Charlie forks.
if [ -z "$GROUP_B" ]; then
    GROUP_B=""
    for k in $(seq $(( N / 2 + 1 )) "$N"); do GROUP_B="$GROUP_B $k"; done
    GROUP_B="${GROUP_B# }"
fi
QUORUM=$(( (2 * N + 2) / 3 ))

rpc_port() { echo $((20200 + $1)); }
p2p_port() { echo $((22200 + $1)); }
prom_port(){ echo $((24200 + $1)); }
fwd_port() { echo $((45000 + 10 * $1 + $2)); }

rpc() {
    curl -s -m 6 -H 'Content-Type: application/json' \
        -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"$2\",\"params\":${3:-[]}}" \
        "http://127.0.0.1:$(rpc_port "$1")"
}
best()      { rpc "$1" chain_getHeader | jq -r '.result.number // empty'; }
finalized() { rpc "$1" chain_getFinalizedHead | jq -r '.result // empty'; }
hash_at()   { rpc "$1" chain_getBlockHash "[$2]" | jq -r '.result // empty'; }
peers()     { rpc "$1" system_health | jq -r '.result.peers // "-"'; }
fin_num()   { local h; h=$(finalized "$1"); [ -n "$h" ] && rpc "$1" chain_getHeader "[\"$h\"]" | jq -r '.result.number // empty'; }

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$BASE/test.log"; }

in_group_b() { for m in $GROUP_B; do [ "$m" = "$1" ] && return 0; done; return 1; }
# A link crosses the cut when exactly one of its ends is in group B.
crosses_cut() {
    if in_group_b "$1"; then in_group_b "$2" && return 1 || return 0
    else in_group_b "$2" && return 0 || return 1; fi
}

# Partitioning through forwarders does not work: libp2p identify tells peers the
# real listen address, so once connected they bypass any proxy and killing it
# changes nothing. Observed directly, peers stayed at 3 through a ten minute
# "cut". --reserved-only restricts which peers, not which addresses.
#
# Substrate's own reserved-peer RPCs do the job with no proxy, no firewall and
# no administration prompt: drop the peer from the reserved set and, under
# --reserved-only, the connection goes and is not redialled.
cut_network() {
    for i in $(seq 1 $N); do for j in $(seq 1 $N); do
        [ "$i" = "$j" ] && continue
        crosses_cut "$i" "$j" || continue
        rpc "$i" system_removeReservedPeer "[\"${PEER[$j]}\"]" > /dev/null
    done; done
}

heal_network() {
    for i in $(seq 1 $N); do for j in $(seq 1 $N); do
        [ "$i" = "$j" ] && continue
        crosses_cut "$i" "$j" || continue
        rpc "$i" system_addReservedPeer "[\"/ip4/127.0.0.1/tcp/$(p2p_port "$j")/p2p/${PEER[$j]}\"]" > /dev/null
    done; done
}

launch_node() {
    local i=$1 bin=$2; shift 2
    local dir="$BASE/node-$i" ks="$BASE/node-$i/chains/$CHAIN_ID/keystore"
    mkdir -p "$ks"
    local pub sec
    pub=$(jq -r .public_key "$BASE/validator-$i/key.json")
    sec=$(jq -r .secret_key "$BASE/validator-$i/key.json")
    printf '"%s"' "$sec" > "$ks/61757261${pub#0x}"
    local arm=""
    [ -n "$EQUIVOCATOR" ] && [ "$i" = "$EQUIVOCATOR" ] && arm="1"
    # env, not a bare assignment: a VAR=value produced by expansion is parsed as
    # a command name, not an assignment, so ${arm:+...} inline would run it.
    env DISABLE_PQC_TRANSPORT=1 DISABLE_QUANTUM_P2P=1 ${arm:+QH_ATTACK_EQUIVOCATE=1} \
    "$bin" --chain "$CHAINSPEC" --validator --name "qh-partition-node-$i" \
        --base-path "$dir" --node-key "$(printf '%064x' "$i")" \
        --port "$(p2p_port "$i")" --out-peers 128 --in-peers 256 \
        --pool-type single-state --rpc-port "$(rpc_port "$i")" \
        --rpc-cors=all --rpc-methods=Unsafe --prometheus-port "$(prom_port "$i")" \
        --no-telemetry --force-authoring "$@" >> "$dir/node.log" 2>&1 &
    echo "$!" > "$dir/node.pid"
}

wait_rpc() { for _ in $(seq 1 40); do [ -n "$(rpc "$1" system_localPeerId | jq -r '.result // empty')" ] && return 0; sleep 1; done; return 1; }

# Every node must agree on the hash at every sampled height, and on the
# finalized head. Disagreement anywhere is a fork.
check_agreement() {
    local label="$1" bad=0 lowest=999999999
    for i in $(seq 1 $N); do
        local f; f=$(fin_num "$i"); f=${f:-0}; f=$((f))
        [ "$f" -lt "$lowest" ] && lowest=$f
    done
    log "  lowest finalized across nodes: $lowest"
    local ref
    for h in $(seq 1 $((lowest / 10 + 1)) | head -1) $((lowest / 4)) $((lowest / 2)) $((lowest * 3 / 4)) "$lowest"; do
        [ "$h" -lt 1 ] && continue
        ref=$(hash_at 1 "$h")
        for i in $(seq 2 $N); do
            local o; o=$(hash_at "$i" "$h")
            if [ -n "$ref" ] && [ -n "$o" ] && [ "$ref" != "$o" ]; then
                log "  ✗ FORK at height $h: node-1 $ref  node-$i $o"
                bad=$((bad + 1))
            fi
        done
    done
    local fref; fref=$(finalized 1)
    for i in $(seq 2 $N); do
        local o; o=$(finalized "$i")
        [ "$fref" != "$o" ] && log "  · finalized heads differ (node-1 ${fref:0:14} vs node-$i ${o:0:14}) — may be lag"
    done
    [ "$bad" -eq 0 ] && log "  ✓ $label: all nodes agree on every sampled height" || log "  ✗ $label: $bad disagreements"
    return "$bad"
}

status_line() {
    local out=""
    for i in $(seq 1 $N); do
        out="$out node-$i best=$(best "$i" | xargs printf '%d' 2>/dev/null || echo -) fin=$(fin_num "$i" || echo -) peers=$(peers "$i");"
    done
    log "  $out"
}

declare -a PEER

cmd_run() {
    local bin="${2:?usage: partition-test.sh run <binary> <label> [minutes]}"
    local label="${3:?need a label}"
    local mins="${4:-10}"
    [ -x "$bin" ] || { echo "no binary at $bin"; exit 1; }

    pkill -f "[q]h-partition-node" 2>/dev/null; sleep 1
    rm -rf "$BASE"; mkdir -p "$BASE"
    : > "$BASE/test.log"

    log "=== partition test: $label ==="
    log "N=$N, quorum=$QUORUM, split: [$(seq 1 $N | grep -vE "^($(echo $GROUP_B | tr ' ' '|'))$" | tr '\n' ' ')] against [$GROUP_B]"
    log "binary: $bin"
    log "equivocation ledger present in binary: $(strings "$bin" 2>/dev/null | grep -c 'equivocation ledger')"
    log "byzantine witness present in binary : $(strings "$bin" 2>/dev/null | grep -c 'QH_ATTACK_EQUIVOCATE')"
    [ -n "$EQUIVOCATOR" ] && log "node-$EQUIVOCATOR armed with QH_ATTACK_EQUIVOCATE (f=1 of N=4, must be survivable)"

    "$GEN" "$N" "$BASE" > /dev/null 2>&1
    log "generated $N validator keys and a chainspec"

    for i in $(seq 1 $N); do launch_node "$i" "$bin"; done
    for i in $(seq 1 $N); do
        wait_rpc "$i" || { log "node-$i RPC never came up"; exit 1; }
        PEER[$i]=$(rpc "$i" system_localPeerId | jq -r .result)
    done
    for i in $(seq 1 $N); do kill "$(cat "$BASE/node-$i/node.pid")" 2>/dev/null; done
    sleep 2

    for i in $(seq 1 $N); do
        local res=()
        for j in $(seq 1 $N); do
            [ "$i" = "$j" ] && continue
            res+=(--reserved-nodes "/ip4/127.0.0.1/tcp/$(p2p_port "$j")/p2p/${PEER[$j]}")
        done
        launch_node "$i" "$bin" "${res[@]}" --reserved-only
    done
    for i in $(seq 1 $N); do wait_rpc "$i" >/dev/null; done
    log "all $N validators up, fully meshed"

    log "settling for 90s so finality starts"
    sleep 90
    status_line
    check_agreement "baseline"
    local base_ok=$?

    if [ -n "${FLAP:-}" ]; then
        # A long partition cannot reproduce the bug: the smaller side authors on
        # fewer Aura slots, so its branch grows slower, loses fork choice
        # decisively and is discarded without ever being imported as a competing
        # candidate. Measured at N=4 and N=3 (2026-09-09), both passed pre-fix.
        #
        # The commit says NATURAL FORK, not partition: two blocks at the SAME
        # height, both propagated, both imported by everyone, briefly. Then every
        # honest node votes for both siblings, and at quorum 2 of 3 each sibling
        # reaches quorum. That is the fork, with no Byzantine node anywhere.
        #
        # So: flap. Cut for slightly more than one block time, heal, repeat. Each
        # cycle can mint one sibling pair; election heights are every 5 blocks, so
        # enough cycles will land on one.
        local cycles="${FLAP_CYCLES:-15}" cut_s="${FLAP_CUT:-6}" heal_s="${FLAP_HEAL:-14}"
        log "--- FLAP: $cycles cycles of ${cut_s}s cut / ${heal_s}s heal, to mint same-height siblings ---"
        for c in $(seq 1 "$cycles"); do
            cut_network; sleep "$cut_s"
            heal_network; sleep "$heal_s"
            [ $((c % 5)) -eq 0 ] && status_line
        done
        log "--- flapping done, settling 4 minutes ---"
        for _ in $(seq 1 4); do sleep 60; status_line; done
        log "--- verdict ---"
        check_agreement "after flapping"
        local flap_ok=$?
        local all_alive="yes"
        for m in $(seq 1 $N); do kill -0 "$(cat "$BASE/node-$m/node.pid" 2>/dev/null)" 2>/dev/null || all_alive="no"; done
        log "  all nodes alive without a reseed: $all_alive"
        log "  equivocations REJECTED by receivers: $(grep -ch 'EQUIVOCATION \[' "$BASE"/node-*/node.log 2>/dev/null | awk '{s+=$1} END {print s+0}')"
        log "  distinct heights with a sibling seen: $(grep -ho 'already voted .* at height #[0-9]*' "$BASE"/node-*/node.log 2>/dev/null | grep -o '#[0-9]*' | sort -u | wc -l | tr -d ' ')"
        if [ "$flap_ok" -eq 0 ] && [ "$all_alive" = "yes" ]; then
            log "RESULT: PASS — no fork under repeated same-height siblings"
        else
            log "RESULT: FAIL — conflicting finalization, see disagreements above"
        fi
        cp "$BASE/test.log" "/tmp/qh-partition-$label.log" 2>/dev/null
        return
    fi

    log "--- cutting the network: {$(echo $(seq 1 $N) | tr \" \" \",\")} minus [$GROUP_B] | [$GROUP_B], for $mins minutes ---"
    cut_network
    sleep 20
    status_line
    local isolated_peers=0
    for m in $GROUP_B; do isolated_peers=$((isolated_peers + $(peers "$m"))); done
    local expect=$(( $(echo $GROUP_B | wc -w) * ($(echo $GROUP_B | wc -w) - 1) ))
    if [ "$isolated_peers" -gt "$expect" ]; then
        log "  ✗ CUT DID NOT TAKE: isolated side still has $isolated_peers peer connections, expected $expect"
        log "RESULT: INVALID — the partition never happened, this run proves nothing"
        cmd_down; exit 2
    fi
    log "  ✓ cut verified: isolated side has $isolated_peers peer connections (expected $expect)"
    local t_end=$(( $(date +%s) + mins * 60 ))
    while [ "$(date +%s)" -lt "$t_end" ]; do sleep 60; status_line; done

    log "--- healing ---"
    heal_network
    log "reserved peers restored, settling 5 minutes"
    for _ in $(seq 1 5); do sleep 60; status_line; done

    log "--- verdict ---"
    check_agreement "after heal"
    local heal_ok=$?

    local victim_alive="yes"
    for m in $GROUP_B; do
        kill -0 "$(cat "$BASE/node-$m/node.pid" 2>/dev/null)" 2>/dev/null || victim_alive="no"
        log "  node-$m alive without a reseed: $(kill -0 "$(cat "$BASE/node-$m/node.pid" 2>/dev/null)" 2>/dev/null && echo yes || echo no), peers $(peers "$m")"
    done
    log "  equivocating votes actually emitted: $(grep -ch 'EQUIVOCATION WITNESS' "$BASE"/node-*/node.log 2>/dev/null | awk '{s+=$1} END {print s+0}')"
    # count ONLY the receiver-side rejection, never the attacker's own witness
    # lines: both contain the string EQUIVOCATION, and grepping the bare tag
    # double counts the same events and reports a fix that is not there.
    log "  equivocations REJECTED by receivers: $(grep -ch 'EQUIVOCATION \[' "$BASE"/node-*/node.log 2>/dev/null | awk '{s+=$1} END {print s+0}')"
    if [ -n "$EQUIVOCATOR" ] && [ "$(grep -ch 'EQUIVOCATION WITNESS' "$BASE"/node-*/node.log 2>/dev/null | awk '{s+=$1} END {print s+0}')" = "0" ]; then
        log "  ✗ the witness never fired — no competing block was ever available, so this run tests nothing"
    fi

    if [ "$base_ok" -eq 0 ] && [ "$heal_ok" -eq 0 ] && [ "$victim_alive" = "yes" ]; then
        log "RESULT: PASS — no fork, the isolated side rejoined without a reseed"
    else
        log "RESULT: FAIL — see disagreements above"
    fi
    cp "$BASE/test.log" "$BASE/../qh-partition-$label.log" 2>/dev/null
    log "log copied to /tmp/qh-partition-$label.log"
}

cmd_down() {
    for i in $(seq 1 $N); do [ -f "$BASE/node-$i/node.pid" ] && kill "$(cat "$BASE/node-$i/node.pid")" 2>/dev/null; done
    sleep 1; echo "stopped; data kept at $BASE"
}

case "${1:-}" in
    run) cmd_run "$@" ;;
    down) cmd_down ;;
    clean) cmd_down; rm -rf "$BASE"; echo "removed $BASE" ;;
    *) echo "usage: $0 run <binary> <label> [partition_minutes] | down | clean"; exit 1 ;;
esac
