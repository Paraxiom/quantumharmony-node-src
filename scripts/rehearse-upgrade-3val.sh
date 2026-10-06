#!/usr/bin/env bash
# Rehearse a runtime upgrade on a THREE validator devnet.
#
# WHY THIS EXISTS, SEPARATELY FROM rehearse-runtime-upgrade.sh
# ------------------------------------------------------------
# The single node rehearsal proves the mechanism: the blob applies and the spec
# version moves. It cannot prove the things that have actually gone wrong on this
# chain, because all of them need more than one validator:
#
#   - authority set continuity across the spec boundary
#   - vote admission and counting while validators are briefly on different runtimes
#   - quorum during the transition
#   - divergence, which is what Charlie has done four times
#
# So this starts three validators that peer with each other, upgrades ONE of them
# by RPC, and then asserts that ALL THREE converge on the new spec version, on the
# SAME finalized chain, with finality still advancing. A fork is the failure this
# is looking for.
#
# SAFETY
# ------
# Entirely local. Its own chainspec and keys, /tmp/qh-test-3val, RPC 9961-9963,
# p2p 30361-30363, names prefixed qh-test- per CLAUDE.md. It never contacts Alice,
# Bob, Charlie or any Docker volume. Build with rust 1.85.
#
# USAGE
#   scripts/rehearse-upgrade-3val.sh <target-runtime.wasm>
#
set -euo pipefail

TARGET_WASM="${1:?usage: $0 <target-runtime.wasm>}"
[ -f "$TARGET_WASM" ] || { echo "no such wasm: $TARGET_WASM" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE="$REPO/target/release/quantumharmony-node"
GENSPEC="$REPO/target/release/generate-devnet-chain-spec"
WORK=/tmp/qh-test-3val
CHAIN_ID=qh_devnet
N=3

for b in "$NODE" "$GENSPEC"; do
    [ -x "$b" ] || { echo "missing $b — build with rust 1.85 first" >&2; exit 1; }
done

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo; echo "3-VALIDATOR REHEARSAL FAILED: $*" >&2; echo "logs in $WORK" >&2; exit 1; }

rpc() { # rpc <port> <method> [params]
    printf '{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}' "$2" "${3:-[]}" > "$WORK/body-$1.json"
    curl -s -m 30 -H 'Content-Type: application/json' -d "@$WORK/body-$1.json" "http://127.0.0.1:$1"
}
jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
spec()   { rpc "$1" state_getRuntimeVersion | jget "d['result']['specVersion']"; }
best()   { rpc "$1" chain_getHeader         | jget "int(d['result']['number'],16)"; }
final()  { rpc "$1" chain_getFinalizedHead  | jget "d['result']"; }
peers()  { rpc "$1" system_health           | jget "d['result']['peers']"; }

echo "=== 1. chainspec and $N validator keys ==="
rm -rf "$WORK"; mkdir -p "$WORK"
"$GENSPEC" "$N" "$WORK/spec" >/dev/null
SPEC="$WORK/spec/devnet-chainspec-raw.json"

echo "=== 2. keystores, node keys, bootnode addresses ==="
declare -a PORT P2P PEERID
for i in $(seq 1 $N); do
    PORT[$i]=$((9960 + i)); P2P[$i]=$((30360 + i))
    base="$WORK/n$i"
    mkdir -p "$base/chains/$CHAIN_ID/keystore" "$base/chains/$CHAIN_ID/network"
    sec=$(python3 -c "import json;print(json.load(open('$WORK/spec/validator-$i/key.json'))['secret_key'])")
    pub=$(python3 -c "import json;print(json.load(open('$WORK/spec/validator-$i/key.json'))['public_key'])")
    # Keep the 0x prefix: without it the key loads but cannot sign, and the
    # coherence guard then refuses to start with a message in which the keystore
    # key and the authority look identical because both are truncated to 8 bytes.
    printf '"%s"' "$sec" > "$base/chains/$CHAIN_ID/keystore/61757261${pub#0x}"
    # generate-node-key prints the peer id on STDERR, not stdout. Sending stderr
    # to /dev/null yields an empty id and the bootnode multiaddr then fails to
    # parse with "unexpected end of file".
    PEERID[$i]=$("$NODE" key generate-node-key --file "$base/chains/$CHAIN_ID/network/secret_ed25519" 2>&1 | tail -1)
    [ -n "${PEERID[$i]}" ] || fail "could not read peer id for validator $i"
done

echo "=== 3. start $N validators, each bootnoded to the others ==="
for i in $(seq 1 $N); do
    boot=()
    for j in $(seq 1 $N); do
        [ "$j" = "$i" ] && continue
        boot+=("--bootnodes=/ip4/127.0.0.1/tcp/${P2P[$j]}/p2p/${PEERID[$j]}")
    done
    "$NODE" --chain "$SPEC" --base-path "$WORK/n$i" --validator --name "qh-test-3val-$i" \
        --rpc-port "${PORT[$i]}" --port "${P2P[$i]}" --prometheus-port $((9660 + i)) \
        --rpc-methods=unsafe --force-authoring --no-mdns \
        "${boot[@]}" > "$WORK/n$i.log" 2>&1 &
    PIDS+=($!)
done

for i in $(seq 1 60); do
    up=0
    for j in $(seq 1 $N); do [ -n "$(spec "${PORT[$j]}")" ] && up=$((up+1)); done
    [ "$up" = "$N" ] && break
    perl -e 'select(undef,undef,undef,1)'
done
[ "$up" = "$N" ] || fail "only $up of $N validators answered RPC"

SPEC_BEFORE=$(spec "${PORT[1]}")
echo "    all $N up, spec_version $SPEC_BEFORE"

echo "=== 4. they must actually be peered and finalizing before we touch anything ==="
for i in $(seq 1 40); do
    ok=1
    for j in $(seq 1 $N); do
        p=$(peers "${PORT[$j]}"); [ "${p:-0}" -ge $((N-1)) ] || ok=0
    done
    [ "$ok" = 1 ] && break
    perl -e 'select(undef,undef,undef,2)'
done
for j in $(seq 1 $N); do printf '    n%s peers=%s best=#%s\n' "$j" "$(peers "${PORT[$j]}")" "$(best "${PORT[$j]}")"; done
[ "$ok" = 1 ] || fail "validators never reached $((N-1)) peers each"

# On a fresh 3-validator chain the first finalization lands around 24s after
# start: the gadget has to see a supermajority before it can certify anything.
# A 15s window failed here twice and looked like a finality stall when it was
# only impatience, so poll instead of sampling once.
F_A=$(final "${PORT[1]}")
adv=0
for i in $(seq 1 45); do
    perl -e 'select(undef,undef,undef,3)'
    F_B=$(final "${PORT[1]}")
    if [ -n "$F_B" ] && [ "$F_B" != "$F_A" ]; then adv=1; break; fi
done
[ "$adv" = 1 ] || fail "finality did not advance within 135s before the upgrade; nothing to rehearse"
echo "    finality advancing (first advance after about $((i * 3))s)"

echo "=== 5. upgrade via ONE validator only ==="
TARGET_SPEC=$(subwasm info "$TARGET_WASM" 2>/dev/null | grep -oE 'quantumharmony-[0-9]+' | head -1 | cut -d- -f2)
echo "    target blob declares spec ${TARGET_SPEC:-unknown}, $(wc -c <"$TARGET_WASM") bytes"
[ "$TARGET_SPEC" = "$SPEC_BEFORE" ] && fail "target is also spec $SPEC_BEFORE; a spec number must never carry two runtimes"

SEC1=$(python3 -c "import json;print(json.load(open('$WORK/spec/validator-1/key.json'))['secret_key'])")
python3 - "$TARGET_WASM" "$SEC1" "$WORK/upgrade.json" <<'PY'
import json,sys
wasm=open(sys.argv[1],'rb').read()
json.dump({"jsonrpc":"2.0","method":"quantumharmony_submitRuntimeUpgrade",
           "params":["0x"+wasm.hex(),sys.argv[2]],"id":1}, open(sys.argv[3],'w'))
PY
OUT=$(curl -s -m 300 -H 'Content-Type: application/json' -d "@$WORK/upgrade.json" "http://127.0.0.1:${PORT[1]}")
echo "    submitted via n1: $(echo "$OUT" | head -c 140)"
echo "$OUT" | grep -q '"error"' && fail "submission rejected"

echo "=== 6. ALL $N must converge on the new spec ==="
for i in $(seq 1 60); do
    done_n=0
    for j in $(seq 1 $N); do [ "$(spec "${PORT[$j]}")" = "$TARGET_SPEC" ] && done_n=$((done_n+1)); done
    [ "$done_n" = "$N" ] && break
    perl -e 'select(undef,undef,undef,3)'
done
for j in $(seq 1 $N); do printf '    n%s spec=%s\n' "$j" "$(spec "${PORT[$j]}")"; done
[ "$done_n" = "$N" ] || fail "only $done_n of $N reached spec $TARGET_SPEC — the others are on a different runtime"

echo "=== 7. no fork: same finalized chain, still advancing ==="
perl -e 'select(undef,undef,undef,18)'
declare -a FH
for j in $(seq 1 $N); do FH[$j]=$(final "${PORT[$j]}"); printf '    n%s finalized %s best=#%s\n' "$j" "${FH[$j]:0:18}…" "$(best "${PORT[$j]}")"; done

# Compare finalized heads pairwise. Different heights are fine; different hashes
# at a shared height are not, so compare each node's head against n1's chain.
for j in $(seq 2 $N); do
    hj=${FH[$j]}
    nj=$(rpc "${PORT[$j]}" chain_getHeader "[\"$hj\"]" | jget "int(d['result']['number'],16)")
    h1_at=$(rpc "${PORT[1]}" chain_getBlockHash "[$nj]" | jget "d['result']")
    [ "$hj" = "$h1_at" ] || fail "FORK: n$j finalized $hj at #$nj, n1 has $h1_at there"
done
echo "    all $N agree on the finalized chain"

# Poll with the same patience as the pre-upgrade check, and REPORT the time.
# Finality here advances roughly every 20-35s, so a fixed 18s window reported a
# stall twice when there was none. The number printed is the interesting output:
# if a runtime upgrade pauses finality, this is where it shows up.
B_A=$(best "${PORT[1]}"); F_C=$(final "${PORT[1]}")
fadv=0
for i in $(seq 1 45); do
    perl -e 'select(undef,undef,undef,3)'
    F_D=$(final "${PORT[1]}")
    if [ -n "$F_D" ] && [ "$F_D" != "$F_C" ]; then fadv=1; break; fi
done
B_B=$(best "${PORT[1]}")
[ "$B_B" -gt "$B_A" ] || fail "block production stopped after the upgrade"
[ "$fadv" = 1 ] || fail "finality did not advance within 135s after the upgrade"
echo "    finality advanced $((i * 3))s after the upgrade"

echo
echo "3-VALIDATOR REHEARSAL PASSED"
echo "  spec_version   $SPEC_BEFORE -> $TARGET_SPEC on all $N validators"
echo "  finalized      all $N on the same chain, no fork"
echo "  liveness       blocks $B_A -> $B_B, finality advancing"
echo "  logs           $WORK"
