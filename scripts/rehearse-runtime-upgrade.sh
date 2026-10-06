#!/usr/bin/env bash
# Rehearse a real forkless runtime upgrade against a throwaway local devnet.
#
# WHY THIS EXISTS
# ---------------
# node/tests/runtime_upgrade_tests.rs is named as though it covers this. It does
# not. Read on 2026-09-26: its 21 tests do read-only queries, arithmetic on a
# byte count (chunkedUpgrade_calculateChunks), and the rejection paths (invalid
# hex, wrong key size, finalize/cancel with nothing pending). Not one submits a
# setCode or observes a spec version change. test_chunked_upgrade_full_flow says
# so itself: "you'd need to provide a real WASM for full test".
#
# So this script is the actual rehearsal. It asserts the thing that matters:
# spec_version goes N -> N+1 on a live chain, and the chain keeps producing and
# finalizing blocks afterwards.
#
# SAFETY
# ------
# Touches nothing shared. Its own chainspec, its own base path under
# /tmp/qh-test-*, its own ports, and a name prefixed qh-test- per CLAUDE.md.
# It never talks to Alice, Bob, Charlie or any Docker volume. Build the node and
# the target blob with rust 1.85; 1.96 cannot link the runtime wasm.
#
# USAGE
#   scripts/rehearse-runtime-upgrade.sh <target-runtime.wasm>
#
set -euo pipefail

TARGET_WASM="${1:?usage: $0 <target-runtime.wasm>}"
[ -f "$TARGET_WASM" ] || { echo "no such wasm: $TARGET_WASM" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE="$REPO/target/release/quantumharmony-node"
GENSPEC="$REPO/target/release/generate-devnet-chain-spec"
WORK=/tmp/qh-test-upgrade-rehearsal
SPEC_DIR="$WORK/spec"
BASE="$WORK/base"
RPC=9955
P2P=30355
PROM=9655
URL="http://127.0.0.1:$RPC"
CHAIN_ID=qh_devnet

for b in "$NODE" "$GENSPEC"; do
    [ -x "$b" ] || { echo "missing $b — build with rust 1.85 first" >&2; exit 1; }
done

# The runtime blob is ~1 MB, so its hex form is ~2 MB. Passing that to curl as
# an argument blows ARG_MAX ("Argument list too long"), so every request body
# goes through a file and curl reads it with -d @file.
RPC_BODY="$WORK/rpc-body.json"
rpc() {
    local method="$1"; shift
    local params="${1:-[]}"
    printf '{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}' "$method" "$params" > "$RPC_BODY"
    curl -s -m 180 -H 'Content-Type: application/json' -d "@$RPC_BODY" "$URL"
}

jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

spec_version() { rpc state_getRuntimeVersion | jget "d['result']['specVersion']"; }
best_block()   { rpc chain_getHeader        | jget "int(d['result']['number'],16)"; }
finalized()    { rpc chain_getFinalizedHead | jget "d['result']"; }

cleanup() {
    [ -n "${NODE_PID:-}" ] && kill "$NODE_PID" 2>/dev/null || true
    wait "${NODE_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo; echo "REHEARSAL FAILED: $*" >&2; echo "node log: $WORK/node.log" >&2; exit 1; }

echo "=== 1. fresh devnet chainspec and validator key ==="
rm -rf "$WORK"; mkdir -p "$SPEC_DIR" "$BASE"
"$GENSPEC" 1 "$SPEC_DIR" >/dev/null
SPEC="$SPEC_DIR/devnet-chainspec-raw.json"
SEC=$(python3 -c "import json;print(json.load(open('$SPEC_DIR/validator-1/key.json'))['secret_key'])")
PUB=$(python3 -c "import json;print(json.load(open('$SPEC_DIR/validator-1/key.json'))['public_key'])")

echo "=== 2. inject the aura key into the keystore ==="
# Substrate keystore file: hex("aura")=61757261 followed by the public key hex
# with no 0x. The CONTENTS are a JSON string holding the secret seed WITH its
# 0x prefix — strip that prefix and the key loads but cannot sign, and the
# coherence guard then refuses to start with a confusing message in which the
# printed keystore key and authority look identical (both are truncated to 8
# bytes). That mistake cost time on 2026-09-26; do not repeat it.
KS="$BASE/chains/$CHAIN_ID/keystore"
mkdir -p "$KS"
printf '"%s"' "$SEC" > "$KS/61757261${PUB#0x}"

echo "=== 3. node network key ==="
mkdir -p "$BASE/chains/$CHAIN_ID/network"
"$NODE" key generate-node-key --file "$BASE/chains/$CHAIN_ID/network/secret_ed25519" >/dev/null 2>&1

echo "=== 4. start the validator ==="
"$NODE" --chain "$SPEC" --base-path "$BASE" --validator --name qh-test-rehearsal \
    --rpc-port "$RPC" --port "$P2P" --prometheus-port "$PROM" \
    --rpc-methods=unsafe --force-authoring \
    --log "runtime-segmentation=trace,runtime=debug" > "$WORK/node.log" 2>&1 &
NODE_PID=$!

for i in $(seq 1 60); do
    [ -n "$(spec_version)" ] && break
    kill -0 "$NODE_PID" 2>/dev/null || fail "node exited during startup"
    perl -e 'select(undef,undef,undef,1)'
done
SPEC_BEFORE=$(spec_version)
[ -n "$SPEC_BEFORE" ] || fail "RPC never came up"
echo "    spec_version before: $SPEC_BEFORE"

echo "=== 5. confirm the chain is live before touching it ==="
B1=$(best_block); perl -e 'select(undef,undef,undef,12)'; B2=$(best_block)
echo "    best block $B1 -> $B2"
[ "$B2" -gt "$B1" ] || fail "no block production before the upgrade; nothing to rehearse"

echo "=== 6. target blob ==="
TARGET_SPEC=$(subwasm info "$TARGET_WASM" 2>/dev/null | grep -oE 'quantumharmony-[0-9]+' | head -1 | cut -d- -f2)
echo "    $TARGET_WASM declares spec ${TARGET_SPEC:-unknown}, $(wc -c <"$TARGET_WASM") bytes"
[ -n "$TARGET_SPEC" ] && [ "$TARGET_SPEC" = "$SPEC_BEFORE" ] && \
    fail "target blob is also spec $SPEC_BEFORE — a spec number must never carry two different runtimes"

echo "=== 7. submit the upgrade ==="
# METHOD=setcode (default) submits one system.setCode wrapped in sudo.
# METHOD=chunked uses the chunked pallet flow instead.
#
# setcode is the default deliberately. BlockLength is 2 MiB with a 75% normal
# ratio, so roughly 1.5 MiB for a single extrinsic, and the runtime blob is
# 0.966 MiB. It fits, so the chunked path buys nothing at this size and its
# own comment says it exists "for runtime upgrades larger than BlockLength".
# The chunked flow was also measured broken on 2026-09-26: every call reported
# success, about 9 of 18 extrinsics were included, and spec_version never moved.
METHOD="${METHOD:-setcode}"
WASM_HEX="0x$(xxd -p -c 100000000 "$TARGET_WASM" | tr -d '\n')"

if [ "$METHOD" = "setcode" ]; then
    echo "    method: single system.setCode via sudo ($(( (${#WASM_HEX} - 2) / 2 )) bytes)"
    SUB=$(rpc quantumharmony_submitRuntimeUpgrade "[\"$WASM_HEX\",\"$SEC\"]")
    echo "    submit: $(echo "$SUB" | head -c 300)"
    echo "$SUB" | grep -q '"error"' && fail "setCode submission rejected"
else
    echo "    method: chunked"
    # Fail early with the real reason. The chunked pallet cannot carry this
    # runtime in either form, measured 2026-09-26:
    #
    #   compressed   0.97 MiB  fits the 2 MiB ceiling, but validate_wasm
    #                          demands \0asm and the blob starts 52 bc 53 76
    #                          (Substrate's zstd container) -> InvalidWasmFormat
    #   uncompressed 4.46 MiB  right magic, but MAX_CHUNKS 32 x MAX_CHUNK_SIZE
    #                          64 KiB caps the path at 2.00 MiB
    #
    # Raising either limit is a pallet change, so it is a runtime change and
    # needs a spec bump. Use METHOD=setcode until that lands.
    MAGIC=$(xxd -p -l 4 "$TARGET_WASM")
    if [ "$MAGIC" != "0061736d" ]; then
        echo "    WARNING: blob magic is $MAGIC, not 0061736d (\\0asm)."
        echo "             The pallet's validate_wasm will reject this, finalize will"
        echo "             fail, and nothing will report the failure except this script."
    fi
    INIT=$(rpc chunkedUpgrade_initiate "[\"$WASM_HEX\",\"$SEC\"]")
    echo "    initiate: $(echo "$INIT" | head -c 300)"
    echo "$INIT" | grep -q '"error"' && fail "initiate rejected"

    TOTAL=$(echo "$INIT" | jget "d['result']['total_chunks']")
    [ -n "$TOTAL" ] || fail "no total_chunks in initiate response"
    echo "    $TOTAL chunks to upload"

    CHUNK_BYTES=$(( (${#WASM_HEX} - 2) / 2 / TOTAL + 1 ))
    for idx in $(seq 0 $((TOTAL - 1))); do
        OFF=$(( 2 + idx * CHUNK_BYTES * 2 ))
        HX="0x${WASM_HEX:$OFF:$((CHUNK_BYTES * 2))}"
        [ "$HX" = "0x" ] && break
        R=$(rpc chunkedUpgrade_uploadChunk "[$idx,\"$HX\",\"$SEC\"]")
        echo "$R" | grep -q '"error"' && fail "chunk $idx rejected: $(echo "$R" | head -c 200)"
        printf '    chunk %s/%s submitted\n' "$((idx + 1))" "$TOTAL"
    done

    # chunkedUpgrade_status now reads the pallet's own storage, so it can be
    # used as evidence. Until 2026-09-26 it was a hardcoded Ok(None) and this
    # check was impossible: uploads "succeeded" while nothing accumulated.
    echo "    waiting for the uploads to be included..."
    # Note for anyone editing this: `[ -n "$X" ] && [ "$X" -ge "$N" ] && break`
    # as a bare command list makes the whole list's status non-zero while it is
    # still waiting, and `set -e` then kills the script with no message at all.
    # Keep this as an `if`.
    LAST_RECV=""
    for i in $(seq 1 40); do
        ST=$(rpc chunkedUpgrade_status)
        RECV=$(echo "$ST" | jget "d['result']['chunks_received']")
        if [ "$RECV" != "$LAST_RECV" ]; then
            printf '      t+%ss: %s/%s on chain\n' "$((i * 3))" "${RECV:-0}" "$TOTAL"
            LAST_RECV="$RECV"
        fi
        if [ -n "$RECV" ] && [ "$RECV" -ge "$TOTAL" ]; then break; fi
        perl -e 'select(undef,undef,undef,3)'
    done
    echo "    status: $(echo "$ST" | head -c 300)"
    if [ "$(echo "$ST" | jget "d['result']")" = "None" ]; then
        fail "status is null after uploading $TOTAL chunks — nothing accumulated on chain"
    fi
    RECV=$(echo "$ST" | jget "d['result']['chunks_received']")
    [ -n "$RECV" ] || fail "status returned no chunks_received"
    [ "$RECV" -ge "$TOTAL" ] || \
        fail "only $RECV of $TOTAL chunks landed on chain — finalize would assemble a partial runtime"
    FIN=$(rpc chunkedUpgrade_finalize "[\"$SEC\"]")
    echo "    finalize: $(echo "$FIN" | head -c 300)"
    echo "$FIN" | grep -q '"error"' && fail "finalize rejected"
fi

echo "=== 8. wait for the new runtime to take effect ==="
for i in $(seq 1 60); do
    NOW=$(spec_version)
    [ -n "$NOW" ] && [ "$NOW" != "$SPEC_BEFORE" ] && break
    kill -0 "$NODE_PID" 2>/dev/null || fail "node died during the upgrade"
    perl -e 'select(undef,undef,undef,2)'
done
SPEC_AFTER=$(spec_version)
echo "    spec_version after: ${SPEC_AFTER:-<none>}"
[ -n "$SPEC_AFTER" ] || fail "RPC gone after the upgrade"
[ "$SPEC_AFTER" != "$SPEC_BEFORE" ] || fail "spec_version never changed from $SPEC_BEFORE — the upgrade did not apply"

echo "=== 9. the chain must still be alive afterwards ==="
B3=$(best_block); F3=$(finalized)
perl -e 'select(undef,undef,undef,18)'
B4=$(best_block); F4=$(finalized)
echo "    best block $B3 -> $B4"
echo "    finalized $(echo "$F3" | head -c 14)… -> $(echo "$F4" | head -c 14)…"
[ "$B4" -gt "$B3" ] || fail "block production stopped after the upgrade"
[ "$F3" != "$F4" ] || fail "finality stalled after the upgrade"

echo
echo "REHEARSAL PASSED"
echo "  spec_version   $SPEC_BEFORE -> $SPEC_AFTER"
echo "  blocks         still produced ($B3 -> $B4)"
echo "  finality       still advancing"
echo "  node log       $WORK/node.log"
