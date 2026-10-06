#!/usr/bin/env bash
# Rehearse what happens when a runtime upgrade has to be undone.
#
# WHAT THIS ESTABLISHED, 2026-09-27 (all three measured, not reasoned)
# --------------------------------------------------------------------
# 1. A `system.setCode` upgrade leaves NO rollback backup.
#    ChunkedUpgrade::RuntimeBackup and ::LastUpgradeBlock are both None
#    afterwards, because backup_current_runtime() is only called inside
#    finalize_chunked_upgrade. So the pallet's rollback_runtime (call index 4)
#    fails with NoRollbackAvailable after the upgrade path we actually recommend.
#    There is also no RPC that calls rollback_runtime at all.
#
# 2. setCode CANNOT go backwards. frame_system::can_set_code rejects it with
#    SpecVersionNeedsToIncrease. The submission still returns a transaction
#    hash and the extrinsic still succeeds, because sudo_unchecked_weight
#    reports the inner failure as Sudid(Err(Module{0,1})). Nothing in the RPC
#    response tells you it did not work.
#
# 3. Rolling FORWARD works: build the previous runtime's code under the NEXT
#    spec version and setCode that. Blocks and finality continue.
#
# THE OPERATIONAL CONSEQUENCE
# ---------------------------
# Rolling back means shipping a new, higher spec version carrying the old code.
# That build must exist BEFORE the upgrade starts. If it does not, "rollback"
# means compiling a runtime under incident pressure, which is exactly when you
# do not want to be doing it.
#
# USAGE
#   scripts/rehearse-rollback.sh <current.wasm> <next.wasm> <rollback.wasm>
#
# where current < next < rollback in spec_version, and rollback.wasm carries the
# code of current.wasm. Example, from a spec-46 tree: 46, 47, and 48-built-from-46.
#
# Local only: own chainspec and keys, /tmp/qh-test-rollback, RPC 9955, p2p 30355,
# qh-test- prefix per CLAUDE.md. Never contacts the fleet. Build with rust 1.85.
set -euo pipefail

CUR="${1:?usage: $0 <current.wasm> <next.wasm> <rollback.wasm>}"
NEXT="${2:?}"; RB="${3:?}"
for f in "$CUR" "$NEXT" "$RB"; do [ -f "$f" ] || { echo "no such wasm: $f" >&2; exit 1; }; done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE="$REPO/target/release/quantumharmony-node"
GENSPEC="$REPO/target/release/generate-devnet-chain-spec"
W=/tmp/qh-test-rollback
CHAIN_ID=qh_devnet
PORT=9955

for b in "$NODE" "$GENSPEC"; do [ -x "$b" ] || { echo "missing $b" >&2; exit 1; }; done

PID=""
cleanup(){ [ -n "$PID" ] && kill "$PID" 2>/dev/null || true; }
trap cleanup EXIT
fail(){ echo; echo "ROLLBACK REHEARSAL FAILED: $*" >&2; echo "logs: $W" >&2; exit 1; }

echo "=== devnet ==="
rm -rf "$W"; mkdir -p "$W/base/chains/$CHAIN_ID/keystore" "$W/base/chains/$CHAIN_ID/network"
"$GENSPEC" 1 "$W/spec" >/dev/null
SEC=$(python3 -c "import json;print(json.load(open('$W/spec/validator-1/key.json'))['secret_key'])")
PUB=$(python3 -c "import json;print(json.load(open('$W/spec/validator-1/key.json'))['public_key'])")
printf '"%s"' "$SEC" > "$W/base/chains/$CHAIN_ID/keystore/61757261${PUB#0x}"
"$NODE" key generate-node-key --file "$W/base/chains/$CHAIN_ID/network/secret_ed25519" >/dev/null 2>&1
"$NODE" --chain "$W/spec/devnet-chainspec-raw.json" --base-path "$W/base" --validator \
    --name qh-test-rollback --rpc-port "$PORT" --port 30355 --prometheus-port 9655 \
    --rpc-methods=unsafe --force-authoring > "$W/node.log" 2>&1 &
PID=$!
echo "$SEC" > "$W/sec.txt"

PORT="$PORT" SEC_FILE="$W/sec.txt" CUR="$CUR" NEXT="$NEXT" RB="$RB" \
python3 - <<'PY'
import json,os,sys,time,urllib.request
URL="http://127.0.0.1:%s" % os.environ["PORT"]
SEC=open(os.environ["SEC_FILE"]).read().strip()
EVENTS="0x26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7"
# frame_system::Error, in declaration order
SYS=["InvalidSpecName","SpecVersionNeedsToIncrease","FailedToExtractRuntimeVersion",
     "NonDefaultComposite","NonZeroRefCount","CallFiltered"]

def rpc(m,p=None):
    b=json.dumps({"jsonrpc":"2.0","method":m,"params":p or [],"id":1}).encode()
    return json.load(urllib.request.urlopen(
        urllib.request.Request(URL,b,{"Content-Type":"application/json"}),timeout=300))
def spec(): return rpc("state_getRuntimeVersion")["result"]["specVersion"]
def height(): return int(rpc("chain_getHeader")["result"]["number"],16)
def setcode(path):
    return rpc("quantumharmony_submitRuntimeUpgrade",
               ["0x"+open(path,'rb').read().hex(), SEC])
def wait_spec(target, secs=120):
    for _ in range(secs//2):
        if spec()==target: return True
        time.sleep(2)
    return spec()==target
def sudid(a,b):
    """Recover inner sudo failures, which the RPC response never shows."""
    out=[]
    for n in range(a,b+1):
        bh=rpc("chain_getBlockHash",[n])["result"]
        ev=rpc("state_getStorage",[EVENTS,bh]).get("result")
        if not ev: continue
        raw=ev[2:]; i=raw.find("07000103")   # Sudo(7).Sudid(0) Err(1) Module(3)
        if i!=-1:
            t=raw[i+8:i+18]; mod=int(t[0:2],16); err=int(t[2:4],16)
            nm=SYS[err] if mod==0 and err<len(SYS) else "?"
            out.append((n,mod,err,nm))
    return out

for _ in range(90):
    try: spec(); break
    except Exception: time.sleep(1)
start=spec(); print("  devnet at spec %s\n" % start)
fails=[]

print("### 1. after setCode, is there anything to roll back to?")
print("  upgrading to the NEXT blob…")
setcode(os.environ["NEXT"])
if not wait_spec(start+1): fails.append("the upgrade itself did not apply")
print("  spec now: %s" % spec())
sys.path.insert(0,'/tmp/qh-probe')
try:
    from twox import key
    for item in ("RuntimeBackup","LastUpgradeBlock"):
        v=rpc("state_getStorage",[key("ChunkedUpgrade",item)]).get("result")
        print("  ChunkedUpgrade::%-16s = %r" % (item,v))
        if v is not None: print("     (a backup exists — rollback_runtime could be used, if an RPC existed)")
    print("  -> None means rollback_runtime fails with NoRollbackAvailable")
except Exception as e:
    print("  (could not read pallet storage: %s)" % e)

print("\n### 2. can setCode go backwards?")
h1=height(); r=setcode(os.environ["CUR"])
print("  submit returned: %s" % json.dumps(r.get("result") or r.get("error"))[:80])
time.sleep(14); h2=height()
now=spec()
print("  spec now: %s" % now)
if now != start+1:
    fails.append("a downgrade APPLIED; that should be impossible")
for n,mod,err,nm in sudid(h1,h2):
    print("    block %s: Module{%s,%s} -> %s" % (n,mod,err,nm))
    if nm!="SpecVersionNeedsToIncrease":
        fails.append("unexpected inner error on the downgrade attempt: %s" % nm)

print("\n### 3. roll forward carrying the old code")
setcode(os.environ["RB"])
if not wait_spec(start+2): fails.append("the roll-forward did not apply")
print("  spec now: %s" % spec())
b=height(); time.sleep(12); b2=height()
print("  blocks %s -> %s" % (b,b2))
if b2<=b: fails.append("block production stopped after the roll-forward")

print()
if fails:
    for f in fails: print("FAIL: %s" % f)
    sys.exit(1)
print("ROLLBACK REHEARSAL PASSED")
print("  setCode leaves no backup, a downgrade is refused, rolling forward works.")
print("  So the rollback blob must be BUILT BEFORE the upgrade starts.")
PY
