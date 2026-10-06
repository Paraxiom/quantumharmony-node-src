#!/usr/bin/env python3
"""Spec 46 -> 47 rehearsal with seeded state, on a local 3-validator devnet.

The stock rehearsals upgrade an empty chain. This one first puts state where
spec 47 has to deal with it, then checks what 47 did with it:

  on 46: oracle price and a QCAD vault (200 QMHY reserved), a Devonomics
         score, a funded plain account that calls register_validator
  on 47: Stablecoin and Devonomics storage empty, the 200 QMHY unreserved,
         nobody removed from the validator set, register_validator refused,
         sudo add_validator still works, one finalized chain, still live

Run the nodes on a spec 46 binary and pass the spec 47 blob. The validators
use classical transport (DISABLE_PQC_TRANSPORT=1, DISABLE_QUANTUM_P2P=1), as
the test network does.

Local only: 127.0.0.1, RPC 9981-9983, p2p 30381-30383, /tmp/qh-test-s47.
Every node started here is killed on exit. Needs python3 with xxhash and
pycryptodome.

usage: scripts/rehearse-spec47-state.py <node-binary> <genspec-binary> <spec47.wasm>
"""
import hashlib, json, os, shutil, signal, subprocess, sys, time, urllib.request
from Crypto.Hash import keccak

NODE, GENSPEC, WASM = sys.argv[1], sys.argv[2], sys.argv[3]
WORK = "/tmp/qh-test-s47"
CHAIN_ID = "qh_devnet"
N = 3
UNITS = 10**18
ENV = dict(os.environ, DISABLE_PQC_TRANSPORT="1", DISABLE_QUANTUM_P2P="1")
procs = []
results = []


def log(*a):
    print(*a, flush=True)


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    log(("  PASS " if ok else "  FAIL ") + name + (f"  [{detail}]" if detail else ""))


def rpc(i, method, params=None, timeout=60):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{9980 + i}", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def res(i, method, params=None):
    return rpc(i, method, params).get("result")


# ---------- hashing / SCALE ----------
def twox128(data: bytes) -> bytes:
    import xxhash
    return xxhash.xxh64(data, seed=0).intdigest().to_bytes(8, "little") + \
        xxhash.xxh64(data, seed=1).intdigest().to_bytes(8, "little")


def blake2_128concat(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=16).digest() + data


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256); k.update(data); return k.digest()


def u32(v): return v.to_bytes(4, "little")
def u64(v): return v.to_bytes(8, "little")
def u128(v): return v.to_bytes(16, "little")


def compact(v):
    if v < 1 << 6: return bytes([v << 2])
    if v < 1 << 14: return (v << 2 | 1).to_bytes(2, "little")
    if v < 1 << 30: return (v << 2 | 2).to_bytes(4, "little")
    b = v.to_bytes((v.bit_length() + 7) // 8, "little")
    return bytes([(len(b) - 4) << 2 | 3]) + b


def sudo(call): return bytes([7, 0]) + call


def submit(i, call: bytes, secret: str):
    r = rpc(i, "quantumharmony_submitSignedExtrinsic", [{"callData": "0x" + call.hex(), "signerKey": secret}], timeout=120)
    log("    submit", call[:2].hex(), "->", json.dumps(r)[:160])
    return r


def storage(i, key: bytes):
    return res(i, "state_getStorage", ["0x" + key.hex()])


def keys_under(i, prefix: bytes):
    return res(i, "state_getKeysPaged", ["0x" + prefix.hex(), 10]) or []


def reserved(i, acct: bytes) -> int:
    raw = storage(i, twox128(b"System") + twox128(b"Account") + blake2_128concat(acct))
    if not raw: return 0
    b = bytes.fromhex(raw[2:])
    # AccountInfo: nonce u32, consumers u32, providers u32, sufficients u32,
    # then AccountData { free u128, reserved u128, frozen u128, flags u128 }
    return int.from_bytes(b[32:48], "little")


def validators(i):
    raw = storage(i, twox128(b"ValidatorSet") + twox128(b"Validators"))
    if not raw: return []
    b = bytes.fromhex(raw[2:])
    # compact length then 32-byte account ids
    mode = b[0] & 3
    n, off = (b[0] >> 2, 1) if mode == 0 else (int.from_bytes(b[:2], "little") >> 2, 2)
    return [b[off + 32 * k: off + 32 * (k + 1)] for k in range(n)]


def spec(i): return res(i, "state_getRuntimeVersion")["specVersion"]
def finalized(i): return res(i, "chain_getFinalizedHead")
def best(i): return int(res(i, "chain_getHeader")["number"], 16)


def wait(pred, secs, step=2):
    end = time.time() + secs
    while time.time() < end:
        try:
            if pred(): return True
        except Exception:
            pass
        time.sleep(step)
    return False


def load_key(d, n):
    k = json.load(open(f"{d}/validator-{n}/key.json"))
    pub = bytes.fromhex(k["public_key"][2:] if k["public_key"].startswith("0x") else k["public_key"])
    return k["secret_key"], k["public_key"], keccak256(pub)


def main():
    shutil.rmtree(WORK, ignore_errors=True); os.makedirs(WORK)
    subprocess.run([GENSPEC, str(N), f"{WORK}/spec"], check=True, capture_output=True)
    subprocess.run([GENSPEC, "5", f"{WORK}/extra"], check=True, capture_output=True)
    chainspec = f"{WORK}/spec/devnet-chainspec-raw.json"
    keys = {n: load_key(f"{WORK}/spec", n) for n in range(1, N + 1)}
    sec1, _, acct1 = keys[1]
    sec4, _, acct4 = load_key(f"{WORK}/extra", 4)   # plain account, not a validator
    _, _, acct5 = load_key(f"{WORK}/extra", 5)      # target for sudo add_validator

    peer = {}
    for n in range(1, N + 1):
        base = f"{WORK}/n{n}/chains/{CHAIN_ID}"
        os.makedirs(f"{base}/keystore"); os.makedirs(f"{base}/network")
        sec, pub, _ = keys[n]
        pubhex = pub[2:] if pub.startswith("0x") else pub
        open(f"{base}/keystore/61757261{pubhex}", "w").write(json.dumps(sec))
        out = subprocess.run([NODE, "key", "generate-node-key", "--file", f"{base}/network/secret_ed25519"],
                             capture_output=True, text=True)
        peer[n] = (out.stderr.strip() or out.stdout.strip()).splitlines()[-1]

    for n in range(1, N + 1):
        boot = [f"--bootnodes=/ip4/127.0.0.1/tcp/{30380 + m}/p2p/{peer[m]}" for m in range(1, N + 1) if m != n]
        cmd = [NODE, "--chain", chainspec, "--base-path", f"{WORK}/n{n}", "--validator",
               "--name", f"qh-test-s47-{n}", "--rpc-port", str(9980 + n), "--port", str(30380 + n),
               "--prometheus-port", str(9680 + n), "--rpc-methods=unsafe", "--force-authoring",
               "--no-mdns"] + boot
        procs.append(subprocess.Popen(cmd, stdout=open(f"{WORK}/n{n}.log", "w"), stderr=subprocess.STDOUT, env=ENV))

    log("== devnet up, peered, finalizing on spec 46")
    assert wait(lambda: all(spec(n) == 46 for n in range(1, N + 1)), 90), "nodes did not answer"
    assert wait(lambda: all(res(n, "system_health")["peers"] >= N - 1 for n in range(1, N + 1)), 90), "no peering"
    f0 = finalized(1)
    assert wait(lambda: finalized(1) != f0, 150, 3), "no finality before upgrade"

    log("== genesis keys: Stablecoin", keys_under(1, twox128(b"Stablecoin")), "Devonomics", keys_under(1, twox128(b"Devonomics")))
    log("== seed state on 46")
    submit(1, sudo(bytes([35, 8]) + u128(UNITS)), sec1)                                   # oracle price 1.0
    check("46: price set", wait(lambda: storage(1, twox128(b"Stablecoin") + twox128(b"QMHYPrice")), 60))
    r_before_vault = reserved(1, acct1)
    submit(1, bytes([35, 0]) + u128(200 * UNITS) + u128(100 * UNITS), sec1)               # open_vault
    check("46: vault opened", wait(lambda: keys_under(1, twox128(b"Stablecoin") + twox128(b"Vaults")), 60))
    check("46: collateral reserved", wait(lambda: reserved(1, acct1) - r_before_vault == 200 * UNITS, 30),
          f"reserved {r_before_vault} -> {reserved(1, acct1)}")
    submit(1, sudo(bytes([37, 2]) + acct1 + u32(42)), sec1)                               # devonomics score
    check("46: devonomics entry", wait(lambda: keys_under(1, twox128(b"Devonomics") + twox128(b"DevScore")), 60))
    submit(1, bytes([5, 0, 0]) + acct4 + compact(1000 * UNITS), sec1)                    # fund plain account
    check("46: plain account funded", wait(lambda: storage(1, twox128(b"System") + twox128(b"Account") + blake2_128concat(acct4)), 60))
    epoch = u64(0) + compact(0) + u64(0) + u64(0) + u64(0) + compact(0) + compact(0) + b"\x00"
    reg = bytes([22, 6]) + epoch
    r46 = submit(1, reg, sec4)
    check("46: register_validator from a plain account lets it in (the open door)",
          wait(lambda: acct4 in validators(1), 60), json.dumps(r46)[:120])

    reserved_before = reserved(1, acct1)
    log("== upgrade to 47 through n1")
    blob = open(WASM, "rb").read()
    up = rpc(1, "quantumharmony_submitRuntimeUpgrade", ["0x" + blob.hex(), sec1], timeout=300)
    check("upgrade submitted", "error" not in up, json.dumps(up)[:120])
    check("all 3 on spec 47", wait(lambda: all(spec(n) == 47 for n in range(1, N + 1)), 180, 3),
          str([spec(n) for n in range(1, N + 1)]))

    # The block that sets :code already reports spec 47; the migrations run
    # at the start of the next block. Wait for two more blocks on every node.
    b_flip = max(best(n) for n in range(1, N + 1))
    check("two blocks past the upgrade", wait(lambda: all(best(n) >= b_flip + 2 for n in range(1, N + 1)), 60), f"from #{b_flip}")
    log("== checks on 47")
    log("   Stablecoin keys:", keys_under(1, twox128(b"Stablecoin")))
    log("   Devonomics keys:", keys_under(1, twox128(b"Devonomics")))
    check("Stablecoin storage empty", keys_under(1, twox128(b"Stablecoin")) == [])
    check("Devonomics storage empty", keys_under(1, twox128(b"Devonomics")) == [])
    ra = reserved(1, acct1)
    check("vault collateral unreserved exactly", reserved_before - ra == 200 * UNITS,
          f"reserved {reserved_before} -> {ra}")
    check("47 removes nobody: the account that joined on 46 is still a validator",
          acct4 in validators(1))
    r47 = submit(1, reg, sec4)
    err = json.dumps(r47.get("error") or r47.get("result"))[:200]
    check("47: register_validator refused", "error" in r47, err)
    submit(1, sudo(bytes([22, 0]) + acct5), sec1)
    check("47: sudo add_validator still works", wait(lambda: acct5 in validators(1), 60))

    time.sleep(15)
    heads = [finalized(n) for n in range(1, N + 1)]
    fork = False
    for n in range(2, N + 1):
        num = int(res(n, "chain_getHeader", [heads[n - 1]])["number"], 16)
        if res(1, "chain_getBlockHash", [num]) != heads[n - 1]: fork = True
    check("no fork: finalized heads on one chain", not fork, str([h[:14] for h in heads]))
    b0, f1 = best(1), finalized(1)
    check("finality still advancing", wait(lambda: finalized(1) != f1, 150, 3))
    check("blocks still produced", best(1) > b0, f"{b0} -> {best(1)}")


try:
    main()
except AssertionError as e:
    check("setup", False, str(e))
finally:
    for p in procs:
        p.send_signal(signal.SIGTERM)
    for p in procs:
        try: p.wait(timeout=30)
        except Exception: p.kill()
    ok = all(r[1] for r in results)
    log("\nSTATE REHEARSAL " + ("PASSED" if ok else "FAILED") + f"  ({sum(r[1] for r in results)}/{len(results)} checks)")
    sys.exit(0 if ok else 1)
