#!/usr/bin/env python3
"""qh-sudo-set-code — apply a runtime upgrade via sudo.

Builds and submits, in one extrinsic:
    sudo.sudo_unchecked_weight(system.set_code(<wasm>), Weight::zero())

sudo_unchecked_weight (NOT sudo.sudo) is required: set_code's declared weight is
`max`, so the normal weight-checked path rejects it.

Submission mirrors qh-sudo-add-validator.py exactly: the custom RPC
`quantumharmony_submitSignedExtrinsic` with the sudo SPHINCS+ key.

Default is DRY-RUN (prints the WASM keccak-256 and sha-256 + call size, writes nothing).
Pass --submit to apply. --expect-hash guards against upgrading the wrong blob.

Usage:
  qh-sudo-set-code.py --wasm <file> --signer-key-file <sudo.key> \
      [--expect-hash 0x..] [--rpc http://127.0.0.1:9944] [--submit]
"""
import argparse, json, sys, time, urllib.request
from pathlib import Path

# pallet / call indices (verified against the c4a7daa fork)
PALLET_SYSTEM, CALL_SET_CODE = 0, 2
PALLET_SUDO, CALL_SUDO_UNCHECKED_WEIGHT = 7, 1

def rpc(u, m, p=None):
    req = json.dumps({"jsonrpc":"2.0","method":m,"params":p or [],"id":1}).encode()
    return json.loads(urllib.request.urlopen(
        urllib.request.Request(u, data=req, headers={"Content-Type":"application/json"}),
        timeout=60).read())

def compact(n):
    if n < 64: return bytes([n << 2])
    if n < 16384: return ((n << 2) | 1).to_bytes(2, "little")
    if n < (1 << 30): return ((n << 2) | 2).to_bytes(4, "little")
    raise ValueError("compact > 2^30 unsupported")

def vec_u8(d): return compact(len(d)) + d

def runtime_hash(data: bytes) -> bytes:
    """keccak-256, the hash this runtime actually uses.

    `type Hashing = QuantumHasher` and QuantumHasher is sp_io keccak_256, which
    is sha3::Keccak256 — ORIGINAL Keccak, not NIST SHA3. hashlib.sha3_256 is the
    NIST variant and gives a different digest; do not substitute it.

    This printed blake2-256 until 2026-09-27. Nothing was broken by it, because
    the guard compared blake2 to blake2, but the number an operator saw was not
    the chain's hash, and it got pasted into an outgoing change notice. Paraxiom
    ships keccak precisely because it does not want BLAKE2 in the story.
    """
    try:
        from Crypto.Hash import keccak
    except ImportError:
        raise SystemExit("need pycryptodome for keccak-256: pip install pycryptodome")
    k = keccak.new(digest_bits=256); k.update(data)
    return k.digest()


def sha_256(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()

def load_secret(p):
    raw = Path(p).read_text().strip()
    if raw.startswith("{"): raw = json.loads(raw)["secret_key"]
    raw = raw.strip('"')
    if raw.startswith("0x"): raw = raw[2:]
    if len(raw) != 256: raise ValueError(f"expected 256 hex chars, got {len(raw)}")
    return raw

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True, help="path to the .compact.compressed.wasm")
    ap.add_argument("--signer-key-file", required=True)
    ap.add_argument("--expect-hash",
                    help="0x keccak-256 OR sha-256 of the WASM; abort on mismatch")
    ap.add_argument("--rpc", default="http://127.0.0.1:9944")
    ap.add_argument("--submit", action="store_true", help="apply (default: dry-run)")
    a = ap.parse_args()

    wasm = Path(a.wasm).read_bytes()
    h = "0x" + runtime_hash(wasm).hex()
    h_sha = "0x" + sha_256(wasm).hex()
    print(f"WASM: {a.wasm}")
    print(f"  size:    {len(wasm)} bytes")
    print(f"  keccak256: {h}   <- the chain's own hasher; quote THIS one")
    print(f"  sha256:    {h_sha}   <- verifiable with sha256sum")

    # current on-chain version (sanity)
    cur = rpc(a.rpc, "state_getRuntimeVersion", [])["result"]
    print(f"  on-chain spec_version BEFORE: {cur.get('specVersion')}")

    if a.expect_hash:
        want = a.expect_hash.lower()
        if want not in (h.lower(), h_sha.lower()):
            print(f"  ✗ GUARD: neither keccak-256 nor sha-256 matches --expect-hash "
                  f"({a.expect_hash}); ABORT")
            sys.exit(2)
        print(f"  ✓ matches --expect-hash ({'keccak-256' if want == h.lower() else 'sha-256'})")

    # build sudo.sudo_unchecked_weight(system.set_code(wasm), Weight{0,0})
    set_code = bytes([PALLET_SYSTEM, CALL_SET_CODE]) + vec_u8(wasm)
    weight = compact(0) + compact(0)   # Weight { ref_time: 0, proof_size: 0 }
    call = bytes([PALLET_SUDO, CALL_SUDO_UNCHECKED_WEIGHT]) + set_code + weight
    print(f"  upgrade call size: {len(call)} bytes (must fit the 2 MB block limit)")

    if not a.submit:
        print("\n  DRY-RUN — nothing submitted. Re-run with --submit to apply.")
        return

    secret = load_secret(a.signer_key_file)
    print("\n  submitting sudo.sudo_unchecked_weight(system.set_code(...)) ...")
    r = rpc(a.rpc, "quantumharmony_submitSignedExtrinsic",
            [{"callData": "0x" + call.hex(), "signerKey": secret}])
    if "error" in r or not r.get("result", {}).get("success"):
        print(f"  FAIL: {json.dumps(r)[:400]}"); sys.exit(4)
    print(f"  tx: {r['result'].get('hash','?')}")

    print("  waiting 18s for inclusion...")
    time.sleep(18)
    post = rpc(a.rpc, "state_getRuntimeVersion", [])["result"]
    print(f"  on-chain spec_version AFTER: {post.get('specVersion')}")
    print("  ✓ upgraded" if post.get("specVersion") != cur.get("specVersion") else "  ✗ version unchanged — investigate")

if __name__ == "__main__":
    main()
