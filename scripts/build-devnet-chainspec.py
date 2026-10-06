#!/usr/bin/env python3
"""Build a 3-validator QH devnet chainspec from sphincs-key validator-set output.

Substrate's chainspec parser wants SS58 addresses in human-readable JSON. The
standard scalecodec library here chokes on 64-byte keys, so we encode SS58
manually per the substrate spec:

  prefix_bytes + pubkey + blake2b_512(b"SS58PRE" + prefix_bytes + pubkey)[0:2]
  → base58

Runs on Alice. Outputs /tmp/qh-devnet/devnet-chainspec.json.
"""

import hashlib
import json
from pathlib import Path

import base58

DEVNET_DIR = Path("/tmp/qh-devnet")
BASE = DEVNET_DIR / "base.json"
SNIPPET = DEVNET_DIR / "chain-spec-snippet.json"
OUT = DEVNET_DIR / "devnet-chainspec.json"
SS58_PREFIX = 42


def ss58_encode(pubkey: bytes, prefix: int = SS58_PREFIX) -> str:
    if prefix < 64:
        prefix_bytes = bytes([prefix])
    else:
        prefix_bytes = bytes([
            ((prefix & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000,
            (prefix >> 8) | ((prefix & 0b0000_0000_0000_0011) << 6),
        ])
    body = prefix_bytes + pubkey
    checksum = hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]
    return base58.b58encode(body + checksum).decode()


def hex_bytes(h):
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def to_ss58(hex_str):
    return ss58_encode(hex_bytes(hex_str))


def main():
    base = json.loads(BASE.read_text())
    snip = json.loads(SNIPPET.read_text())

    aura_hex = snip["aura_authorities"]
    balances = snip["balances"]
    sudo_hex = snip["sudo_key"]

    stash_ss58 = [to_ss58(b["account_id"]) for b in balances]
    aura_ss58 = [to_ss58(a) for a in aura_hex]
    sudo_ss58 = to_ss58(sudo_hex)

    base["name"] = "QuantumHarmony Devnet (M2 setCode test)"
    base["id"] = "qh_devnet"
    base["chainType"] = "Local"
    base["bootNodes"] = []

    patch = base["genesis"]["runtimeGenesis"]["patch"]

    patch["balances"] = {
        "balances": [[stash_ss58[i], balances[i]["balance"]] for i in range(3)],
    }

    patch["session"] = {
        "keys": [
            [stash_ss58[i], stash_ss58[i], {"aura": aura_ss58[i]}]
            for i in range(3)
        ],
        "nonAuthorityKeys": [],
    }

    patch["sphincsKeystore"] = {
        "keys": [[stash_ss58[i], aura_ss58[i]] for i in range(3)],
    }

    patch["sudo"] = {"key": sudo_ss58}

    patch["validatorSet"] = {
        "initialValidators": stash_ss58,
    }

    patch["validatorRewards"] = {
        "blockReward": 1000000000000000000,
        "initialValidators": [[s, 10000000000000000000000] for s in stash_ss58],
        "minStake": 1000000000000000000000,
    }

    OUT.write_text(json.dumps(base, indent=2))
    print(f"Wrote {OUT} ({OUT.stat().st_size} bytes)")
    for i in range(3):
        print(f"  validator-{i+1} stash: {stash_ss58[i]}")
        print(f"  validator-{i+1} aura:  {aura_ss58[i][:40]}...")
    print(f"  sudo: {sudo_ss58}")


if __name__ == "__main__":
    main()
