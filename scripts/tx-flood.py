#!/usr/bin/env python3
"""SPHINCS+ transaction flooder for devnet load tests.

Uses the node's gateway_submit RPC (node/src/rpc/transaction_gateway.rs), which
constructs and signs balances.transfer_allow_death extrinsics node-side with
the supplied SPHINCS+ secret. Senders = devnet validator keys produced by
generate-devnet-chain-spec (key.json per validator).

Usage:
  tx-flood.py --base /tmp/qh-devnet-n --rpc http://127.0.0.1:20001 \
              --senders 8 --rate 10 --duration 120

Writes a CSV (--out) with per-submission timestamps and results, and prints a
summary (submitted / accepted / rejected, achieved rate).
"""
import argparse, json, time, csv, sys, itertools, urllib.request
from pathlib import Path


def rpc(url, method, params):
    body = json.dumps({"id": 1, "jsonrpc": "2.0", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="devnet base dir with validator-*/key.json")
    ap.add_argument("--rpc", default="http://127.0.0.1:20001")
    ap.add_argument("--senders", type=int, default=8)
    ap.add_argument("--sender-offset", type=int, default=0)
    ap.add_argument("--rate", type=float, default=10, help="target submissions/sec overall")
    ap.add_argument("--duration", type=int, default=120, help="seconds")
    ap.add_argument("--amount", default="1000000000000")
    ap.add_argument("--out", default="/tmp/tx-flood.csv")
    args = ap.parse_args()

    keys = []
    for d in sorted(Path(args.base).glob("validator-*/key.json"),
                    key=lambda p: int(p.parent.name.split("-")[1])):
        keys.append(json.loads(d.read_text()))
    if len(keys) < 2:
        sys.exit("need at least 2 validator keys")
    senders = keys[args.sender_offset : args.sender_offset + args.senders]
    recipient = keys[-1]

    genesis = rpc(args.rpc, "gateway_genesisHash", [])
    nonces = {}
    for s in senders:
        nonces[s["ss58_address"]] = rpc(args.rpc, "gateway_nonce", [s["ss58_address"]])
    print(f"flooding via {args.rpc}: {len(senders)} senders -> {recipient['ss58_address'][:12]}…, "
          f"target {args.rate}/s for {args.duration}s")

    w = csv.writer(open(args.out, "w"))
    w.writerow(["ts", "sender", "nonce", "ok", "detail"])
    interval = 1.0 / args.rate
    t_end = time.time() + args.duration
    sent = ok = 0
    cycle = itertools.cycle(senders)
    while time.time() < t_end:
        t0 = time.time()
        s = next(cycle)
        addr = s["ss58_address"]
        try:
            res = rpc(args.rpc, "gateway_submit", [{
                "from": addr, "to": recipient["ss58_address"], "amount": args.amount,
                "nonce": nonces[addr], "genesisHash": genesis, "secretKey": s["secret_key"],
            }])
            nonces[addr] += 1
            ok += 1
            w.writerow([f"{t0:.3f}", addr[:12], nonces[addr] - 1, 1, str(res)[:64]])
        except Exception as e:
            w.writerow([f"{t0:.3f}", addr[:12], nonces[addr], 0, str(e)[:120]])
            # resync nonce on error
            try:
                nonces[addr] = rpc(args.rpc, "gateway_nonce", [addr])
            except Exception:
                pass
        sent += 1
        if sent % 50 == 0:
            print(f"  {sent} submitted, {ok} accepted, t-{int(t_end - time.time())}s")
        delay = interval - (time.time() - t0)
        if delay > 0:
            time.sleep(delay)

    print(f"DONE: submitted={sent} accepted={ok} rejected={sent - ok} "
          f"achieved={sent / args.duration:.1f}/s -> {args.out}")


if __name__ == "__main__":
    main()
