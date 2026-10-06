# QuantumHarmony

QuantumHarmony is a ledger built on Substrate with post-quantum signatures.
Paraxiom operates a test network of three validators. It is not production.

## What it does

- Block seals and finality votes are signed with SPHINCS+ (SHAKE-256f).
- Entries are signed with Falcon-512.
- Finality comes from a custom gadget, not GRANDPA. A block is final when two
  thirds of the validators have signed a vote for it.
- Records are anchored by their fingerprint, with a short technical label.
- Transport between validators is classical (Noise). Randomness is classical.
- QMHY is a test unit used to pay fees. It is not sold.

## Layout

- `node/`: the node binary, the finality gadget, RPC.
- `runtime/`: the runtime, built to wasm.
- `pallets/`: runtime modules.
- `crates/`: support libraries.
- `chainspecs/quantumharmony-testnet.json`: the test network spec.
- `scripts/`: local devnet and runtime upgrade rehearsal.

## Build

You need Rust 1.85 for the runtime wasm. A newer toolchain fails to link it.

```sh
rustup toolchain install 1.85
rustup target add wasm32-unknown-unknown --toolchain 1.85
rustup component add rust-src --toolchain 1.85
cargo +1.85 build --release -p quantumharmony-node
```

The binary is `target/release/quantumharmony-node`.

## Run a local devnet

```sh
./scripts/devnet-n.sh up 3      # keys, chainspec, three validators on 127.0.0.1
./scripts/devnet-n.sh status    # best and finalized block per node
./scripts/devnet-n.sh clean     # stop and delete
```

## Join the test network

Use the operator kit:
https://github.com/Paraxiom/quantum-harmony-node-public

It restores a signed snapshot and starts a node with the right settings.
Syncing a new node from genesis does not work today. This is a known issue.

## Tests

```sh
SKIP_WASM_BUILD=1 cargo +1.85 test -p quantumharmony-node --bin quantumharmony-node
```

The tests under `node/tests/` talk to a running node on 127.0.0.1 and
fail without one.

## Security

See `SECURITY.md`.

## Licence

See `LICENSE`.
