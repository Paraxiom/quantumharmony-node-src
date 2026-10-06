# quantumharmony-runtime-upgrade

Uploads a runtime wasm to a QuantumHarmony node in chunks, signed with a
SPHINCS+ sudo key, through the `chunkedUpgrade_*` RPC methods.

## Build

```sh
cargo +1.85 build --release -p quantumharmony-runtime-upgrade
```

## Use

```sh
./target/release/quantumharmony-runtime-upgrade \
  --endpoint http://127.0.0.1:9944 \
  --wasm path/to/runtime.compact.compressed.wasm \
  --secret-key <128-byte SPHINCS+ secret, hex> \
  --dry-run
```

- `--endpoint`: HTTP RPC of the node. Default `http://127.0.0.1:9944`.
- `--wasm`: the runtime blob.
- `--secret-key`: the sudo key. The tool has no built-in key.
- `--block-time`: seconds between chunks. Default 6.
- `--cancel-pending`: cancel a pending upgrade before starting.
- `--dry-run`: show the plan and stop.

Rehearse every upgrade on a local devnet first. See
`scripts/rehearse-runtime-upgrade.sh` and `scripts/rehearse-upgrade-3val.sh`.
A runtime upgrade cannot be rolled back. The only way out of a bad runtime is
a newer one, so build the next blob before you upgrade.
