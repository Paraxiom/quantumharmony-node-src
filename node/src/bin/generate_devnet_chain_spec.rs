//! Generate an N-validator scaling-devnet chainspec plus per-validator
//! SPHINCS+ keys.
//!
//! For validator-scaling load tests only — never for a live network.
//!
//! Usage:
//!   generate-devnet-chain-spec <N> <out_dir>
//!
//! Writes:
//!   <out_dir>/validator-<i>/key.json          (secret/public/account, 0600)
//!   <out_dir>/devnet-chainspec.json           (human-readable)
//!   <out_dir>/devnet-chainspec-raw.json       (for --chain)
//!
//! SPHINCS+ keygen is non-deterministic, so the FULL 128-byte secret key is
//! stored (same rationale as generate-prod-key): the keystore must hold the
//! actual secret, not a seed.

use sp_core::{crypto::ByteArray, crypto::Ss58Codec, sphincs::Pair, Pair as TraitPair};
use sp_runtime::{traits::IdentifyAccount, MultiSigner};
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <N> <out_dir>", args[0]);
        std::process::exit(1);
    }
    let n: usize = args[1].parse().unwrap_or_else(|_| {
        eprintln!("N must be a positive integer, got {:?}", args[1]);
        std::process::exit(1);
    });
    if n == 0 || n > 256 {
        eprintln!("N must be in 1..=256 (Aura MaxAuthorities), got {}", n);
        std::process::exit(1);
    }
    let out_dir = PathBuf::from(&args[2]);
    fs::create_dir_all(&out_dir).expect("Failed to create output dir");

    let mut authorities = Vec::with_capacity(n);

    for i in 1..=n {
        let (pair, _seed) = Pair::generate();
        let public = pair.public();
        let secret_bytes = pair.secret();

        let signer = MultiSigner::from(public.clone());
        let account_id = signer.into_account();
        let account_bytes: &[u8] = account_id.as_ref();

        let key_dir = out_dir.join(format!("validator-{}", i));
        fs::create_dir_all(&key_dir).expect("Failed to create validator key dir");
        let key_json = serde_json::json!({
            "name": format!("validator-{}", i),
            "public_key": format!("0x{}", hex::encode(public.as_ref() as &[u8])),
            "secret_key": format!("0x{}", hex::encode(secret_bytes)),
            "account_id": format!("0x{}", hex::encode(account_bytes)),
            "ss58_address": account_id.to_ss58check(),
        });
        let key_path = key_dir.join("key.json");
        fs::write(&key_path, serde_json::to_string_pretty(&key_json).unwrap())
            .expect("Failed to write key.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .expect("Failed to chmod key.json");
        }

        let aura = sp_consensus_aura::sphincs::AuthorityId::from_slice(public.as_ref())
            .expect("SPHINCS+ public key converts to AuraId");
        authorities.push((account_id, aura));
        eprintln!("  validator-{}: {}", i, key_json["ss58_address"].as_str().unwrap());
    }

    let spec = quantumharmony_node::chain_spec::devnet_n_config(authorities);

    let plain = spec.as_json(false).expect("Failed to serialize chainspec");
    fs::write(out_dir.join("devnet-chainspec.json"), &plain)
        .expect("Failed to write plain chainspec");

    let raw = spec.as_json(true).expect("Failed to serialize raw chainspec");
    fs::write(out_dir.join("devnet-chainspec-raw.json"), &raw)
        .expect("Failed to write raw chainspec");

    eprintln!(
        "Wrote {} validator keys + chainspec to {}",
        n,
        out_dir.display()
    );
}
