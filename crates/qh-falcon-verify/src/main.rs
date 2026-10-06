//! qh-falcon-verify — standalone Stage-0 signature verifier.
//!
//! Verifies SPHINCS+-SHAKE-256s signatures on QuantumHarmony governance
//! announcements. Called by `qh-agent`'s governance module via:
//!
//!     qh-falcon-verify <pubkey_hex> <message_path> <signature_hex>
//!
//! - exits 0 if the signature is valid
//! - exits 1 if invalid (or any error during decode/IO/verification)
//! - exits 2 on usage errors
//!
//! Stderr carries human-readable error on failure; stdout is silent on
//! success.
//!
//! ## Why standalone (not a node-RPC method)
//!
//! See `docs/ops/falcon-verify-helper-spec.md` for the trade-off
//! analysis. tl;dr: this binary doesn't depend on a running node, so it
//! can verify announcements out-of-band (cold-rig audit) and survives
//! the very recovery scenarios that governance is meant to handle.
//!
//! ## Algorithm choice
//!
//! SPHINCS+-SHAKE-256s-simple, Round 3.1 as implemented by PQClean
//! (`pqcrypto-sphincsplus 0.7`). Hash-based, conservatively secure (no
//! number-theoretic assumptions). Signatures are 29,792 bytes, irrelevant
//! at one-announcement-per-month cadence.
//!
//! This is NOT the chain's parameter set. Aura seals, finality votes and
//! extrinsics use SHAKE-256**f**-simple (49,856-byte signatures; checked
//! against live block seals on 2026-09-30). A key or signature made for the
//! chain will not verify here, and the reverse. Whoever builds the
//! announcement signer must use 256s, or this verifier must move to 256f.
//! Not FIPS 205 either: FIPS 205 SLH-DSA signatures are not byte compatible
//! with Round 3.1 (see pqc-compat-test).

use std::env;
use std::fs;
use std::process::ExitCode;

use pqcrypto_sphincsplus::sphincsshake256ssimple as sphincs;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

fn die(msg: &str, code: u8) -> ExitCode {
    eprintln!("qh-falcon-verify: {}", msg);
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return die(
            "usage: qh-falcon-verify <pubkey_hex> <message_path> <signature_hex>",
            2,
        );
    }
    let pubkey_hex = &args[1];
    let message_path = &args[2];
    let signature_hex = &args[3];

    let pubkey_bytes = match hex::decode(pubkey_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(e) => return die(&format!("bad pubkey hex: {}", e), 1),
    };
    let sig_bytes = match hex::decode(signature_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(e) => return die(&format!("bad signature hex: {}", e), 1),
    };
    // Message comes from stdin if `-`, otherwise from the file at message_path.
    // Stdin lets the agent pipe the message in via `docker exec -i ... -` without
    // needing the file to be visible inside the container.
    let message = if message_path == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        match std::io::stdin().read_to_end(&mut buf) {
            Ok(_) => buf,
            Err(e) => return die(&format!("cannot read message from stdin: {}", e), 1),
        }
    } else {
        match fs::read(message_path) {
            Ok(b) => b,
            Err(e) => return die(&format!("cannot read message file: {}", e), 1),
        }
    };

    let pk = match sphincs::PublicKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(e) => return die(&format!("public key wrong format: {:?}", e), 1),
    };
    let sig = match sphincs::DetachedSignature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(e) => return die(&format!("signature wrong format: {:?}", e), 1),
    };

    match sphincs::verify_detached_signature(&sig, &message, &pk) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => die(&format!("signature invalid: {:?}", e), 1),
    }
}
