//! pohc-falcon-attest — real Falcon-1024 signing harness for the PoHC E1 recorded run.
//!
//! Replaces the Python E1 simulation's HMAC stand-in (labeled "Falcon-1024 prod")
//! with actual Falcon-1024 signatures via paraxiom-pqc. Pure Rust. Zero C.
//!
//! Subcommands (JSON on stdout, diagnostics on stderr):
//!   keygen --out-dir <dir>                          -> falcon1024.sk / falcon1024.pk
//!   sign   --sk <file> --msg-file <file>            -> {"algo","sig_hex","sig_len"}
//!   verify --pk <file> --msg-file <file> --sig-hex <hex>
//!
//! Exit codes: 0 = ok / signature valid, 1 = signature invalid, 2 = usage or I/O error.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, SigningKey, VerificationKey};

const USAGE: &str = "usage:
  pohc-falcon-attest keygen --out-dir <dir> [--algo falcon512|falcon1024]
  pohc-falcon-attest sign   --sk <file> --msg-file <file> [--algo falcon512|falcon1024]
  pohc-falcon-attest verify --pk <file> --msg-file <file> --sig-hex <hex> [--algo falcon512|falcon1024]

(default --algo is falcon1024; the QH axiom-attestation RPC contract is Falcon-512,
 whose signatures fit its 1400-byte limit — Falcon-1024's 1577-byte sigs do not)";

/// Algorithm selection: default Falcon-1024 (original behavior); Falcon-512 for
/// the on-chain RPC path whose signature limit is 1400 bytes.
fn algo_from(args: &[String]) -> Result<(SignAlgorithm, &'static str, &'static str, &'static str), String> {
    match flag_value(args, "--algo").unwrap_or("falcon1024") {
        "falcon1024" => Ok((SignAlgorithm::Falcon1024, "Falcon-1024", "falcon1024.sk", "falcon1024.pk")),
        "falcon512" => Ok((SignAlgorithm::Falcon512, "Falcon-512", "falcon512.sk", "falcon512.pk")),
        other => Err(format!("unknown --algo {other:?} (expected falcon512 or falcon1024)")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("keygen") => cmd_keygen(&args[1..]),
        Some("sign") => cmd_sign(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

// ── Subcommands ─────────────────────────────────────────────────────────────

fn cmd_keygen(args: &[String]) -> Result<ExitCode, String> {
    if flag_value(args, "--seed").is_some() {
        // The paraxiom-pqc Falcon API has no seeded/deterministic keygen
        // (QRNG-seeded keygen is wired for ML-DSA only). Refuse rather than
        // silently ignore the seed: persist keys to files instead.
        return Err("seeded Falcon keygen is not supported by the paraxiom-pqc API; \
                    rerun without --seed (keys are persisted to files for reuse)"
            .into());
    }
    let out_dir = flag_value(args, "--out-dir").ok_or(USAGE)?;
    let (algo, algo_name, sk_file, pk_file) = algo_from(args)?;
    let kp = sign::keypair(algo).map_err(|e| format!("keygen failed: {e:?}"))?;

    fs::create_dir_all(out_dir).map_err(|e| format!("create {out_dir}: {e}"))?;
    let sk_path = Path::new(out_dir).join(sk_file);
    let pk_path = Path::new(out_dir).join(pk_file);
    fs::write(&sk_path, &kp.sk.bytes).map_err(|e| format!("write {}: {e}", sk_path.display()))?;
    fs::write(&pk_path, &kp.vk.bytes).map_err(|e| format!("write {}: {e}", pk_path.display()))?;
    eprintln!("wrote {} and {}", sk_path.display(), pk_path.display());

    println!(
        "{{\"algo\":\"{algo_name}\",\"pk_hex\":\"{}\",\"pk_len\":{}}}",
        hex_encode(&kp.vk.bytes),
        kp.vk.bytes.len()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_sign(args: &[String]) -> Result<ExitCode, String> {
    let sk_path = flag_value(args, "--sk").ok_or(USAGE)?;
    let msg_path = flag_value(args, "--msg-file").ok_or(USAGE)?;
    let (algo, algo_name, _, _) = algo_from(args)?;
    let sk = SigningKey {
        algorithm: algo,
        bytes: fs::read(sk_path).map_err(|e| format!("read {sk_path}: {e}"))?,
    };
    let msg = fs::read(msg_path).map_err(|e| format!("read {msg_path}: {e}"))?;
    let sig = sign::sign(&sk, &msg).map_err(|e| format!("sign failed: {e:?}"))?;
    println!(
        "{{\"algo\":\"{algo_name}\",\"sig_hex\":\"{}\",\"sig_len\":{}}}",
        hex_encode(&sig.bytes),
        sig.bytes.len()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(args: &[String]) -> Result<ExitCode, String> {
    let pk_path = flag_value(args, "--pk").ok_or(USAGE)?;
    let msg_path = flag_value(args, "--msg-file").ok_or(USAGE)?;
    let sig_hex = flag_value(args, "--sig-hex").ok_or(USAGE)?;
    let (algo, algo_name, _, _) = algo_from(args)?;
    let vk = VerificationKey {
        algorithm: algo,
        bytes: fs::read(pk_path).map_err(|e| format!("read {pk_path}: {e}"))?,
    };
    let msg = fs::read(msg_path).map_err(|e| format!("read {msg_path}: {e}"))?;
    let sig = Signature {
        algorithm: algo,
        bytes: hex_decode(sig_hex)?,
    };
    // Malformed signatures verify as invalid, not as a usage error.
    let valid = matches!(sign::verify(&vk, &msg, &sig), Ok(true));
    println!("{{\"algo\":\"{algo_name}\",\"valid\":{valid}}}");
    Ok(if valid { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}
