//! Caller authentication for RPC methods that sign with a node keystore key.
//!
//! `quantumharmony_submitNotarization` (`notr`) and `transparence_record*`
//! (`trsp`) sign an extrinsic on the caller's behalf. Before this module they
//! signed for anyone who could reach the RPC port. Now the caller must present
//! a Falcon signature from a key listed in `--rpc-caller-allowlist`.
//!
//! This is deliberately not `DenyUnsafe`: every node runs
//! `--rpc-methods=Safe`, and unsafe mode would expose `author_insertKey`.
//!
//! Allowlist file: one hex Falcon-512/1024 verifying key per line (the
//! `transparence-signer` sidecar's `vk_hex`). Blank lines and `#` comments are
//! ignored. A key is addressed by its fingerprint, `hex(sha256(vk)[..16])`,
//! which is what trust-services sends (`anchorer.go` `fingerprintOf`).
//!
//! The path comes from the flag, else env `QH_RPC_CALLER_ALLOWLIST` (the
//! container entrypoint does not forward extra flags). Neither set means no
//! allowlist, and every keystore-signing call is refused.

use jsonrpsee::types::error::{ErrorCode, ErrorObject, ErrorObjectOwned};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// Domain tag for Transparence request signatures. See `transparence_message`.
pub const TRANSPARENCE_DOMAIN: &[u8] = b"QH-TRANSPARENCE-RPC-V1";

/// Fingerprint → verifying key.
#[derive(Debug, Default)]
pub struct CallerAllowlist {
    keys: HashMap<String, Vec<u8>>,
}

static INSTALLED: OnceLock<Arc<CallerAllowlist>> = OnceLock::new();

/// Load the allowlist from `--rpc-caller-allowlist` once at startup. An
/// unreadable or empty file is a startup error, not a silently open node.
pub fn install(path: Option<&str>) -> Result<(), String> {
    let list = match path {
        None => {
            log::warn!(
                "🔒 --rpc-caller-allowlist not set: quantumharmony_submitNotarization and \
                 transparence_* will refuse every call"
            );
            CallerAllowlist::default()
        }
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("--rpc-caller-allowlist {p}: {e}"))?;
            let list = CallerAllowlist::parse(&text)
                .map_err(|e| format!("--rpc-caller-allowlist {p}: {e}"))?;
            if list.keys.is_empty() {
                return Err(format!("--rpc-caller-allowlist {p}: no keys"));
            }
            for fp in list.keys.keys() {
                log::info!("🔒 RPC caller allowed: {fp}");
            }
            list
        }
    };
    INSTALLED
        .set(Arc::new(list))
        .map_err(|_| "RPC caller allowlist installed twice".to_string())
}

/// The allowlist `install` loaded, or an empty one if it never ran.
pub fn installed() -> Arc<CallerAllowlist> {
    INSTALLED.get().cloned().unwrap_or_default()
}

pub fn fingerprint(vk: &[u8]) -> String {
    hex::encode(&sp_core::hashing::sha2_256(vk)[..16])
}

impl CallerAllowlist {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut keys = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let vk = hex::decode(line.trim_start_matches("0x"))
                .map_err(|e| format!("line {}: {e}", n + 1))?;
            keys.insert(fingerprint(&vk), vk);
        }
        Ok(Self { keys })
    }

    /// Accept only if `fingerprint` names a listed key and `signature` is that
    /// key's Falcon signature over `message`. Every refusal is logged with the
    /// RPC method and the claimed fingerprint (never the signature), so an
    /// operator can see who was turned away and why.
    pub fn check(
        &self,
        method: &str,
        fingerprint: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ErrorObjectOwned> {
        let deny = |msg: &str| {
            // Caller-supplied: bound it so a request cannot flood the log.
            let fp: String = fingerprint.chars().take(48).collect();
            log::warn!(
                target: "rpc::caller_auth",
                "🔒 refused {method}: {msg} (fingerprint {fp:?})"
            );
            ErrorObject::owned(ErrorCode::InvalidRequest.code(), msg.to_string(), None::<()>)
        };
        if self.keys.is_empty() {
            return Err(deny("caller not authorised: node has no --rpc-caller-allowlist"));
        }
        let vk = self
            .keys
            .get(&fingerprint.to_ascii_lowercase())
            .ok_or_else(|| deny("caller not authorised: unknown signer fingerprint"))?;
        if !paraxiom_pqc::falcon::verify(vk, message, signature) {
            return Err(deny("caller not authorised: bad signature"));
        }
        Ok(())
    }
}

/// Bytes a Transparence caller signs:
///
/// `TRANSPARENCE_DOMAIN ‖ genesis_hash (32) ‖ method (1) ‖ milestone_id (u64 LE) ‖ arg`
///
/// - method 0x01 `recordValidationResult`, arg = `passed` as one byte (0/1)
/// - method 0x02 `recordPaymentAuthorized`, arg = `ceremony_id` (u64 LE)
///
/// The genesis hash keeps a signature for one chain from being replayed on
/// another. Replays on the same chain fail at dispatch (the milestone has
/// already moved state) but still cost the writer a fee.
pub fn transparence_message(genesis: &[u8], method: u8, milestone_id: u64, arg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(TRANSPARENCE_DOMAIN.len() + 32 + 1 + 8 + arg.len());
    m.extend_from_slice(TRANSPARENCE_DOMAIN);
    m.extend_from_slice(genesis);
    m.push(method);
    m.extend_from_slice(&milestone_id.to_le_bytes());
    m.extend_from_slice(arg);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use falcon::safe_api::{DomainSeparation, FnDsaKeyPair};

    fn keypair() -> (Vec<u8>, FnDsaKeyPair) {
        let kp = FnDsaKeyPair::generate(9).unwrap();
        (kp.public_key().to_vec(), kp)
    }

    fn sign(kp: &FnDsaKeyPair, msg: &[u8]) -> Vec<u8> {
        kp.sign(msg, &DomainSeparation::None).unwrap().to_bytes().to_vec()
    }

    #[test]
    fn accepts_listed_key() {
        let (vk, kp) = keypair();
        let list = CallerAllowlist::parse(&format!("# sidecar\n{}\n", hex::encode(&vk))).unwrap();
        let msg = [7u8; 32];
        assert!(list.check("test", &fingerprint(&vk), &msg, &sign(&kp, &msg)).is_ok());
        assert!(list.check("test", &fingerprint(&vk).to_uppercase(), &msg, &sign(&kp, &msg)).is_ok());
    }

    #[test]
    fn refuses_without_allowlist() {
        let (vk, kp) = keypair();
        let msg = [7u8; 32];
        let list = CallerAllowlist::default();
        assert!(list.check("test", &fingerprint(&vk), &msg, &sign(&kp, &msg)).is_err());
    }

    #[test]
    fn refuses_unlisted_key() {
        let (listed, _) = keypair();
        let (vk, kp) = keypair();
        let list = CallerAllowlist::parse(&hex::encode(&listed)).unwrap();
        let msg = [7u8; 32];
        assert!(list.check("test", &fingerprint(&vk), &msg, &sign(&kp, &msg)).is_err());
    }

    #[test]
    fn refuses_listed_fingerprint_with_other_signer() {
        let (vk, _) = keypair();
        let (_, other) = keypair();
        let list = CallerAllowlist::parse(&hex::encode(&vk)).unwrap();
        let msg = [7u8; 32];
        assert!(list.check("test", &fingerprint(&vk), &msg, &sign(&other, &msg)).is_err());
    }

    #[test]
    fn refuses_other_message() {
        let (vk, kp) = keypair();
        let list = CallerAllowlist::parse(&hex::encode(&vk)).unwrap();
        let sig = sign(&kp, &[7u8; 32]);
        assert!(list.check("test", &fingerprint(&vk), &[8u8; 32], &sig).is_err());
    }

    #[test]
    fn transparence_message_binds_every_field() {
        let g = [1u8; 32];
        let base = transparence_message(&g, 0x02, 5, &9u64.to_le_bytes());
        assert_ne!(base, transparence_message(&[2u8; 32], 0x02, 5, &9u64.to_le_bytes()));
        assert_ne!(base, transparence_message(&g, 0x01, 5, &9u64.to_le_bytes()));
        assert_ne!(base, transparence_message(&g, 0x02, 6, &9u64.to_le_bytes()));
        assert_ne!(base, transparence_message(&g, 0x02, 5, &10u64.to_le_bytes()));
    }

    /// Signed by the real transparence-signer sidecar (see the fixture's
    /// _comment). Guards against the sidecar and the node drifting apart on
    /// Falcon key or signature encoding.
    #[test]
    fn verifies_real_sidecar_signature() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/sidecar_falcon512.json")).unwrap();
        let field = |k: &str| hex::decode(f[k].as_str().unwrap()).unwrap();
        let (vk, msg, sig) = (field("vk"), field("msg"), field("sig"));

        let list = CallerAllowlist::parse(f["vk"].as_str().unwrap()).unwrap();
        assert!(list.check("test", &fingerprint(&vk), &msg, &sig).is_ok());

        let mut bad = sig.clone();
        bad[20] ^= 1;
        assert!(list.check("test", &fingerprint(&vk), &msg, &bad).is_err());

        // The fixture signs exactly what the node builds for this request.
        assert_eq!(msg, transparence_message(&[0x11; 32], 0x02, 5, &77u64.to_le_bytes()));
    }

    /// Same vectors as the Go adapter's milestone_releaser_test.go
    /// (transparence-platform-prod, trust-services). Change both or neither.
    #[test]
    fn transparence_message_matches_go_golden_vectors() {
        let prefix = "51482d5452414e53504152454e43452d5250432d5631";
        let genesis = "11".repeat(32);
        assert_eq!(
            hex::encode(transparence_message(&[0x11; 32], 0x02, 5, &77u64.to_le_bytes())),
            format!("{prefix}{genesis}0205000000000000004d00000000000000"),
        );
        assert_eq!(
            hex::encode(transparence_message(&[0x11; 32], 0x01, 5, &[1])),
            format!("{prefix}{genesis}01050000000000000001"),
        );
    }

    #[test]
    fn fingerprint_matches_go_anchorer() {
        // anchorer.go: hex.EncodeToString(sha256.Sum256(pub)[:16])
        assert_eq!(fingerprint(b"abc"), "ba7816bf8f01cfea414140de5dae2223");
    }
}
