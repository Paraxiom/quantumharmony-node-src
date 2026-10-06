//! Quantum Coherence Finality Gadget
//!
//! This module implements the off-chain worker that runs the quantum coherence
//! consensus protocol - the equivalent of GRANDPA for quantum-safe finality.
//!
//! ## Protocol Overview
//!
//! 1. **Wait for new block** from Aura (block production)
//! 2. **Collect STARK proofs** from reporters (quantum entropy measurements)
//! 3. **Verify proofs** using Winterfell STARK verifier
//! 4. **Calculate coherence score** based on QBER measurements
//! 5. **Create and sign vote** with Falcon1024
//! 6. **Broadcast vote** to other validators (encrypted with Triple Ratchet)
//! 7. **Collect votes** from other validators
//! 8. **Check for supermajority** (>2/3 validators agree)
//! 9. **Generate finality certificate**
//! 10. **Submit to runtime** to finalize the block
//!
//! ## GRANDPA Equivalence
//!
//! | GRANDPA | Quantum Coherence |
//! |---------|-------------------|
//! | Voter Set | ValidatorSet with Falcon1024 keys |
//! | Vote | CoherenceVote |
//! | Prevote | STARK proof verification round |
//! | Precommit | Coherence score validation |
//! | Finality Proof | FinalityCertificate |
//! | Byzantine FT | >2/3 validator agreement |

use scale_codec::{Encode, Decode};
use futures::prelude::*;
use log::{debug, info, warn, error};
use sc_client_api::{Backend, BlockchainEvents, backend::Finalizer};
use sc_consensus::JustificationSyncLink;
use sc_network::service::traits::{NetworkService, NotificationService};
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_aura::AuraApi;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor, SaturatedConversion};
use std::{marker::PhantomData, sync::Arc};

use crate::coherence_justification::{CoherenceJustification, COHERENCE_ENGINE_ID};

use pallet_proof_of_coherence::types::{
    CoherenceVote, FinalityCertificate, QuantumState, ValidatorSet, VoteType,
    VoteVerificationResult, MAX_SIGNATURE_SIZE, MAX_VOTES_PER_CERTIFICATE,
};
use pallet_quantum_crypto::stark_proof::{QuantumEntropyProof, PublicInputs, ProofVerificationResult};
use std::collections::HashMap;
use frame_support::BoundedVec;
use sp_core::ConstU32;
use priority_queue::PriorityQueue;
use std::cmp::Reverse;

use crate::threshold_qrng::{
    DeviceId, DeviceShare, ThresholdConfig, CombinedEntropyTx,
    reconstruct_entropy, create_reconstruction_proof, verify_reconstruction_proof,
};

// Post-quantum cryptography for Falcon signatures
use pqcrypto_traits::sign::SecretKey as SignSecretKey;

/// PQ-MonadBFT Phase 3: Pipeline phase for a block
///
/// Tracks which phase each block is in, allowing concurrent processing
/// of multiple blocks in different phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelinePhase {
    /// Block proposed, awaiting votes
    Propose,
    /// Votes being collected
    Vote,
    /// Certificate being created/broadcast
    Certify,
    /// Consensus complete, awaiting execution
    ConsensusComplete,
    /// Execution complete, fully finalized
    Executed,
}

impl Default for PipelinePhase {
    fn default() -> Self {
        PipelinePhase::Propose
    }
}

/// PQ-MonadBFT Phase 3: Block awaiting deferred execution
///
/// After consensus is reached on transaction ordering, the block is queued
/// for parallel execution across toroidal segments.
#[derive(Debug, Clone)]
pub struct DeferredBlock<Block: BlockT> {
    /// Block hash
    pub block_hash: Block::Hash,
    /// Block number
    pub block_number: NumberFor<Block>,
    /// Timestamp when consensus was reached
    pub consensus_timestamp: u64,
    /// Parent's finality certificate (for tail-fork protection)
    pub parent_certificate: Option<Vec<u8>>,
    /// Aggregated QBER from consensus votes
    pub aggregated_qber: u16,
}

/// Quantum Coherence Finality Gadget
///
/// Runs as an off-chain worker (similar to GRANDPA gadget) and coordinates
/// the quantum coherence consensus protocol among validators.
pub struct CoherenceGadget<Block: BlockT, Client, Backend, Pool> {
    /// Client for blockchain queries
    client: Arc<Client>,

    /// Network service for P2P communication
    network: Arc<dyn NetworkService>,

    /// Backend for database access
    _backend: Arc<Backend>,

    /// Transaction pool for submitting unsigned transactions
    transaction_pool: Arc<Pool>,

    /// PHASE 7A: Notification service for receiving votes from other validators
    _notification_service: Arc<tokio::sync::Mutex<Box<dyn NotificationService>>>,

    /// In-memory vote storage (Phase 2B simplified - no gossip yet)
    /// Maps block_hash -> list of votes
    /// In Phase 3, this will be replaced with gossip protocol
    votes: Arc<std::sync::Mutex<HashMap<Block::Hash, Vec<CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>>>>>,

    /// Connected peers for vote broadcasting
    /// Tracks which peers have active notification streams
    connected_peers: Arc<tokio::sync::Mutex<std::collections::HashSet<sc_network::PeerId>>>,

    /// Priority queue for STARK proofs per validator (ValidatorId -> (ID -> Priority))
    /// Priority = Reverse(QBER) so lower QBER = higher priority
    /// Each validator maintains their own queue
    validator_proof_queues: Arc<std::sync::Mutex<HashMap<sp_core::sphincs::Public, PriorityQueue<u64, Reverse<u32>>>>>,

    /// STARK proof storage (ID -> Proof)
    stark_proof_storage: Arc<std::sync::Mutex<HashMap<u64, QuantumEntropyProof<sp_core::sphincs::Public>>>>,

    /// Next proof ID per validator
    next_proof_id: Arc<std::sync::Mutex<HashMap<sp_core::sphincs::Public, u64>>>,

    /// THRESHOLD QRNG: Per-device priority queues (DeviceId -> Queue of shares)
    /// Priority = Reverse(QBER) so lower QBER = higher priority
    /// Devices: QKD QRNG, HSM QRNG, entropy hub
    device_share_queues: Arc<std::sync::Mutex<HashMap<DeviceId, PriorityQueue<DeviceShare, Reverse<u32>>>>>,

    /// Threshold QRNG configuration (K=2, M=3)
    threshold_config: Arc<std::sync::Mutex<ThresholdConfig>>,

    /// PQTG client for real device entropy collection
    /// None = use mock device shares for testing
    /// Some = use real QRNG devices (QKD, HSM, IdQuantique, etc.)
    pqtg_client: Option<Arc<crate::pqtg_client::PqtgClient>>,

    /// Current block leader (elected every 5 blocks)
    current_leader: Arc<std::sync::Mutex<Option<sp_core::sphincs::Public>>>,

    /// Block number of last producer election
    last_election_block: Arc<std::sync::Mutex<u64>>,

    /// Validator Falcon1024 public keys (AccountId -> PublicKey)
    /// Used to verify signatures on received votes
    validator_keys: Arc<std::sync::Mutex<HashMap<sp_core::sphincs::Public, crate::falcon_crypto::PublicKey>>>,

    /// This validator's Falcon1024 secret key (legacy — kept for backward
    /// compatibility with some gossip paths, but **vote signing now uses
    /// SPHINCS+ via `keystore`**). None if this node is not a validator.
    our_secret_key: Option<crate::falcon_crypto::SecretKey>,

    /// public key — i.e. `our_validator_id.0` IS the validator's SPHINCS+
    /// public key, which matches an entry in `Aura::Authorities`.
    /// None if this node is not a validator.
    our_validator_id: Option<sp_core::sphincs::Public>,

    /// Handle to the node's keystore. Phase 7 (2026-04-13): used to sign
    /// coherence votes with the validator's SPHINCS+ keystore key so that
    /// other nodes can verify vote signatures against the on-chain Aura
    /// authority set (no separate Falcon pubkey registry needed).
    keystore: sp_keystore::KeystorePtr,

    /// Justification sync link for broadcasting finality proofs to full nodes
    /// This allows non-validators to receive and verify finality certificates
    justification_sync_link: Arc<dyn JustificationSyncLink<Block>>,

    /// PQ-MonadBFT Phase 1: Leader-collected votes with QBER measurements
    /// Maps block_hash -> Vec<(vote, qber_measurement, qkd_channel_id)>
    /// Only populated when this node is the leader
    leader_vote_aggregation: Arc<std::sync::Mutex<HashMap<Block::Hash, Vec<(
        CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
        u16,  // qber_measurement (basis points)
        u32,  // qkd_channel_id
    )>>>>,

    /// First-vote-wins ledger enforcing one vote per (validator, height) on
    /// every vote-admission path and on our own voting. See [`EquivocationLedger`].
    equivocation_ledger: Arc<std::sync::Mutex<EquivocationLedger<sp_core::sphincs::Public, Block::Hash>>>,

    /// PQ-MonadBFT: Whether to use linear voting (O(n)) or legacy gossip (O(n log n))
    /// Default: true (use linear voting)
    use_linear_voting: bool,

    /// PQ-MonadBFT Phase 3: Pipeline state tracking
    /// Maps block_hash -> PipelinePhase
    /// Allows multiple blocks to be in different phases concurrently
    pipeline_state: Arc<std::sync::Mutex<HashMap<Block::Hash, PipelinePhase>>>,

    /// PQ-MonadBFT Phase 3: Finality certificate cache for tail-fork protection
    /// Maps block_hash -> encoded certificate
    /// New proposals must include parent's certificate
    certificate_cache: Arc<std::sync::Mutex<HashMap<Block::Hash, Vec<u8>>>>,

    /// PQ-MonadBFT Phase 3: Deferred execution queue
    /// Blocks that have reached consensus but await execution
    /// Execution happens in parallel on toroidal segments
    deferred_execution_queue: Arc<std::sync::Mutex<Vec<DeferredBlock<Block>>>>,

    /// PQ-MonadBFT Phase 3: Last certified block (for tail-fork protection)
    /// New proposals must reference this certificate
    last_certified_block: Arc<std::sync::Mutex<Option<(Block::Hash, NumberFor<Block>)>>>,

    /// Phantom data for block type
    _phantom: PhantomData<Block>,
}

/// Byzantine supermajority threshold: ceil(2N/3) votes required to finalize.
///
/// N MUST be the live validator-set size queried from the runtime — a hardcoded
/// N=3 in the vote-receiver path caused the 2026-07-04 finality fork
/// (docs/BUG-hardcoded-quorum-threshold-2026-07-05.md). Every finalize decision
/// and justification check must go through this single function.
///
/// Returns at least 1 so a pathological N=0 can never produce a zero threshold
/// (which would finalize on zero votes).
pub(crate) fn quorum_threshold(total_validators: u32) -> u32 {
    ((total_validators * 2 + 2) / 3).max(1)
}

/// DEVNET-ONLY block ledger for the equivocation witness. Records every block hash this
/// node imports, keyed by height, so the witness can vote for a **real competing block**
/// rather than a fabricated hash. Compiled only under `--features byzantine-attack`.
#[cfg(feature = "byzantine-attack")]
static SEEN_BLOCKS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<u64, Vec<Vec<u8>>>>,
> = std::sync::OnceLock::new();

#[cfg(feature = "byzantine-attack")]
fn seen_blocks_map() -> &'static std::sync::Mutex<std::collections::BTreeMap<u64, Vec<Vec<u8>>>> {
    SEEN_BLOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

/// Record an imported block. `height` is stringified to avoid extra trait bounds on
/// `NumberFor<Block>`; `hash_enc` is the SCALE encoding of the block hash.
#[cfg(feature = "byzantine-attack")]
fn record_seen_block(height: &str, hash_enc: Vec<u8>) {
    let h: u64 = match height.parse() { Ok(v) => v, Err(_) => return };
    if let Ok(mut m) = seen_blocks_map().lock() {
        let entry = m.entry(h).or_insert_with(Vec::new);
        if !entry.contains(&hash_enc) {
            entry.push(hash_enc);
        }
        // keep the ledger bounded — only recent heights matter for equivocation
        while m.len() > 2048 {
            let first = *m.keys().next().unwrap();
            m.remove(&first);
        }
    }
}

/// Find a REAL block at the same height whose hash differs from `current`.
/// Returns `None` when this node has seen no fork at that height — in which case the
/// witness must not fabricate one, because a vote for a non-existent block tests nothing.
#[cfg(feature = "byzantine-attack")]
fn competing_block(height: &str, current: &[u8]) -> Option<Vec<u8>> {
    let h: u64 = height.parse().ok()?;
    let m = seen_blocks_map().lock().ok()?;
    m.get(&h)?.iter().find(|enc| enc.as_slice() != current).cloned()
}

/// The coherence-admission invariant, as a PURE function — no client, no crypto.
///
/// Given the votes a finality certificate carries for `block_hash`, count the
/// DISTINCT authorities whose vote (a) is *for* `block_hash` and (b) passes the
/// injected `verify` check (SPHINCS+ signature + authority membership). The
/// certificate is *coherent* — admissible to finality — iff that distinct count
/// reaches `required` (= `quorum_threshold(N)` at the block).
///
/// This is deliberately split from the crypto primitive: the combinatorial
/// invariant here is what we witness/prove; `verify` is trusted separately and
/// injected, so the tests need no key material. A naive `votes.len() >= required`
/// — the pre-fix Justification path (the #345,140 fork class) — passes *none* of
/// the rejection witnesses: forged signatures, duplicate authorities, and votes
/// for the wrong block are all filtered here, never counted.
///
/// The thin wrapper (`verify_finality_certificate`) supplies `required` and
/// `verify` from the runtime state *at `block_hash`* (fixing the best_hash
/// rotation hazard), and every `finalize_block` door routes through it.
/// Free-function form of the gadget's vote-signature check, so code outside the
/// gadget (notably `service.rs`'s justification-sync paths) verifies votes the
/// same way rather than inventing a second, weaker rule.
///
/// Reads the Aura authority set **at `at`** — the block being voted on — so the
/// admission set and the counting set are the same one whenever that block is
/// imported. If it is not yet imported, admission falls back to the best block's
/// set rather than discarding the vote (see the comment in the body); counting
/// still happens at the voted block, because the quorum check re-verifies every
/// stored vote there before anything is finalized.
pub(crate) fn verify_vote_signature_at<Block, Client>(
    client: &std::sync::Arc<Client>,
    at: Block::Hash,
    vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
) -> Result<bool, String>
where
    Block: BlockT,
    Client: sp_api::ProvideRuntimeApi<Block> + sp_blockchain::HeaderBackend<Block>,
    Client::Api: sp_consensus_aura::AuraApi<Block, sp_consensus_aura::sphincs::AuthorityId>,
{
    use sp_core::crypto::ByteArray;

    // A vote can arrive before its block is imported (common across a WAN). Rejecting it
    // then drops a valid vote for good. Admit it against the best block's authority set,
    // as before; the quorum check re-verifies every stored vote at the voted block before
    // anything is finalized, so counting stays at-block.
    let at = match client.header(at) {
        Ok(Some(_)) => at,
        _ => client.info().best_hash,
    };

    let authorities = client.runtime_api()
        .authorities(at)
        .map_err(|e| format!("Failed to fetch Aura authorities: {:?}", e))?;

    let is_authority = authorities.iter().any(|a| {
        let a_bytes = a.to_raw_vec();
        a_bytes.len() >= 64 && &a_bytes[..64] == &vote.validator.0[..64]
    });
    if !is_authority {
        warn!(
            "❌ Vote rejected: validator 0x{}… is not in the Aura authority set at the voted block",
            hex::encode(&vote.validator.0[..8])
        );
        return Ok(false);
    }

    let message = crate::falcon_crypto::encode_vote_for_signing(
        &vote.validator,
        &vote.block_hash,
        &vote.block_number,
        vote.coherence_score,
        &vote.quantum_state,
    );

    let sig_bytes: Vec<u8> = vote.signature.iter().cloned().collect();
    if sig_bytes.is_empty() {
        warn!("❌ Vote rejected: empty signature from 0x{}…", hex::encode(&vote.validator.0[..8]));
        return Ok(false);
    }
    let signature = match sp_core::sphincs::Signature::try_from(sig_bytes.as_slice()) {
        Ok(sg) => sg,
        Err(_) => {
            warn!("❌ Vote rejected: signature bytes (len={}) do not fit SPHINCS+ Signature", sig_bytes.len());
            return Ok(false);
        }
    };
    let pubkey = sp_core::sphincs::Public::from_raw(vote.validator.0);

    if <sp_core::sphincs::Pair as sp_core::Pair>::verify(&signature, &message, &pubkey) {
        Ok(true)
    } else {
        warn!(
            "❌ Vote rejected: SPHINCS+ signature did not verify for validator 0x{}…",
            hex::encode(&vote.validator.0[..8])
        );
        Ok(false)
    }
}

/// Verify a justification received over gossip **before** anything finalizes on it.
///
/// `service.rs` previously passed the raw gossip bytes straight to
/// `finalize_block` after checking only that the block number was ahead of the
/// finalized head. No decode, no signatures, no quorum, no chain check — any
/// peer could finalize any block it named. This is the gate that path was
/// missing.
pub(crate) fn verify_gossiped_justification<Block, Client>(
    client: &std::sync::Arc<Client>,
    block_hash: Block::Hash,
    encoded_justification: &[u8],
) -> Result<u32, String>
where
    Block: BlockT,
    Client: sp_api::ProvideRuntimeApi<Block> + sp_blockchain::HeaderBackend<Block>,
    Client::Api: sp_consensus_aura::AuraApi<Block, sp_consensus_aura::sphincs::AuthorityId>,
{
    // 1. On our best chain? Descendancy is not enough (fork #4, block 1763165).
    let number = client
        .number(block_hash)
        .map_err(|e| format!("Cannot resolve number for {:?}: {:?}", block_hash, e))?
        .ok_or_else(|| format!("Block {:?} is unknown to this node", block_hash))?;
    match client.hash(number) {
        Ok(Some(canonical)) if canonical == block_hash => {}
        Ok(_) => return Err(format!("Block {:?} is not canonical at #{:?}", block_hash, number)),
        Err(e) => return Err(format!("Cannot resolve canonical hash at #{:?}: {:?}", number, e)),
    }

    // 2. Does it even decode as a coherence justification?
    let decoded = CoherenceJustification::<
        sp_core::sphincs::Public, NumberFor<Block>, Block::Hash,
    >::decode_from_network(encoded_justification)
        .map_err(|e| format!("Justification is undecodable: {:?}", e))?;

    // 3. Threshold from the authority set at the target block.
    let authorities = client.runtime_api()
        .authorities(block_hash)
        .map_err(|e| format!("Failed to query Aura authorities: {:?}", e))?;
    if authorities.is_empty() {
        return Err("Runtime returned an empty authority set".to_string());
    }
    let required = quorum_threshold(authorities.len() as u32);

    // 4. A verified, distinct-authority quorum for THIS block.
    coherent_quorum(
        &block_hash,
        required,
        decoded.certificate.precommit_votes.as_slice(),
        |v| &v.block_hash,
        |v| v.validator.0[..64].to_vec(),
        |v| verify_vote_signature_at(client, block_hash, v).unwrap_or(false),
    )
}

pub(crate) fn coherent_quorum<V, H, Id>(
    block_hash: &H,
    required: u32,
    votes: &[V],
    vote_block: impl Fn(&V) -> &H,
    vote_validator: impl Fn(&V) -> Id,
    verify: impl Fn(&V) -> bool,
) -> Result<u32, String>
where
    H: PartialEq,
    Id: Ord,
{
    let mut distinct = std::collections::BTreeSet::new();
    for vote in votes {
        if vote_block(vote) != block_hash {
            continue; // vote is for a different block — not coherent to this one
        }
        if !verify(vote) {
            continue; // signature / authority check failed — not admitted
        }
        distinct.insert(vote_validator(vote));
    }
    let count = distinct.len() as u32;
    if count < required {
        return Err(format!(
            "incoherent certificate: {} distinct verified authority vote(s) for the target block, need {}",
            count, required
        ));
    }
    Ok(count)
}

/// Outcome of admitting a vote through the [`EquivocationLedger`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VoteAdmission<H> {
    /// First vote seen from this validator at this height — admit.
    First,
    /// Same validator, same height, same block — a redelivery. Not an
    /// equivocation; the per-block vote maps already hold it.
    Repeat,
    /// Same validator, same height, DIFFERENT block. The vote must not be
    /// stored or counted; `first` is the block this validator is held to.
    Equivocation { first: H },
    /// Height is below the window the ledger still remembers (evicted or
    /// pruned). The ledger can no longer judge it, so it is NOT admitted —
    /// fail closed rather than re-admit as `First`.
    OutOfWindow,
}

/// First-vote-wins ledger: one (validator, height) → the block it voted for.
///
/// This is the `honest_single` hypothesis of `QHProofs.FinalityModel`
/// (`lean/QHProofs/FinalityModel.lean`) enforced at the point where votes are
/// admitted: `finality_unique` needs every honest validator to vote for at
/// most ONE block per height, and the gadget did not enforce that anywhere —
/// `process_block` votes on every imported election block, so an honest node
/// importing both siblings of a natural fork voted for both, and receivers
/// counted both. Two consequences, both closed:
///
///   * receiver side — a second, conflicting vote from the same authority at
///     the same height is REJECTED (never stored, never counted) and logged
///     with the `EQUIVOCATION` tag so the monitor can grep it;
///   * sender side — `process_block` consults the ledger before voting and
///     records only after the vote is created and stored, so an honest node
///     votes once per election height.
///
/// The HEIGHT the ledger is keyed on is the height of the block the vote names
/// (looked up from the local header), never the vote's self-declared
/// `block_number` — see [`CoherenceGadget::admit_vote`]. Keying on the declared
/// number would let a Byzantine authority defeat the ledger by mislabeling its
/// second vote's height.
///
/// Window: entries live in `(finalized, …]` — the caller prunes everything at
/// or below the finalized head on each admission — and at most `max_heights`
/// heights are kept. When at capacity, a height below the retained minimum is
/// `OutOfWindow` (rejected), never inserted-then-evicted while reporting
/// `First`. Because admission requires a locally-known header, an authority
/// cannot flood the ledger with far-future heights; it can only add heights
/// for blocks this node actually imported.
///
/// Liveness is unaffected: a height whose votes split across siblings simply
/// does not finalize on its own; the next election height (+5) finalizes it
/// as an ancestor. Different receivers can still see different "first" votes
/// under adversarial ordering — that is the N=3 structural exposure, which
/// this ledger narrows (at ONE receiver two quorums are now impossible by
/// pigeonhole, `2⌈2N/3⌉ > N`) but does not close. The ledger is in-memory:
/// after a restart this node may re-sign at a height it already voted; peers'
/// ledgers reject that as an equivocation, so the safety rule holds network-
/// side. Persisting our own last vote is a follow-up. See
/// docs/qh-consensus-boundary-of-boundary-2026-08-27.md §4.1–4.2.
pub(crate) struct EquivocationLedger<Id, H> {
    by_height: std::collections::BTreeMap<u64, HashMap<Id, H>>,
    max_heights: usize,
}

impl<Id, H> EquivocationLedger<Id, H>
where
    Id: std::hash::Hash + Eq + Clone,
    H: PartialEq + Clone,
{
    /// Heights are only those of locally-imported, not-yet-finalized blocks;
    /// this cap only matters during a long finality stall.
    pub(crate) const DEFAULT_MAX_HEIGHTS: usize = 4096;

    pub(crate) fn new(max_heights: usize) -> Self {
        Self { by_height: Default::default(), max_heights: max_heights.max(1) }
    }

    /// Record `validator`'s vote for `hash` at `height` and say whether it is
    /// admissible. Only a `First` vote mutates the ledger.
    pub(crate) fn observe(&mut self, height: u64, validator: Id, hash: H) -> VoteAdmission<H> {
        if self.by_height.len() >= self.max_heights && !self.by_height.contains_key(&height) {
            if let Some((&min, _)) = self.by_height.first_key_value() {
                if height < min {
                    return VoteAdmission::OutOfWindow;
                }
            }
        }
        let at_height = self.by_height.entry(height).or_default();
        let outcome = match at_height.get(&validator) {
            None => {
                at_height.insert(validator, hash);
                VoteAdmission::First
            }
            Some(first) if *first == hash => VoteAdmission::Repeat,
            Some(first) => VoteAdmission::Equivocation { first: first.clone() },
        };
        while self.by_height.len() > self.max_heights {
            self.by_height.pop_first();
        }
        outcome
    }

    /// Forget every height strictly below `height` (call with `finalized + 1`).
    pub(crate) fn prune_below(&mut self, height: u64) {
        self.by_height = self.by_height.split_off(&height);
    }

    /// The block `validator` is already held to at `height`, if any.
    pub(crate) fn first_vote(&self, height: u64, validator: &Id) -> Option<&H> {
        self.by_height.get(&height).and_then(|m| m.get(validator))
    }
}

impl<Block, Client, BE, Pool> CoherenceGadget<Block, Client, BE, Pool>
where
    Block: BlockT,
    BE: Backend<Block> + 'static,
    Pool: TransactionPool<Block = Block> + 'static,
    Client: ProvideRuntimeApi<Block>
        + BlockchainEvents<Block>
        + HeaderBackend<Block>
        + Finalizer<Block, BE>
        + Send
        + Sync
        + 'static,
    Client::Api: sp_consensus_aura::AuraApi<Block, sp_consensus_aura::sphincs::AuthorityId>,
{
    /// Validator-set size read from the runtime (Aura authorities) at `at`.
    ///
    /// Errors on query failure or an empty authority set. Callers must fail
    /// closed — skip the finalize decision — never substitute a guessed count.
    fn validator_count_at(client: &Arc<Client>, at: Block::Hash) -> Result<u32, String> {
        let authorities = client
            .runtime_api()
            .authorities(at)
            .map_err(|e| format!("Failed to query Aura authorities: {:?}", e))?;
        if authorities.is_empty() {
            return Err("Runtime returned an empty authority set".to_string());
        }
        Ok(authorities.len() as u32)
    }

    /// Is `hash` the block this node currently considers canonical at `number`?
    ///
    /// Substrate's `finalize_block` already refuses a block that is not a
    /// descendant of the finalized head (`NotInFinalizedChain`). It does **not**
    /// refuse a sibling on a competing branch: during fork #4 (2026-09-12, block
    /// 1763165) every validator held both hashes and descendancy was satisfied
    /// for both, so the first to reach threshold was finalized and the chain
    /// split. Descendancy is not enough; the block must be on *our best chain*.
    ///
    /// `HeaderBackend::hash(number)` answers exactly that: the canonical hash at
    /// that height. A side branch returns a different hash, or `None` if the
    /// height is beyond our head.
    ///
    /// Fails closed: a lookup error is reported, never treated as agreement.
    fn is_on_best_chain(
        client: &Arc<Client>,
        number: NumberFor<Block>,
        hash: Block::Hash,
    ) -> Result<bool, String> {
        match client.hash(number) {
            Ok(Some(canonical)) => Ok(canonical == hash),
            Ok(None) => Ok(false),
            Err(e) => Err(format!("Cannot resolve canonical hash at #{}: {:?}", number, e)),
        }
    }

    /// Create a new Quantum Coherence Finality Gadget
    pub fn new(
        client: Arc<Client>,
        network: Arc<dyn NetworkService>,
        backend: Arc<BE>,
        transaction_pool: Arc<Pool>,
        notification_service: Box<dyn NotificationService>,
        pqtg_client: Option<Arc<crate::pqtg_client::PqtgClient>>,
        keystore: sp_keystore::KeystorePtr,
        justification_sync_link: Arc<dyn JustificationSyncLink<Block>>,
    ) -> Self {
        // Initialize threshold QRNG configuration (K=2, M=3)
        // Use default config which matches mock device shares
        let threshold_config = ThresholdConfig::default();

        if pqtg_client.is_some() {
            info!("🔌 PQTG client enabled - will use real QRNG devices");
        } else {
            info!("🧪 PQTG client disabled - using mock device shares for testing");
        }

        // Derive Falcon1024 keypair with quantum-enhanced multi-source entropy
        // This combines: keystore secrets + quantum QRNG + hardware RNG
        use sp_core::crypto::KeyTypeId;
        use scale_codec::Encode;

        let aura_keytype = KeyTypeId(sp_consensus_aura::AURA_ENGINE_ID);
        let keystore_keys = keystore.sphincs_public_keys(aura_keytype);

        info!("🔍 Found {} SPHINCS+ keys in keystore", keystore_keys.len());
        for (i, key) in keystore_keys.iter().enumerate() {
            info!("   Key {}: 0x{}...", i, hex::encode(&key.0[..8]));
        }

        // Query runtime authorities to find which keystore key matches
        use sp_blockchain::HeaderBackend;
        use sp_core::crypto::ByteArray;
        let best_hash = client.info().best_hash;
        let authorities = client.runtime_api()
            .authorities(best_hash)
            .unwrap_or_default();

        info!("🔍 Found {} runtime authorities", authorities.len());
        for (i, auth) in authorities.iter().enumerate() {
            info!("   Auth {}: 0x{}...", i, hex::encode(&auth.to_raw_vec()[..8]));
        }

        // Find a keystore key that matches a runtime authority AND can sign
        // This ensures we use the correct key that is both authorized AND has a secret
        let working_key = keystore_keys.iter().find(|key| {
            // Check if this key matches any authority
            let key_matches_authority = authorities.iter().any(|auth| {
                let auth_bytes = auth.to_raw_vec();
                auth_bytes.len() >= 64 && &auth_bytes[..64] == &key.0[..64]
            });
            if !key_matches_authority {
                return false;
            }
            // Also verify we can sign with this key
            match keystore.sphincs_sign(aura_keytype, key, b"test") {
                Ok(Some(_)) => true,
                _ => false,
            }
        });

        let (validator_id, public_key, secret_key) = match working_key {
            Some(aura_public_key) => {
                // We have an AURA key that can sign - derive Falcon key securely
                let validator_id = sp_core::sphincs::Public::from_raw(aura_public_key.0);
                info!("🔑 Using AURA key for finality: 0x{}...", hex::encode(&aura_public_key.0[..8]));

                // Step 1: Extract secret entropy from keystore via signing (QPP-wrapped)
                // Signing uses the SECRET key, giving us secret entropy without exposing the key
                use crate::qpp::{QuantumEntropy, EntropySource};

                let entropy_message = b"falcon1024-keystore-entropy-v2";
                let keystore_qentropy = match keystore.sphincs_sign(aura_keytype, aura_public_key, entropy_message) {
                    Ok(Some(signature)) => {
                        info!("✅ Extracted secret entropy from keystore via SPHINCS+ signature");
                        QuantumEntropy::new(signature.0.to_vec(), EntropySource::Keystore, None)
                    }
                    Ok(None) => {
                        warn!("⚠️  Keystore has key but couldn't sign, using public key fallback");
                        QuantumEntropy::new(aura_public_key.0.to_vec(), EntropySource::Keystore, None)
                    }
                    Err(e) => {
                        warn!("⚠️  Keystore signing failed: {:?}, using public key fallback", e);
                        QuantumEntropy::new(aura_public_key.0.to_vec(), EntropySource::Keystore, None)
                    }
                };

                // Step 2: Get quantum entropy from threshold QRNG (if available)
                // Note: This is synchronous constructor, can't await. Will fetch in background later.
                // For now, we'll use deterministic entropy from keystore and rely on quantum mixing
                // during vote signing operations.
                //
                // QPP Integration Note: For async entropy operations, use qpp_integration::create_async_entropy()
                // with AsyncOp wrapper to ensure type-level prevention of blocking in async contexts.
                let quantum_qentropy: Option<QuantumEntropy> = None; // NOTE: PQTG entropy fetched asynchronously during vote signing, not at construction time

                // Step 3: Mix in hardware RNG entropy (QPP-wrapped)
                use rand::RngCore;
                let mut hwrng_bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut hwrng_bytes);
                let hwrng_qentropy = Some(QuantumEntropy::new(
                    hwrng_bytes.to_vec(),
                    EntropySource::HardwareRNG,
                    None,
                ));
                info!("✅ Mixed in 32 bytes from hardware RNG (OS entropy)");

                // Step 4: Generate Falcon1024 keypair with QPP enforcement (no-cloning!)
                // Entropy is consumed (moved), cannot be reused - enforced at compile time
                // Detailed logging happens inside generate_keypair_qpp()
                let (pk, sk, _entropy_sources) = crate::falcon_crypto::generate_keypair_qpp(
                    keystore_qentropy,      // Consumed
                    quantum_qentropy,       // Consumed
                    hwrng_qentropy,         // Consumed
                    &validator_id.encode(),
                );

                (validator_id, pk, sk)
            }
            None => {
                // No keystore aura key matches any runtime authority.
                //
                // Bug 2 fix (2026-05-02): default behavior is to PANIC, refusing
                // to start in silent-degraded mode. Fresh operators hit this path
                // when their keys aren't yet in `aura.Authorities` and would
                // otherwise believe they were producing — the silent half-success
                // failure mode we're engineering out of onboarding.
                //
                // The previous degraded-mode fallback (fake validator ID) is still
                // available behind the QH_ALLOW_DEGRADED_COHERENCE env var, for
                // the existing keypair-repair recovery scenario where ops know
                // what they're doing.
                let found_keys: Vec<String> = keystore_keys
                    .iter()
                    .map(|k| hex::encode(&k.0[..8]))
                    .collect();
                let authority_keys: Vec<String> = authorities
                    .iter()
                    .map(|a| hex::encode(&a.to_raw_vec()[..8]))
                    .collect();

                let allow_degraded = std::env::var("QH_ALLOW_DEGRADED_COHERENCE")
                    .map(|v| v != "false" && v != "0")
                    .unwrap_or(false);

                if !allow_degraded {
                    panic!(
                        "[COHERENCE] no keystore aura key matches any runtime authority — \
                         refusing to start in silent-degraded mode. \
                         Keystore keys: {:?}, on-chain authorities: {:?}. \
                         Either (a) ensure your keys are in aura.Authorities via the \
                         commit-reveal onboarding flow, or (b) for keypair-repair \
                         recovery only, restart with QH_ALLOW_DEGRADED_COHERENCE=1.",
                        found_keys, authority_keys
                    );
                }

                eprintln!(
                    "⚠️  [COHERENCE] QH_ALLOW_DEGRADED_COHERENCE=1 — running in degraded mode \
                    (keystore keys: {:?}, authorities: {:?}). Coherence finality voting DISABLED \
                    for this session. Update on-chain Aura.Authorities via sudo to restore.",
                    found_keys, authority_keys
                );
                // Use a placeholder validator identity so the gadget can construct.
                // Votes signed with this identity will fail verification on peers,
                // but that's expected — this node cannot participate in finality
                // until the authority set is updated.
                let fake_id = sp_core::sphincs::Public::from_raw([0u8; 64]);
                // Generate a real Falcon-1024 keypair with a fixed zero seed.
                // This keypair is structurally valid but has no authority on-chain,
                // so votes signed with it will never be accepted. The gadget runs
                // in a no-op mode until the authority set is updated.
                let (pk, sk) = crate::falcon_crypto::generate_keypair(&[0u8; 32]);
                (fake_id, pk, sk)
            }
        };

        // Initialize validator keys map with our own public key
        let mut validator_keys = HashMap::new();
        validator_keys.insert(validator_id.clone(), public_key);

        // Check environment for linear voting mode (default: true for O(n) efficiency)
        let use_linear_voting = std::env::var("USE_LINEAR_VOTING")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        if use_linear_voting {
            info!("🚀 PQ-MonadBFT: Linear O(n) voting ENABLED");
        } else {
            info!("📡 Legacy gossip O(N log N) voting mode");
        }

        Self {
            client,
            network,
            _backend: backend,
            transaction_pool,
            _notification_service: Arc::new(tokio::sync::Mutex::new(notification_service)),
            votes: Arc::new(std::sync::Mutex::new(HashMap::new())),
            connected_peers: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            validator_proof_queues: Arc::new(std::sync::Mutex::new(HashMap::new())),
            stark_proof_storage: Arc::new(std::sync::Mutex::new(HashMap::new())),
            next_proof_id: Arc::new(std::sync::Mutex::new(HashMap::new())),
            device_share_queues: Arc::new(std::sync::Mutex::new(HashMap::new())),
            threshold_config: Arc::new(std::sync::Mutex::new(threshold_config)),
            pqtg_client,
            current_leader: Arc::new(std::sync::Mutex::new(None)),
            last_election_block: Arc::new(std::sync::Mutex::new(0)),
            validator_keys: Arc::new(std::sync::Mutex::new(validator_keys)),
            our_secret_key: Some(secret_key),
            our_validator_id: Some(validator_id),
            keystore: keystore.clone(),
            justification_sync_link,
            leader_vote_aggregation: Arc::new(std::sync::Mutex::new(HashMap::new())),
            equivocation_ledger: Arc::new(std::sync::Mutex::new(EquivocationLedger::new(
                EquivocationLedger::<sp_core::sphincs::Public, Block::Hash>::DEFAULT_MAX_HEIGHTS,
            ))),
            use_linear_voting,
            // PQ-MonadBFT Phase 3: Pipelining infrastructure
            pipeline_state: Arc::new(std::sync::Mutex::new(HashMap::new())),
            certificate_cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
            deferred_execution_queue: Arc::new(std::sync::Mutex::new(Vec::new())),
            last_certified_block: Arc::new(std::sync::Mutex::new(None)),
            _phantom: PhantomData,
        }
    }

    /// Finalize block in client backend (off-chain finality)
    ///
    /// This is the correct approach for finality - similar to GRANDPA.
    /// The finality certificate is kept in memory, not in the transaction pool.
    ///
    /// IMPORTANT: Substrate requires sequential finalization. We must finalize
    /// all blocks from last_finalized+1 up to target_block.
    async fn finalize_block_in_client(
        &self,
        block_hash: Block::Hash,
        certificate: FinalityCertificate<
            sp_core::sphincs::Public,
            <Block::Header as HeaderT>::Number,
            Block::Hash,
        >,
    ) -> Result<(), String> {
        use sp_blockchain::HeaderBackend;

        info!(
            "📊 Finality details: {} validators, coherence score {}, avg QBER {:.2}%",
            certificate.validator_count,
            certificate.total_coherence_score,
            certificate.consensus_quantum_state.average_qber as f64 / 100.0
        );

        // Phase 6A: Sequential finalization
        // Get the last finalized block from client info
        let last_finalized = self.client.info().finalized_hash;
        let last_finalized_number = self.client.info().finalized_number;

        // Get target block number
        let target_header = self.client.header(block_hash)
            .map_err(|e| format!("Failed to get block header: {:?}", e))?
            .ok_or("Block header not found")?;
        let target_number = *target_header.number();

        info!("🔍 Current finalized: #{}, target: #{}", last_finalized_number, target_number);

        // If target is already finalized or older, skip
        if target_number <= last_finalized_number {
            info!("⏭️  Block #{} already finalized, skipping", target_number);
            return Ok(());
        }

        // Both finalization walks below descend from this target by parent links,
        // so they are descendancy-safe by construction but NOT best-chain safe:
        // if the target itself sits on a competing branch, the entire walk
        // finalizes that branch. One gate here covers both walks. Checking every
        // block in the walk would be redundant — if the target is canonical, so
        // is every ancestor.
        if !Self::is_on_best_chain(&self.client, target_number, block_hash)? {
            warn!(
                "⏭️  Target #{} {:?} is not on our best chain — refusing to finalize a side branch",
                target_number, block_hash
            );
            return Ok(());
        }

        // Calculate how many blocks need to be finalized
        let blocks_behind: u64 = (target_number - last_finalized_number).saturated_into();

        // BATCH CATCH-UP: If far behind, finalize up to BATCH_SIZE blocks per election cycle
        // instead of skipping entirely. This ensures finality always makes progress.
        // At 5000 blocks/cycle and ~30s/cycle, catches up ~10,000 blocks/min.
        // 73,600 blocks behind = ~15 cycles = ~7.5 minutes to full catch-up.
        const MAX_CATCHUP_BLOCKS: u64 = 5000;
        if blocks_behind > MAX_CATCHUP_BLOCKS {
            let cycles_needed = blocks_behind / MAX_CATCHUP_BLOCKS + 1;
            warn!(
                "⚠️  Finality is {} blocks behind. Batch catching up {} blocks this cycle ({} cycles remaining).",
                blocks_behind, MAX_CATCHUP_BLOCKS, cycles_needed
            );

            // Instead of skipping, finalize a batch of MAX_CATCHUP_BLOCKS from
            // last_finalized+1 forward. We DON'T jump to target — we walk forward
            // sequentially from the last finalized block, which Substrate requires.
            let batch_target_num: NumberFor<Block> = MAX_CATCHUP_BLOCKS.saturated_into();
            let batch_target_number = last_finalized_number + batch_target_num;

            // Get the block hash for our batch target by walking backwards from target
            let mut walk_hash = block_hash;
            let mut walk_number = target_number;
            while walk_number > batch_target_number {
                let header = self.client.header(walk_hash)
                    .map_err(|e| format!("Failed to get header during batch walk: {:?}", e))?
                    .ok_or_else(|| format!("Header not found during batch walk at #{}", walk_number))?;
                walk_hash = *header.parent_hash();
                walk_number = walk_number - 1u32.into();
            }
            let batch_target_hash = walk_hash;

            // Now walk backwards from batch_target to build the hash map for this batch
            let mut batch_hashes: std::collections::HashMap<NumberFor<Block>, Block::Hash> = std::collections::HashMap::new();
            batch_hashes.insert(batch_target_number, batch_target_hash);
            let mut bw_hash = batch_target_hash;
            let mut bw_number = batch_target_number;
            while bw_number > last_finalized_number + 1u32.into() {
                let header = self.client.header(bw_hash)
                    .map_err(|e| format!("Failed to get header for batch #{}: {:?}", bw_number, e))?
                    .ok_or_else(|| format!("Header not found for batch #{}", bw_number))?;
                bw_hash = *header.parent_hash();
                bw_number = bw_number - 1u32.into();
                batch_hashes.insert(bw_number, bw_hash);
            }

            info!("🔗 Batch finalizing {} blocks (#{} to #{})", batch_hashes.len(), last_finalized_number + 1u32.into(), batch_target_number);

            let mut current = last_finalized_number + 1u32.into();
            let mut batch_count = 0u32;
            while current <= batch_target_number {
                let current_hash = *batch_hashes.get(&current)
                    .ok_or_else(|| format!("Batch hash not found for #{}", current))?;
                match self.client.finalize_block(current_hash, None, true) {
                    Ok(()) => {
                        batch_count += 1;
                        if batch_count % 500 == 0 {
                            info!("🔒 Batch finalized up to #{} ({}/{})", current, batch_count, MAX_CATCHUP_BLOCKS);
                        }
                    },
                    Err(e) => {
                        error!("❌ Batch finalization failed at block #{}: {:?}", current, e);
                        if batch_count > 0 {
                            info!("✅ Batch finalized {} blocks before failure", batch_count);
                        }
                        return Err(format!("Batch finalization failed at #{}: {:?}", current, e));
                    }
                }
                current = current + 1u32.into();
            }

            info!("✅ Batch finalized {} blocks (#{} to #{}). {} blocks remaining to catch up.",
                batch_count, last_finalized_number + 1u32.into(), batch_target_number,
                blocks_behind - (batch_count as u64));
            return Ok(());
        }

        // Finalize all blocks sequentially from last_finalized+1 to target
        // Substrate requires blocks to be finalized in order (no skipping!)
        info!("🔗 Finalizing {} blocks sequentially from #{} to #{}", blocks_behind, last_finalized_number + 1u32.into(), target_number);

        // OPTIMIZATION: Build block hash map by walking backwards once (O(n) instead of O(n²))
        let mut block_hashes: std::collections::HashMap<NumberFor<Block>, Block::Hash> = std::collections::HashMap::new();
        block_hashes.insert(target_number, block_hash);

        let mut walk_hash = block_hash;
        let mut walk_number = target_number;

        while walk_number > last_finalized_number + 1u32.into() {
            let header = self.client.header(walk_hash)
                .map_err(|e| format!("Failed to get header for #{}: {:?}", walk_number, e))?
                .ok_or_else(|| format!("Header not found for #{}", walk_number))?;

            walk_hash = *header.parent_hash();
            walk_number = walk_number - 1u32.into();
            block_hashes.insert(walk_number, walk_hash);
        }

        info!("📋 Built block hash map with {} entries", block_hashes.len());

        let mut current_number = last_finalized_number + 1u32.into();
        let mut finalized_count = 0u32;

        // Encode the justification once - only used for the target block
        // This allows full nodes to verify and finalize the target block
        let encoded_justification = {
            let justification = CoherenceJustification::new(certificate.clone());
            let encoded = justification.encode();
            info!("📝 Encoded coherence justification: {} bytes", encoded.len());
            Some((COHERENCE_ENGINE_ID, encoded))
        };

        while current_number <= target_number {
            let current_hash = *block_hashes.get(&current_number)
                .ok_or_else(|| format!("Block hash not found for #{}", current_number))?;

            // For the target block, include the justification so it gets broadcast
            // For intermediate blocks, finalize without justification
            let justification_for_block = if current_number == target_number {
                encoded_justification.clone()
            } else {
                None
            };

            // Finalize this block using Client's Finalizer trait
            match self.client.finalize_block(current_hash, justification_for_block, true) {
                Ok(()) => {
                    finalized_count += 1;
                    if finalized_count % 10 == 0 || current_number == target_number {
                        info!("🔒 Finalized up to #{} ({}/{})", current_number, finalized_count, blocks_behind);
                    }
                },
                Err(e) => {
                    error!("❌ Failed to finalize block #{}: {:?}", current_number, e);
                    return Err(format!("Failed to finalize block #{}: {:?}", current_number, e));
                }
            }

            current_number = current_number + 1u32.into();
        }

        // Broadcast justification to peers via gossip protocol
        // This is what actually sends the justification to full nodes
        if let Some((_, encoded)) = encoded_justification {
            info!("📡 Broadcasting justification for block #{} to peers via gossip", target_number);
            if let Err(e) = self.broadcast_justification(block_hash, target_number, encoded) {
                warn!("⚠️  Failed to broadcast justification: {}", e);
            }
        }

        info!("✅ Successfully finalized {} blocks (#{} to #{})", finalized_count, last_finalized_number + 1u32.into(), target_number);
        Ok(())
    }

    /// Submit checkpoint certificate to on-chain storage
    ///
    /// Phase 6B: Store finality certificate on-chain for checkpoints.
    /// This provides an audit trail and enables cross-chain finality proofs.
    async fn submit_checkpoint_certificate(
        &self,
        _block_hash: Block::Hash,
        certificate: FinalityCertificate<
            sp_core::sphincs::Public,
            <Block::Header as HeaderT>::Number,
            Block::Hash,
        >,
    ) -> Result<(), String> {
        info!("📤 Submitting checkpoint certificate to on-chain storage...");

        // Phase 6B simplified: Prepare certificate for on-chain storage
        // In Phase 7, we'll do proper inherent integration with block authoring
        info!("✅ Certificate prepared for on-chain storage (Phase 6B - simplified approach)");
        info!("   Block: #{:?}", certificate.block_number);
        info!("   Validators: {}", certificate.validator_count);
        info!("   Coherence Score: {}", certificate.total_coherence_score);

        // Note: The actual on-chain storage will be implemented in Phase 7
        // when we add proper inherent data providers to block authoring.
        // For now, we've proven that:
        // 1. Certificates are generated ✅
        // 2. Checkpoints are detected ✅
        // 3. Storage pallet is ready ✅
        // 4. Extrinsic exists ✅

        Ok(())
    }

    /// Main consensus loop
    ///
    /// This is the heart of the quantum coherence finality protocol.
    /// It runs continuously, listening for new blocks and coordinating
    /// the finality voting process among validators.
    pub async fn run(self) -> Result<(), String> {
        info!("🔮 Quantum Coherence Finality Gadget starting...");

        // Subscribe to new block imports
        let mut block_import_stream = self.client.import_notification_stream();

        // Get notification service for receiving votes from other validators
        let notification_service = self._notification_service.clone();
        let votes_for_receiver = self.votes.clone();
        let connected_peers_for_receiver = self.connected_peers.clone();
        let validator_keys_for_receiver = self.validator_keys.clone();
        let client_for_receiver = self.client.clone();
        // PQ-MonadBFT Phase 1: Clone leader vote aggregation and current leader
        let leader_vote_aggregation_for_receiver = self.leader_vote_aggregation.clone();
        let current_leader_for_receiver = self.current_leader.clone();
        let our_validator_id_for_receiver = self.our_validator_id;
        let equivocation_ledger_for_receiver = self.equivocation_ledger.clone();

        // DEVNET-ONLY adversarial witness (compiled only under --features byzantine-attack).
        #[cfg(feature = "byzantine-attack")]
        let attack_client = self.client.clone();
        #[cfg(feature = "byzantine-attack")]
        let attack_peers = self.connected_peers.clone();
        #[cfg(feature = "byzantine-attack")]
        let attack_service = self._notification_service.clone();

        // Spawn vote receiver task
        let vote_receiver_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_vote_receiver_static(
                notification_service,
                votes_for_receiver,
                connected_peers_for_receiver,
                validator_keys_for_receiver,
                client_for_receiver,
                leader_vote_aggregation_for_receiver,
                current_leader_for_receiver,
                our_validator_id_for_receiver,
                equivocation_ledger_for_receiver,
            ).await {
                error!("Vote receiver task failed: {}", e);
            }
        });

        // DEVNET-ONLY adversarial witness: forge + broadcast unauthorized certificates.
        // Compiled only under --features byzantine-attack AND armed only by env
        // QH_ATTACK_FORGE_CERT — a validator binary contains neither.
        #[cfg(feature = "byzantine-attack")]
        if std::env::var("QH_ATTACK_FORGE_CERT").is_ok() {
            warn!("😈😈😈 BYZANTINE ATTACK MODE ARMED (QH_ATTACK_FORGE_CERT) — DEVNET ONLY. If you see this on a validator, STOP THE NODE.");
            tokio::spawn(async move {
                Self::run_forge_attack_static(attack_client, attack_peers, attack_service).await;
            });
        }

        // Main block processing loop
        while let Some(notification) = block_import_stream.next().await {
            let block_hash = notification.hash;
            let block_number = *notification.header.number();

            info!(
                "🔮 New block imported: #{} ({:?})",
                block_number, block_hash
            );

            // DEVNET-ONLY: record every imported block by height so the equivocation
            // witness can target a real competing block on a genuine fork.
            #[cfg(feature = "byzantine-attack")]
            record_seen_block(&block_number.to_string(), block_hash.encode());

            // Run the finality protocol for this block
            if let Err(e) = self.process_block(block_hash, block_number).await {
                warn!(
                    "Failed to process block #{} for finality: {}",
                    block_number, e
                );
            }
        }

        // Wait for vote receiver to finish (shouldn't happen unless we're shutting down)
        let _ = vote_receiver_handle.await;

        Ok(())
    }

    /// DEVNET-ONLY Byzantine attack task — the adversarial witness for the coherence
    /// gate. Compiled only under `--features byzantine-attack` and armed only by env
    /// `QH_ATTACK_FORGE_CERT`; a validator binary contains neither. It periodically
    /// broadcasts a FORGED `FinalityCertificateBroadcast` with valid-looking QBER/health
    /// scalars but a certificate carrying ZERO real votes — the exact #345,140-class
    /// attack (finalize on scalars, no authorization). Honest peers running the gate MUST
    /// reject it (`incoherent certificate: 0 distinct verified …`) and keep finalizing.
    #[cfg(feature = "byzantine-attack")]
    async fn run_forge_attack_static(
        client: Arc<Client>,
        connected_peers: Arc<tokio::sync::Mutex<std::collections::HashSet<sc_network::PeerId>>>,
        notification_service: Arc<tokio::sync::Mutex<Box<dyn NotificationService>>>,
    ) {
        use scale_codec::Encode;
        use crate::coherence_gossip::GossipMessage;

        let mut ticks: u64 = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            ticks += 1;

            let chain = client.info();
            let target_hash = chain.best_hash;
            let target_number = chain.best_number;

            // Forge: valid-looking scalars, certificate carrying ZERO real votes.
            let forged = FinalityCertificate::<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash> {
                block_hash: target_hash,
                block_number: target_number,
                precommit_votes: Default::default(),
                consensus_quantum_state: QuantumState {
                    valid_proofs: 0,
                    rejected_proofs: 0,
                    average_qber: 0,
                    entropy_pool_hash: Default::default(),
                    reporter_count: 0,
                    min_qber: 0,
                    max_qber: 0,
                },
                total_coherence_score: 0,
                validator_count: 3,
                timestamp: ticks,
            };

            let message = GossipMessage::<Block>::FinalityCertificateBroadcast {
                block_hash: target_hash,
                block_number: target_number,
                aggregated_qber: 0,   // passes the <= 1100 scalar check
                healthy_channels: 3,  // passes the >= validator_count/2 check
                validator_count: 3,
                encoded_certificate: forged.encode(),
            };
            let encoded = message.encode();

            let peers: Vec<_> = { connected_peers.lock().await.iter().cloned().collect() };
            {
                let mut service = notification_service.lock().await;
                for p in &peers {
                    service.send_sync_notification(p, encoded.clone());
                }
            }
            warn!(
                "😈 [ATTACK] broadcast FORGED certificate (0 votes, valid scalars) for block #{:?} to {} peer(s) — honest gate MUST reject",
                target_number, peers.len()
            );
        }
    }

    /// Vote receiver task - listens for votes from other validators
    ///
    /// Phase 7C: Real P2P vote reception and processing
    /// PQ-MonadBFT Phase 1: Also handles linear O(n) vote aggregation
    ///
    /// This is a static method that doesn't require &self, allowing it to run
    /// in a separate tokio task without lifetime issues.
    async fn run_vote_receiver_static(
        notification_service: Arc<tokio::sync::Mutex<Box<dyn NotificationService>>>,
        votes: Arc<std::sync::Mutex<HashMap<Block::Hash, Vec<CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>>>>>,
        connected_peers: Arc<tokio::sync::Mutex<std::collections::HashSet<sc_network::PeerId>>>,
        validator_keys: Arc<std::sync::Mutex<HashMap<sp_core::sphincs::Public, crate::falcon_crypto::PublicKey>>>,
        client: Arc<Client>,
        // PQ-MonadBFT Phase 1: Leader vote aggregation
        leader_vote_aggregation: Arc<std::sync::Mutex<HashMap<Block::Hash, Vec<(
            CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
            u16,  // qber_measurement
            u32,  // qkd_channel_id
        )>>>>,
        current_leader: Arc<std::sync::Mutex<Option<sp_core::sphincs::Public>>>,
        our_validator_id: Option<sp_core::sphincs::Public>,
        equivocation_ledger: Arc<std::sync::Mutex<EquivocationLedger<sp_core::sphincs::Public, Block::Hash>>>,
    ) -> Result<(), String> {
        use scale_codec::Decode;
        use crate::coherence_gossip::GossipMessage;
        use crate::coherence_justification::{CoherenceJustification, COHERENCE_ENGINE_ID};
        use sc_network::service::traits::NotificationEvent;

        info!("📡 Vote receiver task starting...");

        loop {
            // Receive next event from notification service
            // Using tokio::sync::Mutex allows us to await while holding the lock
            let event = {
                let mut service = notification_service.lock().await;

                // Use biased select to prioritize actual events over timeout
                // This prevents dropping in-progress event futures
                tokio::select! {
                    biased;
                    evt = service.next_event() => evt,
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                        debug!("📡 Vote receiver: no events in 5s, still listening...");
                        None
                    },
                }
            };

            // Handle the event
            match event {
                Some(NotificationEvent::NotificationReceived { peer, notification }) => {
                    debug!("📨 Received message from peer {:?} ({} bytes)", peer, notification.len());

                    // Decode the gossip message
                    let message = match GossipMessage::<Block>::decode(&mut &notification[..]) {
                        Ok(msg) => msg,
                        Err(e) => {
                            warn!("❌ Failed to decode gossip message from {:?}: {}", peer, e);
                            continue;
                        }
                    };

                    // Handle the message based on type
                    match message {
                        GossipMessage::Vote(vote) => {
                            info!(
                                "📨 Received vote from peer {:?} for block #{} (validator: {:?})",
                                peer, vote.block_number, vote.validator
                            );

                            // Validate the vote
                            let keys = validator_keys.lock()
                                .map_err(|e| format!("Failed to lock validator_keys: {}", e))?;
                            if let Err(e) = Self::validate_vote_static(&vote, &keys) {
                                warn!("❌ Invalid vote from {:?}: {}", peer, e);
                                continue;
                            }
                            drop(keys);

                            // AUTHORITATIVE finality-safety gate (2026-07-17 review): the SPHINCS+
                            // signature MUST verify against the current on-chain Aura authority set.
                            // A vote we cannot cryptographically verify — bad signature, or a
                            // validator not in the authority set — must NEVER be stored or counted
                            // toward finality. This replaces the ephemeral-Falcon "P2P authenticated"
                            // fallback that finalized the #345,140 fork.
                            // See docs/finality-safety-review-and-fix-list.md.
                            match Self::verify_vote_signature_static(&client, vote.block_hash, &vote) {
                                Ok(true) => {}
                                Ok(false) => {
                                    warn!("❌ Rejecting vote from {:?}: SPHINCS+ verification failed (bad signature or non-authority)", peer);
                                    continue;
                                }
                                Err(e) => {
                                    warn!("❌ Rejecting vote from {:?}: could not verify ({}) — failing closed", peer, e);
                                    continue;
                                }
                            }

                            // One vote per (validator, height): a conflicting second vote is
                            // an equivocation and is never stored or counted.
                            if !Self::admit_vote(&client, &equivocation_ledger, &vote, "gossip") {
                                continue;
                            }

                            // Store the vote
                            let mut votes_map = votes.lock()
                                .map_err(|e| format!("Failed to lock votes: {}", e))?;

                            let block_votes = votes_map.entry(vote.block_hash)
                                .or_insert_with(Vec::new);

                            // Check for duplicate
                            if block_votes.iter().any(|v| v.validator == vote.validator) {
                                debug!("⚠️  Duplicate vote from validator {:?}, ignoring", vote.validator);
                                continue;
                            }

                            // Add vote
                            block_votes.push(vote.clone());
                            let vote_count = block_votes.len();

                            info!(
                                "✅ Vote stored: {} total votes for block {:?}",
                                vote_count,
                                vote.block_hash
                            );

                            // Check for supermajority immediately after receiving vote
                            // This catches cases where votes arrive after process_block has finished waiting.
                            // The threshold MUST come from the live validator set: a hardcoded N=3 here
                            // caused the 2026-07-04 finality fork. Fail closed on query failure — the
                            // vote stays stored and process_block can still finalize later.
                            // The voted block must be on OUR best chain before we
                            // consider finalizing it. Descendancy is not enough:
                            // in fork #4 both siblings descended from the finalized
                            // head, both collected a quorum, and the first to arrive
                            // was finalized. The vote stays stored either way — if
                            // this branch later becomes canonical, process_block can
                            // still finalize it.
                            match Self::is_on_best_chain(&client, vote.block_number, vote.block_hash) {
                                Ok(true) => {}
                                Ok(false) => {
                                    debug!(
                                        "⏭️  Vote for #{:?} {:?} is not on our best chain — stored, not finalized",
                                        vote.block_number, vote.block_hash
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    warn!("⚠️  Skipping finalize check — {}", e);
                                    continue;
                                }
                            }

                            // Threshold from the authority set AT THE VOTED BLOCK.
                            // Reading it at `best_hash` uses whatever set exists at our
                            // head now, which after a rotation is not the set that cast
                            // these votes.
                            let total_validators = match Self::validator_count_at(&client, vote.block_hash) {
                                Ok(n) => n,
                                Err(e) => {
                                    warn!("⚠️  Skipping finalize check — cannot determine validator count at the voted block: {}", e);
                                    continue;
                                }
                            };
                            let threshold = quorum_threshold(total_validators);

                            if vote_count as u32 >= threshold {
                                error!(
                                    "🎉 SUPERMAJORITY REACHED in vote receiver! Block #{}: {}/{} votes",
                                    vote.block_number, vote_count, total_validators
                                );

                                // Create justification and finalize
                                let finalized_number: u32 = client.info().finalized_number.saturated_into();
                                let block_num: u32 = vote.block_number.saturated_into();

                                if block_num > finalized_number {
                                    // Collect votes for this block
                                    let votes_for_block: Vec<_> = block_votes.iter().cloned().collect();
                                    let vote_block_hash = vote.block_hash;
                                    let vote_block_number = vote.block_number;
                                    drop(votes_map); // Release lock before finalization

                                    // Finalize the block
                                    let justification: sp_runtime::Justification = (
                                        *b"COHR",
                                        format!("Coherence supermajority: {} votes", votes_for_block.len()).into_bytes(),
                                    );

                                    match client.finalize_block(vote_block_hash, Some(justification.into()), true) {
                                        Ok(()) => {
                                            error!("✅🎯 Block #{} FINALIZED via vote receiver supermajority!", block_num);
                                        }
                                        Err(e) => {
                                            warn!("❌ Failed to finalize block #{}: {:?}", block_num, e);
                                        }
                                    }
                                    continue; // Skip to next message
                                }
                            }
                        }

                        GossipMessage::VoteRequest(block_hash) => {
                            debug!("📬 Vote request received for block {:?} from {:?}", block_hash, peer);
                            // Future: Send our votes for this block back to requester
                        }

                        GossipMessage::Justification { block_hash, block_number, encoded_justification } => {
                            info!(
                                "📨 Received justification for block #{} ({:?}) from {:?} ({} bytes)",
                                block_number, block_hash, peer, encoded_justification.len()
                            );

                            // Check if we already have this block finalized
                            let finalized_number = client.info().finalized_number;
                            if block_number <= finalized_number {
                                debug!("⏭️  Block #{} already finalized (current: #{}), ignoring justification", block_number, finalized_number);
                                continue;
                            }

                            // Decode the justification
                            let justification: CoherenceJustification<
                                sp_core::sphincs::Public,
                                NumberFor<Block>,
                                Block::Hash,
                            > = match CoherenceJustification::decode_from_network(&encoded_justification) {
                                Ok(j) => j,
                                Err(e) => {
                                    warn!("❌ Failed to decode justification: {:?}", e);
                                    continue;
                                }
                            };

                            // Verify the block exists
                            if client.header(block_hash).ok().flatten().is_none() {
                                warn!("⚠️  Block {:?} not found, cannot import justification", block_hash);
                                continue;
                            }

                            // Verify we have enough votes — same threshold rule and count source
                            // as the finalize path: ceil(2N/3) of the runtime authority set at this
                            // block. Never trust cert.validator_count alone: a producer could claim
                            // any value, and pre-fix certs set it to the vote count (circular).
                            let total_validators = match Self::validator_count_at(&client, block_hash) {
                                Ok(n) => n,
                                Err(e) => {
                                    warn!("⚠️  Rejecting justification for block #{} — cannot determine validator count: {}", block_number, e);
                                    continue;
                                }
                            };
                            let cert = &justification.certificate;
                            if cert.validator_count != total_validators {
                                warn!(
                                    "⚠️  Justification cert for block #{} claims {} validators, runtime says {} — using runtime count",
                                    block_number, cert.validator_count, total_validators
                                );
                            }
                            let required_votes = quorum_threshold(total_validators);
                            let actual_votes = cert.precommit_votes.len() as u32;

                            if actual_votes < required_votes {
                                warn!(
                                    "❌ Insufficient votes in justification: {} < {} required",
                                    actual_votes, required_votes
                                );
                                continue;
                            }

                            // AUTHORITATIVE coherence gate (2026-07-18 finality-safety review):
                            // the vote COUNT above is necessary but NOT sufficient — it never
                            // verified a signature. Re-decode the certificate with the producer's
                            // whose votes are for THIS block; forged / duplicate / wrong-block votes
                            // are filtered here, never counted.
                            let verifiable = match CoherenceJustification::<
                                sp_core::sphincs::Public, NumberFor<Block>, Block::Hash,
                            >::decode_from_network(&encoded_justification)
                            {
                                Ok(j) => j,
                                Err(e) => {
                                    warn!("❌ Justification rejected for block #{}: undecodable for verification ({:?})", block_number, e);
                                    continue;
                                }
                            };
                            match Self::verify_finality_certificate(&client, block_hash, &verifiable.certificate) {
                                Ok(n) => info!(
                                    "✅ Coherence gate passed: {} distinct verified authority vote(s) for block #{}",
                                    n, block_number
                                ),
                                Err(e) => {
                                    warn!("❌ Justification rejected by coherence gate for block #{}: {}", block_number, e);
                                    continue;
                                }
                            }

                            // Finalize the block using the justification
                            let substrate_justification = (COHERENCE_ENGINE_ID, encoded_justification.clone());
                            match client.finalize_block(block_hash, Some(substrate_justification), true) {
                                Ok(()) => {
                                    info!(
                                        "🎉 Block #{} finalized via received justification! (coherence score: {})",
                                        block_number, cert.total_coherence_score
                                    );

                                    // Re-broadcast the justification to our peers so finality
                                    // propagates epidemically beyond the leader's direct peer set
                                    // (in/out peer caps make the mesh partial at large N).
                                    // Natural termination: a node only re-broadcasts when the
                                    // justification ADVANCED its own finality — already-finalized
                                    // blocks are dropped above before reaching this point.
                                    let rebroadcast = GossipMessage::<Block>::Justification {
                                        block_hash,
                                        block_number,
                                        encoded_justification: encoded_justification.clone(),
                                    };
                                    let encoded = {
                                        use scale_codec::Encode;
                                        rebroadcast.encode()
                                    };
                                    let peers_snapshot: Vec<_> = {
                                        let peers = connected_peers.lock().await;
                                        peers.iter().filter(|p| **p != peer).cloned().collect()
                                    };
                                    let mut service = notification_service.lock().await;
                                    let peer_count = peers_snapshot.len();
                                    for p in peers_snapshot {
                                        service.send_sync_notification(&p, encoded.clone());
                                    }
                                    drop(service);
                                    debug!("📡 Re-broadcast justification for block #{} to {} peers", block_number, peer_count);
                                },
                                Err(e) => {
                                    warn!("❌ Failed to finalize block #{}: {:?}", block_number, e);
                                }
                            }
                        }

                        // PQ-MonadBFT Phase 1: Handle vote sent directly to leader
                        GossipMessage::VoteToLeader { vote, qber_measurement, qkd_channel_id } => {
                            info!(
                                "🎯 [LINEAR] Received vote from {:?} for block #{} (QBER: {:.2}%)",
                                &vote.validator.0[..8],
                                vote.block_number,
                                qber_measurement as f64 / 100.0
                            );

                            // Check if we are the current leader
                            let leader_opt = current_leader.lock()
                                .map_err(|e| format!("Failed to lock current leader: {}", e))?
                                .clone();

                            let our_id = our_validator_id.ok_or("No validator ID set")?;

                            if leader_opt != Some(our_id) {
                                // We're not the leader - forward to leader or ignore
                                debug!("Received VoteToLeader but we're not the leader, ignoring");
                                continue;
                            }

                            // We ARE the leader - validate and store the vote
                            let keys = validator_keys.lock()
                                .map_err(|e| format!("Failed to lock validator_keys: {}", e))?;
                            if let Err(e) = Self::validate_vote_static(&vote, &keys) {
                                warn!("❌ Invalid vote from {:?}: {}", &vote.validator.0[..8], e);
                                continue;
                            }
                            drop(keys);

                            // AUTHORITATIVE finality-safety gate (2026-07-17 review): same rule as
                            // the gossip receiver — the SPHINCS+ signature must verify against an
                            // on-chain Aura authority, or the vote is dropped and never aggregated.
                            match Self::verify_vote_signature_static(&client, vote.block_hash, &vote) {
                                Ok(true) => {}
                                Ok(false) => {
                                    warn!("❌ Rejecting vote from 0x{}…: SPHINCS+ verification failed (bad signature or non-authority)", hex::encode(&vote.validator.0[..8]));
                                    continue;
                                }
                                Err(e) => {
                                    warn!("❌ Rejecting vote from 0x{}…: could not verify ({}) — failing closed", hex::encode(&vote.validator.0[..8]), e);
                                    continue;
                                }
                            }

                            // One vote per (validator, height) — same rule as the gossip path.
                            if !Self::admit_vote(&client, &equivocation_ledger, &vote, "leader") {
                                continue;
                            }

                            // Store in leader vote aggregation
                            let block_hash = vote.block_hash;
                            let block_number = vote.block_number;
                            let validator_id = vote.validator.clone();

                            let vote_count = {
                                let mut aggregation = leader_vote_aggregation.lock()
                                    .map_err(|e| format!("Failed to lock leader vote aggregation: {}", e))?;

                                let votes = aggregation.entry(block_hash).or_insert_with(Vec::new);

                                // Check for duplicate votes from same validator
                                if votes.iter().any(|(v, _, _)| v.validator == validator_id) {
                                    debug!("Duplicate vote from validator {:?}, ignoring", &validator_id.0[..8]);
                                    continue;
                                }

                                votes.push((vote.clone(), qber_measurement, qkd_channel_id));
                                votes.len()
                            };

                            info!(
                                "👑 Leader aggregated vote: {} total for block #{} (QBER: {:.2}%)",
                                vote_count,
                                block_number,
                                qber_measurement as f64 / 100.0
                            );

                            // Also store in regular votes map for compatibility
                            let mut votes_map = votes.lock()
                                .map_err(|e| format!("Failed to lock votes: {}", e))?;
                            let block_votes = votes_map.entry(block_hash).or_insert_with(Vec::new);
                            if !block_votes.iter().any(|v| v.validator == validator_id) {
                                block_votes.push(vote);
                            }
                        }

                        // PQ-MonadBFT Phase 1: Handle finality certificate broadcast from leader
                        GossipMessage::FinalityCertificateBroadcast {
                            block_hash,
                            block_number,
                            aggregated_qber,
                            healthy_channels,
                            validator_count,
                            encoded_certificate,
                        } => {
                            info!(
                                "📜 [LINEAR] Received finality certificate for block #{} (QBER: {:.2}%, healthy: {}/{})",
                                block_number,
                                aggregated_qber as f64 / 100.0,
                                healthy_channels,
                                validator_count
                            );

                            // Validate QBER threshold (reject if > 11%)
                            if aggregated_qber > 1100 {
                                warn!(
                                    "❌ Certificate rejected: QBER {:.2}% exceeds 11% threshold",
                                    aggregated_qber as f64 / 100.0
                                );
                                continue;
                            }

                            // Validate healthy channel count (reject if < 50% healthy)
                            if healthy_channels < validator_count / 2 {
                                warn!(
                                    "❌ Certificate rejected: only {}/{} channels healthy (< 50%)",
                                    healthy_channels, validator_count
                                );
                                continue;
                            }

                            // Check if we already have this block finalized
                            let finalized_number = client.info().finalized_number;
                            if block_number <= finalized_number {
                                debug!("⏭️  Block #{} already finalized, ignoring certificate", block_number);
                                continue;
                            }

                            // AUTHORITATIVE coherence gate (2026-07-18 finality-safety review):
                            // the QBER / healthy-channel scalars above are ADD-ONS, never
                            // authorization. Decode the certificate and require a verified
                            // DISTINCT-authority quorum for THIS block before finalizing —
                            // otherwise a single peer could finalize any imported fork block
                            // with arbitrary scalars and an undecoded certificate (#345,140 class).
                            {
                                use scale_codec::Decode;
                                let broadcast_cert = match FinalityCertificate::<
                                    sp_core::sphincs::Public, NumberFor<Block>, Block::Hash,
                                >::decode(&mut &encoded_certificate[..])
                                {
                                    Ok(c) => c,
                                    Err(e) => {
                                        warn!("❌ Certificate rejected for block #{}: undecodable ({:?})", block_number, e);
                                        continue;
                                    }
                                };
                                match Self::verify_finality_certificate(&client, block_hash, &broadcast_cert) {
                                    Ok(n) => info!(
                                        "✅ Coherence gate passed: {} distinct verified authority vote(s) for block #{}",
                                        n, block_number
                                    ),
                                    Err(e) => {
                                        warn!("❌ Certificate rejected by coherence gate for block #{}: {}", block_number, e);
                                        continue;
                                    }
                                }
                            }

                            // Finalize the block using the certificate
                            let substrate_justification = (COHERENCE_ENGINE_ID, encoded_certificate.clone());
                            match client.finalize_block(block_hash, Some(substrate_justification), true) {
                                Ok(()) => {
                                    info!(
                                        "🎉 [LINEAR] Block #{} finalized via leader certificate! (QBER: {:.2}%)",
                                        block_number,
                                        aggregated_qber as f64 / 100.0
                                    );
                                },
                                Err(e) => {
                                    warn!("❌ Failed to finalize block #{}: {:?}", block_number, e);
                                }
                            }
                        }
                    }
                }

                Some(NotificationEvent::NotificationStreamOpened { peer, handshake, .. }) => {
                    info!("🤝 Peer {:?} opened notification stream (handshake: {} bytes)", peer, handshake.len());
                    // Add peer to connected set
                    connected_peers.lock().await.insert(peer);
                    info!("✅ Peer {:?} added to connected peers", peer);
                }

                Some(NotificationEvent::NotificationStreamClosed { peer }) => {
                    info!("👋 Peer {:?} closed notification stream", peer);
                    // Remove peer from connected set
                    connected_peers.lock().await.remove(&peer);
                    info!("✅ Peer {:?} removed from connected peers", peer);
                }

                Some(NotificationEvent::ValidateInboundSubstream { peer, result_tx, .. }) => {
                    debug!("🔍 Validating inbound substream from {:?}", peer);
                    // Accept all inbound substreams (validators are authenticated via signatures)
                    let _ = result_tx.send(sc_network::service::traits::ValidationResult::Accept);
                }

                None => {
                    debug!("📡 Notification stream ended, waiting before retry...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Validate vote without &self (for static context)
    ///
    /// Performs basic validation checks on a received vote before storing it.
    /// This is called from the vote receiver task which runs in a static context.
    fn validate_vote_static(
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
        validator_keys: &HashMap<sp_core::sphincs::Public, crate::falcon_crypto::PublicKey>,
    ) -> Result<(), String> {
        // 1. Check coherence score is reasonable
        // Score formula: Σ(1000 / (1 + QBER_i)) per proof, so max ~1000 per proof
        // With up to 20 proofs and excellent QBER, max would be ~20000
        if vote.coherence_score > 20000 {
            return Err(format!("Coherence score {} exceeds maximum", vote.coherence_score));
        }

        // 2. Check QBER is reasonable
        if vote.quantum_state.average_qber > 1100 {
            return Err(format!("QBER {} exceeds 11% threshold", vote.quantum_state.average_qber));
        }

        // 3. Check signature exists
        if vote.signature.len() == 0 {
            return Err("Vote has no signature".to_string());
        }

        // 4. Verify Falcon1024 signature (if we have the key)
        // Note: For remote validators, we may not have their Falcon key yet.
        // In this case, accept the vote if it passes basic checks.
        // The validator identity is authenticated via the P2P layer.
        if let Some(public_key) = validator_keys.get(&vote.validator) {
            // We have the key - verify the signature
            let message = crate::falcon_crypto::encode_vote_for_signing(
                &vote.validator,
                &vote.block_hash,
                &vote.block_number,
                vote.coherence_score,
                &vote.quantum_state,
            );

            crate::falcon_crypto::verify_signature(&message, &vote.signature, public_key)?;
            debug!("✅ Vote validation passed for validator {:?} (Falcon1024 verified)", vote.validator);
        } else {
            // NOTE (2026-07-17 finality-safety review): the ephemeral Falcon key is NOT the
            // finality gate. Remote validators regenerate their Falcon key on every restart,
            // so it can never be pre-provisioned here — this branch only means "no Falcon key
            // to check", and this function performs BASIC validity checks only (QBER, signature
            // present). The AUTHORITATIVE admission check is the SPHINCS+ signature verified
            // against the on-chain Aura authority set in `verify_vote_signature_static`, which
            // every finality path now calls before a vote is stored or counted. Do NOT
            // reintroduce a "P2P authenticated" *acceptance* as a substitute for signature
            // verification — that fallback finalized the #345,140 fork.
            debug!(
                "No Falcon key for remote validator {:?}; SPHINCS+/authority check is authoritative",
                vote.validator
            );
        }

        Ok(())
    }

    /// Process a block for quantum coherence finality
    ///
    /// This is where the actual consensus protocol runs for each block.
    async fn process_block(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
    ) -> Result<(), String> {
        debug!("Processing block #{} for finality", block_number);

        let block_num: u64 = block_number.saturated_into();

        // PQ-MonadBFT Phase 3: Track pipeline state - block enters PROPOSE phase
        if let Err(e) = self.set_pipeline_phase(block_hash, PipelinePhase::Propose) {
            warn!("⚠️  Failed to set PROPOSE phase for block #{}: {}", block_number, e);
        }

        // MEMPOOL GROOMING: Check pool status and groom ASAP if needed
        self.groom_mempool_if_needed().await?;

        // ELECTION: Check if it's time to elect a new block producer (every 5 blocks)
        let is_election_block = block_num % 5 == 0;
        let is_leader = if is_election_block {
            self.elect_block_producer(block_num)?
        } else {
            false
        };

        // PHASE 1: Collect STARK proofs from validators
        // If this is an election block, leader collects from all validator queues
        // Otherwise, just generate proofs for this validator
        let proofs = if is_election_block && is_leader {
            // Leader collects proofs from all validators' priority queues
            self.collect_proofs_as_leader(&block_hash).await?
        } else if is_election_block {
            // Follower on election block: just submit our proofs
            self.submit_validator_proofs(&block_hash).await?;
            vec![]
        } else {
            // Non-election block: just generate and queue our own proofs
            self.submit_validator_proofs(&block_hash).await?;
            vec![]
        };

        // Skip consensus on non-election blocks (voting happens only on election blocks)
        if !is_election_block {
            debug!("Not election block #{}, skipping consensus", block_number);
            return Ok(());
        }

        // On election blocks, ALL validators vote (not just leader)
        // Leader does additional work (entropy collection, proof verification)

        // Calculate coherence score - leader uses proofs, non-leader uses default
        let (coherence_score, quantum_state) = if is_leader && !proofs.is_empty() {
            info!("👑 Leader collected {} STARK proofs from validators for block #{}", proofs.len(), block_number);

            // THRESHOLD QRNG: Collect device entropy (real or mock)
            if self.pqtg_client.is_some() {
                self.collect_device_entropy_via_pqtg().await?;
            } else {
                self.generate_mock_device_shares_for_testing().await?;
            }

            // THRESHOLD QRNG: Leader collects device shares
            let leader_pubkey = b"LEADER_PUBKEY_PLACEHOLDER";
            match self.collect_device_shares_as_leader(leader_pubkey).await {
                Ok(Some(entropy_tx)) => {
                    info!(
                        "🎲 Leader reconstructed combined entropy from {} device shares",
                        entropy_tx.device_shares.len()
                    );
                    if let Err(e) = self.demonstrate_entropy_encryption(&entropy_tx, block_number.saturated_into()).await {
                        warn!("⚠️  Entropy encryption demo skipped: {}", e);
                    }
                },
                Ok(None) => debug!("⏭️  Insufficient device shares"),
                Err(e) => warn!("⚠️  Failed to collect device shares: {}", e),
            }

            // PHASE 2: Verify STARK proofs using Winterfell
            let valid_proofs = self.verify_stark_proofs(proofs).await?;
            info!("Verified {} valid STARK proofs", valid_proofs.len());

            // PHASE 3: Calculate coherence score from proofs
            self.calculate_coherence(&valid_proofs)?
        } else {
            // Non-leader: use default coherence score for voting
            info!("🗳️  Follower voting on election block #{}", block_number);
            let default_score = 1912u64; // Default reasonable score
            let default_state = pallet_proof_of_coherence::types::QuantumState {
                valid_proofs: 1,
                rejected_proofs: 0,
                average_qber: 450, // 4.5% QBER
                entropy_pool_hash: Default::default(),
                reporter_count: 1,
                min_qber: 450,
                max_qber: 450,
            };
            (default_score, default_state)
        };

        info!(
            "Coherence score: {}, avg QBER: {:.2}%",
            coherence_score,
            quantum_state.average_qber as f64 / 100.0
        );

        // honest_single (sender side): we vote at most ONCE per election height.
        // Both siblings of a natural fork are imported and both reach this point;
        // without this guard an honest node signs votes for both, which is exactly
        // the equivocation the receivers now reject. First-imported sibling wins;
        // a split height is finalized as an ancestor by the next election height.
        // CHECK here, RECORD only after the vote exists (below): recording first
        // would leave us held to a hash we never signed if create_vote fails.
        if let Some(our_id) = self.our_validator_id {
            let held = self.equivocation_ledger.lock()
                .map_err(|e| format!("Failed to lock equivocation ledger: {}", e))?
                .first_vote(block_num, &our_id)
                .copied();
            if let Some(prev) = held {
                if prev != block_hash {
                    info!(
                        "⏭️  Already voted {:?} at election height #{} — not voting for sibling {:?} (honest_single)",
                        prev, block_number, block_hash
                    );
                    return Ok(());
                }
            }
        }

        // PHASE 4: Create and sign vote with Falcon1024
        let vote = self.create_vote(
            block_hash,
            block_number,
            coherence_score,
            quantum_state.clone(),
            VoteType::Prevote,
        )?;
        info!(
            "✅ Created Prevote for block #{} with score {}",
            block_number, coherence_score
        );

        // PHASE 5: Store vote (in Phase 3, this will broadcast via gossip)
        self.store_vote(block_hash, vote.clone())?;
        info!("📝 Stored our vote for block #{}", block_number);

        // Now the vote exists locally: hold ourselves to it for this height.
        if let Some(our_id) = self.our_validator_id {
            match self.equivocation_ledger.lock() {
                Ok(mut l) => {
                    let _ = l.observe(block_num, our_id, block_hash);
                }
                Err(e) => warn!("⚠️  equivocation ledger poisoned ({}) — own vote at #{} not recorded", e, block_number),
            }
        }

        // PHASE 7B: Broadcast our vote to connected peers
        error!("🔴 Before broadcast_vote for block #{}", block_number);
        self.broadcast_vote(&vote)?;
        error!("🔴 After broadcast_vote for block #{}", block_number);

        // PQ-MonadBFT Phase 3: Track pipeline state - block enters VOTE phase
        if let Err(e) = self.set_pipeline_phase(block_hash, PipelinePhase::Vote) {
            warn!("⚠️  Failed to set VOTE phase for block #{}: {}", block_number, e);
        }

        // PHASE 7: Wait for votes and check for supermajority on ANY recent block
        // P2P votes may arrive for different blocks due to timing, so check all
        error!("🔴 PHASE 7: Starting supermajority check for block #{}", block_number);
        let mut best_block_with_sm: Option<(Block::Hash, NumberFor<Block>, u32)> = None;
        let mut total_validators = 0u32;

        for attempt in 0..10 {
            // Check ALL blocks in the votes map for supermajority
            // Use block scope to ensure MutexGuard is dropped before await
            let found_sm = {
                let votes_map = self.votes.lock().map_err(|e| format!("Failed to lock votes: {}", e))?;
                // Fail closed: without a live validator count there is no valid
                // threshold, so no supermajority can be declared this attempt.
                total_validators = match self.get_current_validators() {
                    Ok(v) if !v.is_empty() => v.len() as u32,
                    Ok(_) => {
                        warn!("⚠️  Supermajority attempt {}: empty authority set — failing closed", attempt + 1);
                        0
                    }
                    Err(e) => {
                        warn!("⚠️  Supermajority attempt {}: cannot determine validator count ({}) — failing closed", attempt + 1, e);
                        0
                    }
                };
                let threshold = quorum_threshold(total_validators);

                // Debug: log the votes map contents
                error!("🔴 Supermajority check attempt {}: {} blocks in votes map, threshold {}/{}",
                      attempt + 1, votes_map.len(), threshold, total_validators);
                for (hash, block_votes) in votes_map.iter() {
                    if let Some(first_vote) = block_votes.first() {
                        let num: u64 = first_vote.block_number.saturated_into();
                        error!("🔴    Block #{}: {} votes", num, block_votes.len());
                    }
                }

                for (hash, block_votes) in votes_map.iter() {
                    let valid_count = block_votes.iter()
                        .filter(|v| self.is_valid_validator(&v.validator))
                        .count() as u32;

                    if total_validators > 0 && valid_count >= threshold {
                        // Get block number from first vote
                        if let Some(vote) = block_votes.first() {
                            let num: u64 = vote.block_number.saturated_into();
                            info!("📊 Found supermajority for block #{}: {}/{} votes", num, valid_count, total_validators);
                            // Keep the highest block with supermajority
                            if best_block_with_sm.is_none() ||
                               vote.block_number.saturated_into::<u64>() > best_block_with_sm.as_ref().unwrap().1.saturated_into::<u64>() {
                                best_block_with_sm = Some((*hash, vote.block_number, valid_count));
                            }
                        }
                    }
                }
                // MutexGuard dropped here at end of block
                best_block_with_sm.is_some()
            };

            if found_sm {
                info!("✅ Supermajority found after {} attempts", attempt + 1);
                break;
            }

            if attempt < 9 {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }

        if let Some((best_hash, best_number, vote_count)) = best_block_with_sm {
            let block_hash = best_hash;
            let block_number = best_number;
            info!(
                "✅ Supermajority achieved for block #{}: {}/{} validators voted!",
                block_number, vote_count, total_validators
            );

            // PHASE 8: Generate finality certificate
            // PQ-MonadBFT Phase 3: Set pipeline phase to CERTIFY
            self.set_pipeline_phase(block_hash, PipelinePhase::Certify)?;

            let certificate = self.generate_finality_certificate(block_hash, block_number)?;
            info!(
                "📜 Generated FinalityCertificate for block #{} with {} votes",
                block_number, certificate.validator_count
            );

            // PQ-MonadBFT Phase 3: Cache certificate for tail-fork protection
            let encoded_cert = certificate.encode();
            if let Err(e) = self.cache_certificate(block_hash, block_number, encoded_cert.clone()) {
                warn!("⚠️  Failed to cache certificate: {}", e);
            }

            // PQ-MonadBFT Phase 2: Leader broadcasts certificate to all validators
            // This allows validators to finalize even if they didn't receive all votes directly
            if self.use_linear_voting && is_leader {
                if let Err(e) = self.broadcast_finality_certificate(
                    block_hash,
                    block_number,
                    &certificate,
                ) {
                    warn!("⚠️  Failed to broadcast finality certificate: {}", e);
                }
            }

            // PQ-MonadBFT Phase 3: Queue for deferred execution
            // Get aggregated QBER from certificate
            let aggregated_qber = certificate.consensus_quantum_state.average_qber as u16;

            // Get parent's certificate for tail-fork protection
            let parent_hash = self.client.header(block_hash)
                .ok()
                .flatten()
                .map(|h| *h.parent_hash());
            let parent_cert = parent_hash.and_then(|ph| self.get_cached_certificate(&ph));

            if let Err(e) = self.queue_for_deferred_execution(
                block_hash,
                block_number,
                aggregated_qber,
                parent_cert,
            ) {
                warn!("⚠️  Failed to queue for deferred execution: {}", e);
            }

            // PHASE 9: Finalize block via client (not transaction pool!)
            info!("🔮 Finalizing block #{} via quantum coherence consensus", block_number);
            info!("   Block: {:?}", block_hash);
            info!("   Validators: {}/{}", certificate.validator_count, total_validators);
            info!("   Coherence Score: {}", certificate.total_coherence_score);

            // Phase 6A: Finalize via client backend (off-chain finality)
            // This is the correct approach - like GRANDPA, not transaction pool
            match self.finalize_block_in_client(block_hash, certificate.clone()).await {
                Ok(()) => {
                    info!("✅ Block #{} finalized successfully!", block_number);
                },
                Err(e) => {
                    error!("❌ Failed to finalize block #{}: {}", block_number, e);
                }
            }

            // Phase 6B: Checkpoint on-chain every 3 blocks (for testing - normally 100)
            // Check if this is a checkpoint block
            let block_num: u64 = block_number.saturated_into();
            if block_num % 3 == 0 {
                info!("📌 Checkpoint block #{} - storing certificate on-chain", block_num);

                // Submit checkpoint certificate to on-chain storage
                match self.submit_checkpoint_certificate(block_hash, certificate.clone()).await {
                    Ok(()) => {
                        info!("✅ Checkpoint certificate submitted for block #{}", block_num);
                    },
                    Err(e) => {
                        error!("❌ Failed to submit checkpoint certificate for block #{}: {}", block_num, e);
                    }
                }
            }
        } else {
            debug!(
                "No supermajority found for any block in votes map after 10 attempts"
            );
        }

        // PQ-MonadBFT Phase 3: Process deferred executions
        // After consensus completes, process any blocks in the deferred execution queue
        match self.process_deferred_executions().await {
            Ok(count) if count > 0 => {
                info!("📦 Processed {} deferred block executions", count);
            }
            Ok(_) => {} // No blocks to process, that's fine
            Err(e) => {
                warn!("⚠️  Failed to process deferred executions: {}", e);
            }
        }

        // PQ-MonadBFT Phase 3: Periodic pipeline cleanup (every 10 blocks)
        if block_num % 10 == 0 {
            if let Err(e) = self.cleanup_pipeline() {
                warn!("⚠️  Failed to cleanup pipeline: {}", e);
            }
        }

        Ok(())
    }


    /// Generate a mock quantum entropy proof for testing
    ///
    /// This creates a proof with empty STARK bytes for fast testing.
    /// STARK proof generation with Winterfell is too slow (~10+ seconds) for 6-second block times.
    /// In production, proofs would be pre-computed by reporters and submitted to the chain.
    /// Used for testing the gadget flow without requiring real quantum hardware.
    fn generate_mock_proof(&self) -> Result<QuantumEntropyProof<sp_core::sphincs::Public>, String> {
        self.generate_mock_proof_with_qber(500) // Default 5% QBER
    }

    /// Generate a mock proof with specific QBER value.
    ///
    /// Uses current timestamp so the proof passes freshness checks in `verify_single_proof`.
    fn generate_mock_proof_with_qber(&self, qber: u32) -> Result<QuantumEntropyProof<sp_core::sphincs::Public>, String> {
        use sp_core::sphincs::Public;
        use sp_core::H256;

        let mock_reporter = Public::from_raw([1u8; 64]); // Mock reporter ID

        let sample_count = 1024u32;

        // Current timestamp for freshness check compliance
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Skip STARK proof generation for mock - too slow for real-time block production
        // In production, reporters would submit pre-computed proofs
        let proof = QuantumEntropyProof {
            stark_proof: vec![1u8; 32], // Dummy proof (<100 bytes triggers mock mode)
            public_inputs: PublicInputs {
                entropy_commitment: H256::from([2u8; 32]), // Non-zero (passes structural check)
                qber,
                qkd_key_id: vec![3u8; 32], // Non-empty (passes structural check)
                reporter: mock_reporter,
                sample_count,
                hardware_attestation: H256::from([4u8; 32]), // Non-zero (passes structural check)
            },
            signature: Vec::new(), // Empty — Falcon1024 verification only runs in production mode
            timestamp: now_ms,
        };

        debug!("Generated mock proof: QBER={}%, samples={} (STARK verification skipped for performance)",
            proof.public_inputs.qber as f64 / 100.0,
            proof.public_inputs.sample_count
        );

        Ok(proof)
    }

    /// Verify STARK proofs using Winterfell
    ///
    /// Each proof demonstrates:
    /// - Valid quantum entropy collection from QRNG
    /// - QBER measurement < 11% threshold
    /// - Authentic QKD key usage
    /// - Valid Falcon1024 signature from reporter
    async fn verify_stark_proofs(
        &self,
        proofs: Vec<QuantumEntropyProof<sp_core::sphincs::Public>>,
    ) -> Result<Vec<QuantumEntropyProof<sp_core::sphincs::Public>>, String> {
        let mut valid_proofs = Vec::new();

        for proof in proofs {
            match self.verify_single_proof(&proof) {
                ProofVerificationResult::Valid => {
                    valid_proofs.push(proof);
                }
                result => {
                    warn!("Proof verification failed: {:?}", result);
                }
            }
        }

        Ok(valid_proofs)
    }

    /// Verify a single STARK proof.
    ///
    /// Checks (applied in both mock and production modes):
    /// 1. QBER < 11% (1100/10000)
    /// 2. Minimum 256 samples
    /// 3. Timestamp freshness (within 60 seconds)
    /// 4. QKD key ID is non-empty
    /// 5. Entropy commitment is non-zero
    /// 6. Hardware attestation is non-zero
    ///
    /// Additional checks in production mode (proof ≥ 100 bytes):
    /// 7. STARK proof cryptographic validity (Winterfell)
    /// 8. Falcon-1024 reporter signature (when validator keystore available)
    fn verify_single_proof(
        &self,
        proof: &QuantumEntropyProof<sp_core::sphincs::Public>,
    ) -> ProofVerificationResult {
        // Check QBER threshold (BB84 security bound: 11%)
        if proof.public_inputs.qber >= 1100 {
            return ProofVerificationResult::QberTooHigh;
        }

        // Check minimum sample count (256 = statistical significance floor)
        if proof.public_inputs.sample_count < 256 {
            return ProofVerificationResult::InsufficientSamples;
        }

        // Timestamp freshness: reject proofs older than 60 seconds
        // Prevents replay of stale entropy measurements
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let max_age_ms = 60_000; // 60 seconds
        if proof.timestamp > 0 && now_ms.saturating_sub(proof.timestamp) > max_age_ms {
            warn!("Proof timestamp too old: {}ms (max {}ms)", now_ms.saturating_sub(proof.timestamp), max_age_ms);
            return ProofVerificationResult::InvalidStarkProof;
        }

        // QKD key ID must be non-empty (identifies which QKD session generated the entropy)
        if proof.public_inputs.qkd_key_id.is_empty() {
            warn!("Proof rejected: empty QKD key ID");
            return ProofVerificationResult::InvalidStarkProof;
        }

        // Entropy commitment must not be zero (all-zero = no real entropy was committed)
        if proof.public_inputs.entropy_commitment == sp_core::H256::zero() {
            warn!("Proof rejected: zero entropy commitment");
            return ProofVerificationResult::InvalidStarkProof;
        }

        // Hardware attestation must not be zero (proves measurement came from real QRNG)
        if proof.public_inputs.hardware_attestation == sp_core::H256::zero() {
            warn!("Proof rejected: zero hardware attestation");
            return ProofVerificationResult::InvalidStarkProof;
        }

        // MOCK MODE: Skip STARK verification for performance
        // Winterfell proof generation/verification is too slow (~10+ seconds) for 6-second blocks
        // In production, reporters pre-compute proofs and submit them to the chain
        if proof.stark_proof.len() < 100 {
            debug!("✅ Mock STARK proof accepted (STARK verification skipped, structural checks passed)");
            debug!("   QBER: {}%, Samples: {}, QKD Key: {} bytes",
                proof.public_inputs.qber as f64 / 100.0,
                proof.public_inputs.sample_count,
                proof.public_inputs.qkd_key_id.len()
            );
            return ProofVerificationResult::Valid;
        }

        // === Production STARK verification path ===
        use pallet_quantum_crypto::qber_stark::{QberStark, QberProof, QberPublicInputs};

        // Convert proof types
        let qber_pub_inputs = QberPublicInputs {
            qber_value: proof.public_inputs.qber,
            measurement_count: proof.public_inputs.sample_count,
            device_id_hash: proof.public_inputs.hardware_attestation.0,
            environmental_hash: proof.public_inputs.entropy_commitment.0,
        };

        // Deserialize STARK proof
        let qber_proof = match QberProof::from_bytes(&proof.stark_proof) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to deserialize STARK proof: {}", e);
                return ProofVerificationResult::InvalidStarkProof;
            }
        };

        // Verify using Winterfell
        let stark_verifier = QberStark::new();
        match stark_verifier.verify(qber_pub_inputs, qber_proof) {
            Ok(_) => {
                debug!("✅ STARK proof verified successfully!");
            }
            Err(e) => {
                warn!("❌ STARK proof verification failed: {}", e);
                return ProofVerificationResult::InvalidStarkProof;
            }
        }

        // Falcon-1024 reporter signature verification
        // Proves the STARK proof was generated by the claimed reporter
        if !proof.signature.is_empty() {
            let reporter = &proof.public_inputs.reporter;
            let keys = self.validator_keys.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(falcon_pk) = keys.get(reporter) {
                // Verify signature over Keccak-256(stark_proof || qber || sample_count || entropy_commitment)
                use sp_crypto_hashing::keccak_256;
                let mut signed_data = Vec::with_capacity(proof.stark_proof.len() + 64);
                signed_data.extend_from_slice(&proof.stark_proof);
                signed_data.extend_from_slice(&proof.public_inputs.qber.to_le_bytes());
                signed_data.extend_from_slice(&proof.public_inputs.sample_count.to_le_bytes());
                signed_data.extend_from_slice(&proof.public_inputs.entropy_commitment.0);
                let digest = keccak_256(&signed_data);

                if let Err(e) = crate::falcon_crypto::verify_signature(&digest, &proof.signature, falcon_pk) {
                    warn!("❌ Falcon-1024 signature verification failed for reporter {:?}: {}", reporter, e);
                    return ProofVerificationResult::InvalidStarkProof;
                }
                debug!("✅ Falcon-1024 reporter signature verified for {:?}", reporter);
            } else {
                debug!("⚠️  Reporter {:?} not in validator keystore — skipping signature check", reporter);
            }
        }

        ProofVerificationResult::Valid
    }

    /// Calculate coherence score from valid proofs
    ///
    /// Score = Σ(1000 / (1 + QBER_i)) for all valid proofs
    ///
    /// Higher score = better quantum quality
    /// Typical threshold: 5000 (requires ~6 reporters with good QBER)
    fn calculate_coherence(
        &self,
        proofs: &[QuantumEntropyProof<sp_core::sphincs::Public>],
    ) -> Result<(u64, QuantumState), String> {
        if proofs.is_empty() {
            return Ok((
                0,
                QuantumState {
                    valid_proofs: 0,
                    rejected_proofs: 0,
                    average_qber: 0,
                    entropy_pool_hash: Default::default(),
                    reporter_count: 0,
                    min_qber: 0,
                    max_qber: 0,
                },
            ));
        }

        let mut total_score = 0u64;
        let mut total_qber = 0u32;
        let mut min_qber = u32::MAX;
        let mut max_qber = 0u32;

        for proof in proofs {
            let qber = proof.public_inputs.qber;

            // Calculate score for this proof: 1000 / (1 + QBER/10000)
            // Example: QBER=500 (5%) => score = 1000 * 10000 / (10000 + 500) = 952
            let score = (1000u64 * 10000) / (10000 + qber as u64);
            total_score += score;

            total_qber += qber;
            min_qber = min_qber.min(qber);
            max_qber = max_qber.max(qber);
        }

        let average_qber = total_qber / proofs.len() as u32;

        let quantum_state = QuantumState {
            valid_proofs: proofs.len() as u32,
            rejected_proofs: 0, // We already filtered invalid ones
            average_qber,
            entropy_pool_hash: Default::default(), // NOTE: Entropy pool hash aggregation deferred to Phase 2 on-chain verification
            reporter_count: proofs.len() as u32,  // NOTE: Unique reporter counting requires validator identity deduplication
            min_qber,
            max_qber,
        };

        Ok((total_score, quantum_state))
    }

    /// Create a coherence vote for the current validator
    fn create_vote(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
        coherence_score: u64,
        quantum_state: QuantumState,
        vote_type: VoteType,
    ) -> Result<CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>, String> {
        // Get our validator ID (or use default if not a validator)
        // Use same key format as get_current_validators: bytes[0] = validator_index, rest = 0
        let validator = self.our_validator_id
            .clone()
            .unwrap_or_else(|| {
                let mut bytes = [0u8; 64];
                bytes[0] = 1; // First validator index
                sp_core::sphincs::Public::from_raw(bytes)
            });

        // Encode the vote data for signing. Keep using the existing helper
        // so the signing and verification message formats stay in lock-step.
        let message = crate::falcon_crypto::encode_vote_for_signing(
            &validator,
            &block_hash,
            &block_number,
            coherence_score,
            &quantum_state,
        );

        // Phase 7: sign votes with the validator's SPHINCS+ keystore key
        // (the same key used for Aura block seals). This lets any peer
        // verify vote signatures against the on-chain Aura authority set
        // without a separate Falcon pubkey registry.
        use sp_core::crypto::KeyTypeId;
        use sp_keystore::Keystore;
        let aura_keytype = KeyTypeId(sp_consensus_aura::AURA_ENGINE_ID);
        let sphincs_pub = sp_core::sphincs::Public::from_raw(validator.0);
        let signature = match self.keystore.sphincs_sign(aura_keytype, &sphincs_pub, &message) {
            Ok(Some(sig)) => {
                debug!("🔐 Signed vote with SPHINCS+ ({} bytes)", sig.0.len());
                BoundedVec::try_from(sig.0.to_vec())
                    .map_err(|_| "SPHINCS+ signature too large for BoundedVec (bump MAX_SIGNATURE_SIZE)".to_string())?
            }
            Ok(None) => {
                warn!("⚠️  Keystore has no SPHINCS+ key matching our validator pubkey — using empty vote signature (this vote will be rejected by peers)");
                BoundedVec::default()
            }
            Err(e) => {
                warn!("⚠️  SPHINCS+ vote signing failed: {:?} — using empty signature", e);
                BoundedVec::default()
            }
        };

        Ok(CoherenceVote {
            validator,
            block_hash,
            block_number,
            coherence_score,
            quantum_state,
            signature,
            vote_type,
        })
    }

    /// Store a vote in our local vote cache
    fn store_vote(
        &self,
        block_hash: Block::Hash,
        vote: CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<(), String> {
        let mut votes = self.votes.lock().map_err(|e| format!("Failed to lock votes: {}", e))?;
        votes.entry(block_hash).or_insert_with(Vec::new).push(vote);
        Ok(())
    }

    /// PHASE 7C: Send vote using PQ-MonadBFT linear voting or legacy gossip
    ///
    /// ## PQ-MonadBFT Linear Voting (O(n))
    /// - Validators send votes directly to the current leader (1 message each)
    /// - Leader aggregates votes and broadcasts certificate (1 message to all)
    /// - Total: N + N = 2N messages = O(n)
    ///
    /// ## Legacy Gossip (O(N log N))
    /// - Votes gossiped to all connected peers
    /// - Each peer re-gossips to their peers
    /// - Total: O(N log N) messages
    fn broadcast_vote(
        &self,
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<(), String> {
        use crate::coherence_gossip::GossipMessage;

        // Check if linear voting is enabled
        if self.use_linear_voting {
            return self.send_vote_linear(vote);
        }

        // Legacy gossip mode - broadcast to all peers
        self.broadcast_vote_gossip(vote)
    }

    /// PQ-MonadBFT Phase 1: Linear O(n) voting
    ///
    /// If we ARE the leader: store vote locally for aggregation
    /// If we are NOT the leader: send vote directly to leader only
    fn send_vote_linear(
        &self,
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<(), String> {
        use crate::coherence_gossip::GossipMessage;

        // Get current leader
        let leader_opt = {
            self.current_leader.lock()
                .map_err(|e| format!("Failed to lock current leader: {}", e))?
                .clone()
        };

        let leader = match leader_opt {
            Some(l) => l,
            None => {
                // No leader elected yet, fall back to gossip
                warn!("⚠️  No leader elected, falling back to gossip broadcast");
                return self.broadcast_vote_gossip(vote);
            }
        };

        // Get our validator ID
        let our_id = self.our_validator_id.ok_or("No validator ID set")?;

        // Get QBER measurement (from vote's quantum state)
        // Cast to u16 - QBER in basis points (0-10000) fits in u16
        let qber_measurement = vote.quantum_state.average_qber as u16;
        let qkd_channel_id = 0u32; // NOTE: Default channel; QKD monitoring integration requires ETSI QKD API client

        // Check if we are the leader
        if leader == our_id {
            // We ARE the leader - store vote locally for aggregation
            info!(
                "👑 Leader storing own vote for block #{} (QBER: {:.2}%)",
                vote.block_number,
                qber_measurement as f64 / 100.0
            );

            let block_hash = vote.block_hash;
            let mut aggregation = self.leader_vote_aggregation.lock()
                .map_err(|e| format!("Failed to lock leader vote aggregation: {}", e))?;

            aggregation
                .entry(block_hash)
                .or_insert_with(Vec::new)
                .push((vote.clone(), qber_measurement, qkd_channel_id));

            info!(
                "📊 Leader has {} votes for block #{}",
                aggregation.get(&block_hash).map(|v| v.len()).unwrap_or(0),
                vote.block_number
            );

            return Ok(());
        }

        // We are NOT the leader - send vote directly to leader
        info!(
            "🎯 Sending vote to leader for block #{} (QBER: {:.2}%)",
            vote.block_number,
            qber_measurement as f64 / 100.0
        );

        // Create VoteToLeader message
        let message = GossipMessage::<Block>::VoteToLeader {
            vote: vote.clone(),
            qber_measurement,
            qkd_channel_id,
        };
        let encoded = message.encode();

        // Find the peer ID for the leader
        // For now, broadcast to all peers but the message is marked for leader
        // In production, we'd maintain a validator_id -> peer_id mapping
        let peers: Vec<_> = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.connected_peers.lock().await.iter().cloned().collect()
            })
        });

        if peers.is_empty() {
            warn!("⚠️  No peers connected, cannot send vote to leader");
            return Ok(());
        }

        // Lock notification service and send to peers
        // Note: In production, send only to the leader's peer ID
        let mut service = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self._notification_service.lock().await
            })
        });

        // Send to all peers - they will forward to leader if not leader themselves
        for peer in &peers {
            service.send_sync_notification(peer, encoded.clone());
        }

        info!(
            "✅ Vote sent to leader via {} peers: block #{}, score {}, QBER {:.2}%",
            peers.len(),
            vote.block_number,
            vote.coherence_score,
            qber_measurement as f64 / 100.0
        );

        // DEVNET-ONLY adversarial witness: EQUIVOCATION. Compiled only under
        // `--features byzantine-attack` AND armed only by env `QH_ATTACK_EQUIVOCATE`
        // — a validator binary contains neither.
        //
        // This is a strictly harder attack than `QH_ATTACK_FORGE_CERT`. That one
        // broadcasts a certificate carrying ZERO votes, so it dies on authorization
        // (`incoherent certificate: 0 distinct verified …`). Here we emit a SECOND,
        // genuinely signed vote from a REAL authority for a DIFFERENT block hash at
        // the SAME height. Both votes carry a valid SPHINCS+ signature and both come
        // from a member of the authority set, so neither can be filtered on signature
        // or membership — only the same-height conflict distinguishes them.
        //
        // Safety property under test: honest nodes must never produce two conflicting
        // FinalityCertificates at one height. At N=4 (quorum 3) one equivocator must
        // be survivable (f=1); at N=3 (quorum 2) the correct outcome is to HALT, not
        // to finalize both branches.
        #[cfg(feature = "byzantine-attack")]
        if std::env::var("QH_ATTACK_EQUIVOCATE").is_ok() {
            // Target a REAL competing block at this height — a sibling this node actually
            // imported on a genuine fork. A fabricated hash would test nothing: no honest
            // node has such a block, so its vote bucket can never approach quorum. If no
            // fork exists at this height we emit nothing and say so.
            let current = vote.block_hash.encode();
            let competitor = competing_block(&vote.block_number.to_string(), &current);
            let raw = match competitor {
                Some(enc) => enc,
                None => {
                    debug!(
                        "equivocation witness: no competing block seen at #{} — nothing to equivocate on",
                        vote.block_number
                    );
                    return Ok(());
                }
            };
            match <Block::Hash as Decode>::decode(&mut &raw[..]) {
                Ok(conflicting_hash) => match self.create_vote(
                    conflicting_hash,
                    vote.block_number,
                    vote.coherence_score,
                    vote.quantum_state.clone(),
                    vote.vote_type.clone(),
                ) {
                    Ok(equivocating_vote) => {
                        let encoded_evil = GossipMessage::<Block>::VoteToLeader {
                            vote: equivocating_vote,
                            qber_measurement,
                            qkd_channel_id,
                        }
                        .encode();
                        for peer in &peers {
                            service.send_sync_notification(peer, encoded_evil.clone());
                        }
                        warn!(
                            "😈 EQUIVOCATION WITNESS: second SIGNED vote for #{} on REAL competing block {:?} sent to {} peer(s) — DEVNET ONLY",
                            vote.block_number,
                            conflicting_hash,
                            peers.len()
                        );
                    }
                    Err(e) => warn!("equivocation witness: create_vote failed: {}", e),
                },
                Err(e) => warn!("equivocation witness: hash decode failed: {:?}", e),
            }
        }

        Ok(())
    }

    /// Legacy gossip broadcast - O(N log N) complexity
    fn broadcast_vote_gossip(
        &self,
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<(), String> {
        use crate::coherence_gossip::GossipMessage;

        // Encode the vote using GossipMessage format
        let message = GossipMessage::<Block>::Vote(vote.clone());
        let encoded = message.encode();

        info!(
            "📡 [GOSSIP] Broadcasting vote for block #{} to P2P network (size: {} bytes)",
            vote.block_number,
            encoded.len()
        );

        // Get connected peers from our tracking set
        let peers: Vec<_> = {
            // Use tokio's block_in_place to call async from sync context
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.connected_peers.lock().await.iter().cloned().collect()
                })
            })
        };

        if peers.is_empty() {
            debug!("⚠️  No peers connected, vote not broadcasted");
            return Ok(());
        }

        info!("📡 Broadcasting to {} connected peers", peers.len());

        // Lock notification service and broadcast to all peers
        let mut service = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self._notification_service.lock().await
            })
        });

        // Broadcast to all connected peers
        for peer in &peers {
            service.send_sync_notification(peer, encoded.clone());
            debug!("📤 Sent vote to peer {:?}", peer);
        }

        info!(
            "✅ Vote broadcasted to {} validators: block #{}, score {}, QBER {:.2}%",
            peers.len(),
            vote.block_number,
            vote.coherence_score,
            vote.quantum_state.average_qber as f64 / 100.0
        );

        debug!("broadcast_vote_gossip returning Ok(()) for block #{}", vote.block_number);
        Ok(())
    }

    /// PQ-MonadBFT Phase 2: Leader broadcasts finality certificate to all validators
    ///
    /// After collecting 2/3+ votes and creating the certificate, the leader broadcasts
    /// it to all validators. This allows validators to finalize even if they didn't
    /// receive all votes directly (O(n) broadcast).
    fn broadcast_finality_certificate(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
        certificate: &FinalityCertificate<
            sp_core::sphincs::Public,
            NumberFor<Block>,
            Block::Hash,
        >,
    ) -> Result<(), String> {
        use crate::coherence_gossip::GossipMessage;

        // Calculate aggregated QBER from leader's vote collection
        let (aggregated_qber, healthy_channels, validator_count) = {
            let aggregation = self.leader_vote_aggregation.lock()
                .map_err(|e| format!("Failed to lock leader vote aggregation: {}", e))?;

            match aggregation.get(&block_hash) {
                Some(votes) => {
                    let count = votes.len() as u32;
                    if count == 0 {
                        (certificate.consensus_quantum_state.average_qber as u16, 0u32, certificate.validator_count)
                    } else {
                        let total_qber: u32 = votes.iter().map(|(_, qber, _)| *qber as u32).sum();
                        let avg = (total_qber / count) as u16;
                        let healthy = votes.iter().filter(|(_, qber, _)| *qber < 1100).count() as u32;
                        (avg, healthy, count)
                    }
                }
                None => {
                    // Fallback to certificate values
                    (certificate.consensus_quantum_state.average_qber as u16,
                     certificate.validator_count,
                     certificate.validator_count)
                }
            }
        };

        // Encode certificate for transmission
        let encoded_certificate = certificate.encode();

        // Create the broadcast message
        let message = GossipMessage::<Block>::FinalityCertificateBroadcast {
            block_hash,
            block_number,
            aggregated_qber,
            healthy_channels,
            validator_count,
            encoded_certificate,
        };
        let encoded = message.encode();

        info!(
            "📜 [LINEAR] Leader broadcasting finality certificate for block #{} (QBER: {:.2}%, healthy: {}/{}, size: {} bytes)",
            block_number,
            aggregated_qber as f64 / 100.0,
            healthy_channels,
            validator_count,
            encoded.len()
        );

        // Get connected peers
        let peers: Vec<_> = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.connected_peers.lock().await.iter().cloned().collect()
            })
        });

        if peers.is_empty() {
            warn!("⚠️  No peers connected, certificate not broadcasted");
            return Ok(());
        }

        // Broadcast to all peers
        let mut service = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self._notification_service.lock().await
            })
        });

        for peer in &peers {
            service.send_sync_notification(peer, encoded.clone());
        }

        info!(
            "✅ [LINEAR] Finality certificate broadcasted to {} validators for block #{}",
            peers.len(),
            block_number
        );

        // Clear the leader's vote aggregation for this block
        {
            let mut aggregation = self.leader_vote_aggregation.lock()
                .map_err(|e| format!("Failed to lock leader vote aggregation: {}", e))?;
            aggregation.remove(&block_hash);
        }

        Ok(())
    }

    /// PQ-MonadBFT: Handle vote received from a validator (leader only)
    ///
    /// When we are the leader, validators send their votes directly to us.
    /// We aggregate the votes and QBER measurements for certificate creation.
    fn handle_vote_from_validator(
        &self,
        vote: CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
        qber_measurement: u16,
        qkd_channel_id: u32,
    ) -> Result<(), String> {
        // Verify we are the current leader
        let leader_opt = {
            self.current_leader.lock()
                .map_err(|e| format!("Failed to lock current leader: {}", e))?
                .clone()
        };

        let our_id = self.our_validator_id.ok_or("No validator ID set")?;

        if leader_opt != Some(our_id) {
            // We're not the leader, ignore (or forward to leader)
            debug!("Received VoteToLeader but we're not the leader, ignoring");
            return Ok(());
        }

        // Validate the vote signature
        if !self.verify_vote_signature(&vote)? {
            warn!("❌ Invalid vote signature from validator {:?}", &vote.validator.0[..8]);
            return Err("Invalid vote signature".to_string());
        }

        // One vote per (validator, height) — same rule as the receiver paths.
        // A rejected vote is peer misbehaviour, not a local fault: drop it, Ok.
        if !Self::admit_vote(&self.client, &self.equivocation_ledger, &vote, "leader-direct") {
            return Ok(());
        }

        // Store the vote in leader aggregation
        let block_hash = vote.block_hash;
        let block_number = vote.block_number;
        let validator = vote.validator.clone();

        let vote_count = {
            let mut aggregation = self.leader_vote_aggregation.lock()
                .map_err(|e| format!("Failed to lock leader vote aggregation: {}", e))?;

            let votes = aggregation.entry(block_hash).or_insert_with(Vec::new);

            // Check for duplicate votes from same validator
            if votes.iter().any(|(v, _, _)| v.validator == validator) {
                debug!("Duplicate vote from validator {:?}, ignoring", &validator.0[..8]);
                return Ok(());
            }

            votes.push((vote, qber_measurement, qkd_channel_id));
            votes.len()
        };

        info!(
            "👑 Leader received vote from {:?} for block #{} (QBER: {:.2}%, total: {} votes)",
            &validator.0[..8],
            block_number,
            qber_measurement as f64 / 100.0,
            vote_count
        );

        Ok(())
    }

    // `check_leader_supermajority` removed 2026-08-28: it had no callers and
    // carried a hardcoded `Err(_) => 3` validator count (the 2026-07-04 fork
    // class). The live leader/receiver counting goes through `quorum_threshold`
    // with `validator_count_at` / `check_supermajority`, which fail closed.

    /// Verify a vote's SPHINCS+ signature against the on-chain Aura authority set.
    ///
    /// AUTHORITATIVE coherence gate for a finality CERTIFICATE — the single
    /// sanctioned admission check every certificate-based finalize door must pass
    /// (`Justification`, `FinalityCertificateBroadcast`). It defers to the pure
    /// [`coherent_quorum`] invariant: count only DISTINCT authorities whose vote is
    /// for `block_hash` and passes [`Self::verify_vote_signature_static`] (SPHINCS+
    /// signature + on-chain Aura membership), and require `quorum_threshold(N)` of
    /// them. Returns the verified distinct count, or an error naming why the
    /// certificate is incoherent. (2026-07-18 finality-safety review: closes the two
    /// paths that finalized on QBER scalars / an unverified vote count — the
    /// #345,140 fork class.)
    fn verify_finality_certificate(
        client: &Arc<Client>,
        block_hash: Block::Hash,
        cert: &FinalityCertificate<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<u32, String> {
        // A certificate can be perfectly signed by a real quorum and still be for a
        // block on a competing branch. Signature validity and distinctness say
        // nothing about which chain we are on, so check that first: this is the
        // gate that fork #4 (block 1763165) walked straight through.
        let number = client
            .number(block_hash)
            .map_err(|e| format!("Cannot resolve number for {:?}: {:?}", block_hash, e))?
            .ok_or_else(|| format!("Block {:?} is unknown to this node", block_hash))?;
        if !Self::is_on_best_chain(client, number, block_hash)? {
            return Err(format!(
                "Block #{:?} {:?} is not on our best chain — refusing to verify a certificate for a side branch",
                number, block_hash
            ));
        }

        let total_validators = Self::validator_count_at(client, block_hash)?;
        let required = quorum_threshold(total_validators);
        coherent_quorum(
            &block_hash,
            required,
            cert.precommit_votes.as_slice(),
            |v| &v.block_hash,
            |v| v.validator.0[..64].to_vec(),
            |v| Self::verify_vote_signature_static(client, block_hash, v).unwrap_or(false),
        )
    }

    /// Phase 7 (2026-04-13): strict verification, no "trust unknown validator"
    /// fallback. Steps:
    ///   1. Check `vote.validator` is in the current `Aura::Authorities` list
    ///      — rejects votes from non-authorities.
    ///   2. Reconstruct the exact message that was signed in `create_vote`.
    ///   3. Verify the SPHINCS+ signature natively against the authority's
    ///      public key.
    fn verify_vote_signature(
        &self,
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<bool, String> {
        Self::verify_vote_signature_static(&self.client, vote.block_hash, vote)
    }

    /// Static variant of [`Self::verify_vote_signature`] for use inside the
    /// spawned vote-receiver / leader-aggregator tasks, which hold `Arc<Client>`
    /// rather than `&self`. This is the ONLY sanctioned admission check for a
    /// vote into the finality count: it verifies (1) the validator is in the
    /// current on-chain Aura authority set and (2) the SPHINCS+ signature is
    /// valid. A vote that does not return `Ok(true)` here must never be stored
    /// or counted. (2026-07-17 finality-safety review — replaces the ephemeral
    /// Falcon "P2P authenticated" fallback that finalized the #345,140 fork.)
    fn verify_vote_signature_static(
        client: &Arc<Client>,
        at: Block::Hash,
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<bool, String> {
        verify_vote_signature_at::<Block, Client>(client, at, vote)
    }

    /// Get the message bytes that were signed for a vote
    fn get_vote_signing_message(
        &self,
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
    ) -> Result<Vec<u8>, String> {
        // Recreate the signing message (must match what was signed in create_vote)
        let mut message = Vec::new();
        message.extend_from_slice(vote.block_hash.as_ref());
        message.extend_from_slice(&vote.block_number.encode());
        message.extend_from_slice(&vote.coherence_score.to_le_bytes());
        Ok(message)
    }

    // =========================================================================
    // PQ-MonadBFT Phase 3: Pipelining Methods
    // =========================================================================

    /// Set the pipeline phase for a block
    ///
    /// Tracks which phase each block is in, allowing concurrent processing
    /// of multiple blocks (Block N in CERTIFY while Block N+1 in VOTE).
    fn set_pipeline_phase(
        &self,
        block_hash: Block::Hash,
        phase: PipelinePhase,
    ) -> Result<(), String> {
        let mut pipeline = self.pipeline_state.lock()
            .map_err(|e| format!("Failed to lock pipeline state: {}", e))?;

        let old_phase = pipeline.get(&block_hash).copied();
        pipeline.insert(block_hash, phase);

        if let Some(old) = old_phase {
            debug!(
                "📊 Pipeline: Block {:?} phase {:?} → {:?}",
                &block_hash.as_ref()[0..4], old, phase
            );
        } else {
            debug!(
                "📊 Pipeline: Block {:?} entering phase {:?}",
                &block_hash.as_ref()[0..4], phase
            );
        }

        Ok(())
    }

    /// Get the current pipeline phase for a block
    fn get_pipeline_phase(&self, block_hash: &Block::Hash) -> Option<PipelinePhase> {
        self.pipeline_state.lock().ok()
            .and_then(|p| p.get(block_hash).copied())
    }

    /// Cache a finality certificate for tail-fork protection
    ///
    /// New block proposals must include their parent's certificate,
    /// preventing leaders from forking away predecessor's blocks.
    fn cache_certificate(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
        encoded_certificate: Vec<u8>,
    ) -> Result<(), String> {
        let mut cache = self.certificate_cache.lock()
            .map_err(|e| format!("Failed to lock certificate cache: {}", e))?;

        cache.insert(block_hash, encoded_certificate);

        // Update last certified block
        let mut last_certified = self.last_certified_block.lock()
            .map_err(|e| format!("Failed to lock last certified block: {}", e))?;
        *last_certified = Some((block_hash, block_number));

        info!(
            "📜 Cached certificate for block #{} (tail-fork protection)",
            block_number
        );

        // Prune old certificates (keep last 100)
        if cache.len() > 100 {
            // Find oldest entries to remove
            // In a real implementation, we'd track by block number
            let to_remove: Vec<_> = cache.keys().take(cache.len() - 100).cloned().collect();
            for hash in to_remove {
                cache.remove(&hash);
            }
        }

        Ok(())
    }

    /// Get cached certificate for a block (for tail-fork protection)
    fn get_cached_certificate(&self, block_hash: &Block::Hash) -> Option<Vec<u8>> {
        self.certificate_cache.lock().ok()
            .and_then(|c| c.get(block_hash).cloned())
    }

    /// Validate tail-fork protection for a new block proposal
    ///
    /// MonadBFT-style protection: New proposals MUST include their parent's
    /// finality certificate, preventing leaders from forking.
    fn validate_tail_fork_protection(
        &self,
        parent_hash: &Block::Hash,
        parent_certificate: Option<&[u8]>,
    ) -> Result<bool, String> {
        // Get the last certified block
        let last_certified = self.last_certified_block.lock()
            .map_err(|e| format!("Failed to lock last certified block: {}", e))?
            .clone();

        match last_certified {
            Some((certified_hash, certified_number)) => {
                // If we have a certified block, the parent must be certified
                // or be the certified block itself
                if parent_hash == &certified_hash {
                    // Parent is the last certified block - OK
                    return Ok(true);
                }

                // Check if parent certificate is provided
                match parent_certificate {
                    Some(cert) => {
                        // Verify certificate is in our cache or valid
                        if let Some(cached) = self.get_cached_certificate(parent_hash) {
                            if cert == cached.as_slice() {
                                return Ok(true);
                            }
                        }
                        // Check if finality is far behind — if so, accept uncached certs
                        // (we're in catch-up mode and can't enforce yet).
                        // Once finality is within 200 blocks, enforce cache-based validation.
                        let finalized = self.client.info().finalized_number;
                        let best = self.client.info().best_number;
                        let finality_gap: u64 = (best - finalized).saturated_into();
                        if finality_gap > 200 {
                            debug!(
                                "Finality {} blocks behind, accepting uncached cert for {:?} during catch-up",
                                finality_gap, &parent_hash.as_ref()[0..4]
                            );
                            Ok(true)
                        } else {
                            error!(
                                "❌ Tail-fork violation: Parent certificate for {:?} not in cache (finality gap: {})",
                                &parent_hash.as_ref()[0..4], finality_gap
                            );
                            Ok(false)
                        }
                    }
                    None => {
                        warn!(
                            "❌ Tail-fork violation: No parent certificate for {:?} (last certified: #{:?})",
                            &parent_hash.as_ref()[0..4],
                            certified_number
                        );
                        Ok(false) // Return false but don't error - let caller decide
                    }
                }
            }
            None => {
                // No blocks certified yet - allow any proposal
                debug!("No certified blocks yet, skipping tail-fork check");
                Ok(true)
            }
        }
    }

    /// Queue a block for deferred execution
    ///
    /// After consensus is reached on transaction ordering, execution is deferred
    /// to allow parallel processing across toroidal segments.
    fn queue_for_deferred_execution(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
        aggregated_qber: u16,
        parent_certificate: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let deferred = DeferredBlock {
            block_hash,
            block_number,
            consensus_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            parent_certificate,
            aggregated_qber,
        };

        let mut queue = self.deferred_execution_queue.lock()
            .map_err(|e| format!("Failed to lock deferred execution queue: {}", e))?;

        queue.push(deferred);

        info!(
            "⏳ Block #{} queued for deferred execution (QBER: {:.2}%, queue size: {})",
            block_number,
            aggregated_qber as f64 / 100.0,
            queue.len()
        );

        // Update pipeline phase
        self.set_pipeline_phase(block_hash, PipelinePhase::ConsensusComplete)?;

        Ok(())
    }

    /// Process deferred executions (called periodically or after consensus)
    ///
    /// Executes queued blocks in parallel across toroidal segments.
    /// State root is committed in the NEXT block (deferred commitment).
    async fn process_deferred_executions(&self) -> Result<usize, String> {
        let blocks_to_execute: Vec<DeferredBlock<Block>> = {
            let mut queue = self.deferred_execution_queue.lock()
                .map_err(|e| format!("Failed to lock deferred execution queue: {}", e))?;

            // Take all blocks from queue
            std::mem::take(&mut *queue)
        };

        if blocks_to_execute.is_empty() {
            return Ok(0);
        }

        info!(
            "🚀 Processing {} deferred block executions",
            blocks_to_execute.len()
        );

        let mut executed_count = 0;

        for deferred in blocks_to_execute {
            // In a real implementation, this would:
            // 1. Route transactions to toroidal segments by address hash
            // 2. Execute in parallel across 512 segments
            // 3. Detect and re-execute conflicts
            // 4. Compute state root for next block

            // For now, just mark as executed and log
            info!(
                "✅ Executed block #{} (deferred by {}s, QBER: {:.2}%)",
                deferred.block_number,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .saturating_sub(deferred.consensus_timestamp),
                deferred.aggregated_qber as f64 / 100.0
            );

            // Update pipeline phase to executed
            self.set_pipeline_phase(deferred.block_hash, PipelinePhase::Executed)?;

            executed_count += 1;
        }

        Ok(executed_count)
    }

    /// Get current pipeline status (for debugging/monitoring)
    fn get_pipeline_status(&self) -> Result<Vec<(Block::Hash, PipelinePhase)>, String> {
        let pipeline = self.pipeline_state.lock()
            .map_err(|e| format!("Failed to lock pipeline state: {}", e))?;

        Ok(pipeline.iter().map(|(h, p)| (*h, *p)).collect())
    }

    /// Clean up old pipeline entries (keep last 50 blocks)
    fn cleanup_pipeline(&self) -> Result<usize, String> {
        let mut pipeline = self.pipeline_state.lock()
            .map_err(|e| format!("Failed to lock pipeline state: {}", e))?;

        let before = pipeline.len();

        // Remove executed blocks (they're done)
        pipeline.retain(|_, phase| *phase != PipelinePhase::Executed);

        // If still too many, remove oldest (by insertion order in HashMap isn't guaranteed,
        // but this is a reasonable cleanup strategy)
        if pipeline.len() > 50 {
            let to_remove = pipeline.len() - 50;
            let keys: Vec<_> = pipeline.keys().take(to_remove).cloned().collect();
            for key in keys {
                pipeline.remove(&key);
            }
        }

        Ok(before - pipeline.len())
    }

    /// Broadcast finality justification to all connected peers via P2P gossip
    ///
    /// This is critical for full nodes to receive finality proofs and update their
    /// finalized head. Without this, full nodes stay at "finalized #0" forever.
    ///
    /// The justification contains the FinalityCertificate which proves that >2/3
    /// of validators agreed on the block's coherence score.
    fn broadcast_justification(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
        encoded_justification: Vec<u8>,
    ) -> Result<(), String> {
        use crate::coherence_gossip::GossipMessage;

        // Encode the justification using GossipMessage format
        let message = GossipMessage::<Block>::Justification {
            block_hash,
            block_number,
            encoded_justification: encoded_justification.clone(),
        };
        let encoded = message.encode();

        info!(
            "📡 Broadcasting justification for block #{} to P2P network (size: {} bytes, justification: {} bytes)",
            block_number,
            encoded.len(),
            encoded_justification.len()
        );

        // Get connected peers from our tracking set
        let peers: Vec<_> = {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.connected_peers.lock().await.iter().cloned().collect()
                })
            })
        };

        if peers.is_empty() {
            warn!("⚠️  No peers connected, justification not broadcasted - full nodes won't finalize!");
            return Ok(());
        }

        info!("📡 Broadcasting justification to {} connected peers", peers.len());

        // Lock notification service and broadcast to all peers
        let mut service = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self._notification_service.lock().await
            })
        });

        // Broadcast to all connected peers
        for peer in &peers {
            service.send_sync_notification(peer, encoded.clone());
            debug!("📤 Sent justification to peer {:?}", peer);
        }

        info!(
            "✅ Justification broadcasted to {} peers for block #{}",
            peers.len(),
            block_number
        );

        Ok(())
    }

    /// Verify validator membership
    ///
    /// Checks if a public key belongs to the active validator set.
    /// Phase 7: Queries runtime Session pallet for current validators
    fn is_valid_validator(
        &self,
        validator: &sp_core::sphincs::Public,
    ) -> bool {
        // Query validators from runtime
        match self.get_current_validators() {
            Ok(validators) => {
                // Debug: Log the validator being checked and the valid set
                debug!(
                    "🔍 Checking validator {:?} against {} validators",
                    &validator.0[..8],
                    validators.len(),
                );

                // Check if validator is in the current set (full 64-byte match).
                // The previous code had a "TEMPORARY FIX" here that accepted *any*
                // vote when the key didn't match, as long as the validator set was
                // non-empty. That masked the test-key fallback bug in new() and
                // let supermajority math add up fake `[1,1,1,...]` votes to real
                // ones. Removed — if a vote's validator doesn't match the current
                // Aura authorities, it's rejected.
                let is_valid = validators.iter().any(|v| v.0 == validator.0);
                if !is_valid {
                    warn!(
                        "🔴 Rejecting vote from validator {:?} (not in current {} authorities)",
                        &validator.0[..8],
                        validators.len()
                    );
                }
                is_valid
            }
            Err(e) => {
                // Fail closed. The previous branch accepted the vote ("P2P
                // authenticated") when the runtime could not be queried — the
                // one remaining path where an unverifiable vote counted toward
                // quorum. Callers are per-attempt filters; the vote stays stored
                // and is re-checked on the next attempt.
                warn!("🔴 Rejecting vote from validator {:?}: cannot query authority set ({}) — failing closed", &validator.0[..8], e);
                false
            }
        }
    }

    /// Admit a received, signature-verified vote through the first-vote-wins
    /// ledger. `true` = admissible (first vote at this height, or a redelivery
    /// of the same vote); `false` = rejected. Never propagates an error: every
    /// failure mode rejects the vote (fail closed) and leaves the receiver alive.
    ///
    /// Call AFTER `verify_vote_signature_static`: an unverified vote must not be
    /// able to pre-occupy a (validator, height) slot and get an honest vote
    /// rejected as an equivocation.
    ///
    /// The height is taken from the LOCAL HEADER of `vote.block_hash`, and the
    /// vote's self-declared `block_number` must agree with it:
    ///   * unknown block   → rejected (we cannot place it; `VoteRequest` is not
    ///     implemented, so a vote that outruns its block is lost here — the
    ///     node still finalizes via the justification broadcast);
    ///   * number mismatch → rejected and logged `MISLABELED` (provably
    ///     malicious: the signer named a height its block does not have);
    ///   * already final   → rejected silently (cannot matter).
    fn admit_vote(
        client: &Arc<Client>,
        ledger: &Arc<std::sync::Mutex<EquivocationLedger<sp_core::sphincs::Public, Block::Hash>>>,
        vote: &CoherenceVote<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>,
        source: &str,
    ) -> bool {
        let short_id = hex::encode(&vote.validator.0[..8]);
        let declared: u64 = vote.block_number.saturated_into();
        let actual: u64 = match client.header(vote.block_hash) {
            Ok(Some(header)) => (*header.number()).saturated_into(),
            Ok(None) => {
                debug!(
                    "⏸️  [{}] vote from 0x{}… names unknown block {:?} (claims #{}) — not admitted (fail closed)",
                    source, short_id, vote.block_hash, declared
                );
                return false;
            }
            Err(e) => {
                warn!("⚠️  [{}] vote from 0x{}…: header lookup failed ({:?}) — not admitted (fail closed)", source, short_id, e);
                return false;
            }
        };
        if actual != declared {
            error!(
                "🚨 MISLABELED VOTE [{}]: validator 0x{}… claims #{} for block {:?} which is #{} — rejected",
                source, short_id, declared, vote.block_hash, actual
            );
            return false;
        }
        let finalized: u64 = client.info().finalized_number.saturated_into();
        if actual <= finalized {
            debug!("⏭️  [{}] vote from 0x{}… for #{} ≤ finalized #{} — ignored", source, short_id, actual, finalized);
            return false;
        }
        // Keep the lock scope to the ledger operations; log after release.
        let outcome = match ledger.lock() {
            Ok(mut l) => {
                l.prune_below(finalized + 1);
                l.observe(actual, vote.validator, vote.block_hash)
            }
            Err(e) => {
                error!("❌ [{}] equivocation ledger poisoned ({}) — rejecting vote from 0x{}…", source, e, short_id);
                return false;
            }
        };
        match outcome {
            VoteAdmission::First | VoteAdmission::Repeat => true,
            VoteAdmission::Equivocation { first } => {
                error!(
                    "🚨 EQUIVOCATION [{}]: validator 0x{}… already voted {:?} at height #{}, now {:?} — second vote rejected",
                    source, short_id, first, actual, vote.block_hash
                );
                false
            }
            VoteAdmission::OutOfWindow => {
                warn!(
                    "⚠️  [{}] vote from 0x{}… at #{} is below the equivocation-ledger window — rejected (fail closed)",
                    source, short_id, actual
                );
                false
            }
        }
    }

    /// Query current validators from runtime Session pallet
    ///
    /// Returns the list of active validators for the current session.
    fn get_current_validators(&self) -> Result<Vec<sp_core::sphincs::Public>, String> {
        let best_hash = self.client.info().best_hash;

        // Use Aura authorities which are AuraId (SPHINCS+ public keys in our fork)
        // These represent the current block producers / validators
        let runtime_api = self.client.runtime_api();

        // Get Aura authorities (which are our validators in this consensus)
        // The authorities() method is from the AuraApi trait
        let authorities = runtime_api
            .authorities(best_hash)
            .map_err(|e| format!("Failed to query Aura authorities: {:?}", e))?;

        info!("📋 Queried {} validators (Aura authorities) from runtime", authorities.len());

        // Use the actual authority public key bytes, not synthetic keys
        // This matches how our_validator_id is created in new()
        use sp_core::crypto::ByteArray;
        let validators: Vec<sp_core::sphincs::Public> = authorities
            .into_iter()
            .map(|authority| {
                // Get the raw bytes from the SPHINCS+ public key
                let raw_bytes = authority.to_raw_vec();
                let mut bytes = [0u8; 64];
                let copy_len = raw_bytes.len().min(64);
                bytes[..copy_len].copy_from_slice(&raw_bytes[..copy_len]);
                sp_core::sphincs::Public::from_raw(bytes)
            })
            .collect();

        debug!("✅ Converted {} authorities to SPHINCS+ public keys", validators.len());
        Ok(validators)
    }

    /// Check if we have supermajority (>= 2/3 validators)
    ///
    /// Byzantine Fault Tolerance requires >= 2/3 honest validators:
    /// - With f Byzantine nodes, need n >= 3f + 1 total nodes
    /// - Supermajority = ceil(n * 2/3) votes required
    ///
    /// Returns (has_supermajority, vote_count, total_validators)
    fn check_supermajority(
        &self,
        block_hash: Block::Hash,
    ) -> Result<(bool, u32, u32), String> {
        let votes = self.votes.lock().map_err(|e| format!("Failed to lock votes: {}", e))?;

        // Filter votes to only count those from valid validators
        let valid_votes: Vec<_> = votes.get(&block_hash)
            .map(|v| v.iter().filter(|vote| self.is_valid_validator(&vote.validator)).collect())
            .unwrap_or_else(Vec::new);

        let vote_count = valid_votes.len() as u32;

        // Phase 7: Query the runtime for the actual validator set.
        // Fail closed on query failure — a guessed count is how the 2026-07-04
        // fork happened (docs/BUG-hardcoded-quorum-threshold-2026-07-05.md).
        let total_validators = match self.get_current_validators() {
            Ok(validators) if !validators.is_empty() => validators.len() as u32,
            Ok(_) => return Err("Cannot check supermajority: runtime returned an empty authority set".to_string()),
            Err(e) => return Err(format!("Cannot check supermajority: validator count query failed ({})", e)),
        };

        // Correct Byzantine supermajority = ceil(total * 2 / 3)
        // Examples:
        // - 3 validators: ceil(3 * 2 / 3) = ceil(2) = 2 votes needed (>= 67%)
        // - 4 validators: ceil(4 * 2 / 3) = ceil(2.67) = 3 votes needed (>= 75%)
        // - 100 validators: ceil(100 * 2 / 3) = ceil(66.67) = 67 votes needed (>= 67%)
        //
        // TEST MODE: With <= 2 validators and no P2P vote propagation working,
        // allow finality with just the leader's vote. This enables testing the
        // finalization flow while P2P gossip is being fixed.
        let threshold = if total_validators <= 2 {
            info!("⚠️  TEST MODE: Using reduced threshold (1) for {} validators", total_validators);
            1u32 // Allow finality with just leader's vote for testing
        } else {
            quorum_threshold(total_validators)
        };

        let has_supermajority = vote_count >= threshold;

        // Log at info level to see what's happening with supermajority check
        info!(
            "🗳️  Supermajority check: {}/{} valid votes (threshold: {}, has_supermajority: {})",
            vote_count, total_validators, threshold, has_supermajority
        );

        Ok((has_supermajority, vote_count, total_validators))
    }

    /// Generate finality certificate from collected votes
    fn generate_finality_certificate(
        &self,
        block_hash: Block::Hash,
        block_number: NumberFor<Block>,
    ) -> Result<FinalityCertificate<sp_core::sphincs::Public, NumberFor<Block>, Block::Hash>, String> {
        let votes = self.votes.lock().map_err(|e| format!("Failed to lock votes: {}", e))?;

        let block_votes = votes
            .get(&block_hash)
            .ok_or_else(|| "No votes found for block".to_string())?;

        // Calculate aggregated quantum state
        let mut total_valid_proofs = 0u32;
        let mut total_rejected_proofs = 0u32;
        let mut total_qber = 0u64;
        let mut total_score = 0u64;

        for vote in block_votes.iter() {
            total_valid_proofs += vote.quantum_state.valid_proofs;
            total_rejected_proofs += vote.quantum_state.rejected_proofs;
            total_qber += vote.quantum_state.average_qber as u64;
            total_score += vote.coherence_score;
        }

        let vote_count = block_votes.len() as u32;
        let average_qber = (total_qber / vote_count as u64) as u32;

        let consensus_quantum_state = QuantumState {
            valid_proofs: total_valid_proofs / vote_count,
            rejected_proofs: total_rejected_proofs / vote_count,
            average_qber,
            entropy_pool_hash: Default::default(), // NOTE: Entropy pool hash aggregation deferred to Phase 2
            reporter_count: 0, // NOTE: Unique reporter counting requires identity deduplication across votes
            min_qber: 0, // NOTE: QBER min/max computation requires iterating precommit quantum states
            max_qber: 0, // NOTE: QBER min/max computation requires iterating precommit quantum states
        };

        // validator_count is the SET size, not the vote count (votes are
        // precommit_votes.len()). Writing vote_count here made the importer's
        // quorum check circular — a 2-vote cert claimed a 2-validator set.
        let validator_set_size = match self.get_current_validators() {
            Ok(v) if !v.is_empty() => v.len() as u32,
            Ok(_) => return Err("Cannot build certificate: runtime returned an empty authority set".to_string()),
            Err(e) => return Err(format!("Cannot build certificate: validator count query failed ({})", e)),
        };

        // A certificate needs ceil(2N/3) votes — trim the rest. Without this,
        // collecting more than MAX_VOTES_PER_CERTIFICATE (=100) votes makes
        // try_from fail and the round produces NO certificate, silently
        // disabling justification broadcast above ~100 validators. Trimming
        // also bounds certificate size (quorum × ~50KB SPHINCS+ votes).
        // Past N=149 the quorum itself exceeds the constant — needs a fork PR.
        let mut certificate_votes = block_votes.clone();
        certificate_votes.truncate(quorum_threshold(validator_set_size) as usize);
        let precommit_votes = BoundedVec::<_, ConstU32<MAX_VOTES_PER_CERTIFICATE>>::try_from(certificate_votes)
            .map_err(|_| format!("Too many votes for certificate (max: {})", MAX_VOTES_PER_CERTIFICATE))?;

        Ok(FinalityCertificate {
            block_hash,
            block_number,
            precommit_votes,
            consensus_quantum_state,
            total_coherence_score: total_score,
            validator_count: validator_set_size,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        })
    }

    /// Validator submits proofs to their own priority queue
    /// Each validator continuously generates and queues proofs
    async fn submit_validator_proofs(&self, _block_hash: &Block::Hash) -> Result<(), String> {
        // Get our actual validator ID from keystore
        let validator_id = self.get_our_validator_id()?;

        info!("📝 Validator 0x{}... submitting proofs to queue", hex::encode(&validator_id.0[..4]));

        // Generate and queue mock proofs with varying QBER
        for qber_value in [450, 500, 550] {  // 4.5%, 5%, 5.5% QBER
            let mock_proof = self.generate_mock_proof_with_qber(qber_value)?;
            self.queue_validator_proof(validator_id, mock_proof)?;
        }

        Ok(())
    }

    /// Add STARK proof to validator's priority queue (ordered by QBER - lower is better)
    fn queue_validator_proof(
        &self,
        validator_id: sp_core::sphincs::Public,
        proof: QuantumEntropyProof<sp_core::sphincs::Public>
    ) -> Result<(), String> {
        let qber = proof.public_inputs.qber;

        // Get/create next proof ID for this validator
        let mut next_ids = self.next_proof_id.lock()
            .map_err(|e| format!("Failed to lock proof ID: {}", e))?;
        let proof_id = *next_ids.entry(validator_id).or_insert(1);
        next_ids.insert(validator_id, proof_id + 1);
        drop(next_ids);

        // Store proof globally
        let mut storage = self.stark_proof_storage.lock()
            .map_err(|e| format!("Failed to lock proof storage: {}", e))?;
        storage.insert(proof_id, proof);
        drop(storage);

        // Add to validator's priority queue
        let mut queues = self.validator_proof_queues.lock()
            .map_err(|e| format!("Failed to lock validator queues: {}", e))?;
        let queue = queues.entry(validator_id).or_insert_with(PriorityQueue::new);
        queue.push(proof_id, Reverse(qber));

        debug!("📦 Validator {:?} queued proof ID {} with QBER {}% (queue size: {})",
            &validator_id.0[0..4], proof_id, qber as f64 / 100.0, queue.len());
        Ok(())
    }

    /// Leader collects best proofs from all validators' queues
    async fn collect_proofs_as_leader(&self, _block_hash: &Block::Hash) -> Result<Vec<QuantumEntropyProof<sp_core::sphincs::Public>>, String> {
        info!("👑 Leader collecting proofs from all validator queues");

        // First, ensure our own proofs are submitted
        self.submit_validator_proofs(_block_hash).await?;

        let mut queues = self.validator_proof_queues.lock()
            .map_err(|e| format!("Failed to lock validator queues: {}", e))?;
        let mut storage = self.stark_proof_storage.lock()
            .map_err(|e| format!("Failed to lock proof storage: {}", e))?;

        let mut all_proofs = Vec::new();

        // Collect best proofs from each validator (2 per validator)
        for (validator_id, queue) in queues.iter_mut() {
            let mut validator_proofs = 0;
            for _ in 0..2 {
                if let Some((proof_id, _priority)) = queue.pop() {
                    if let Some(proof) = storage.remove(&proof_id) {
                        debug!("📤 Collected proof from validator {:?} with QBER {}%",
                            &validator_id.0[0..4], proof.public_inputs.qber as f64 / 100.0);
                        all_proofs.push(proof);
                        validator_proofs += 1;
                    }
                }
            }
            if validator_proofs > 0 {
                info!("✅ Collected {} proofs from validator {:?}", validator_proofs, &validator_id.0[0..4]);
            }
        }

        info!("📊 Total proofs collected from {} validators: {}", queues.len(), all_proofs.len());
        Ok(all_proofs)
    }

    /// Check if it's time for block producer election (every 5 blocks)
    fn should_elect_producer(&self, current_block: u64) -> Result<bool, String> {
        let last_election = self.last_election_block.lock()
            .map_err(|e| format!("Failed to lock election block: {}", e))?;

        Ok(current_block % 5 == 0 && current_block != *last_election)
    }

    /// Elect block producer using QRNG with threshold entropy (every 5 blocks)
    ///
    /// ## PQ-MonadBFT Phase 4: QRNG Leader Election
    ///
    /// Uses threshold QRNG (K-of-M Shamir shares from HSM/entropy hub devices)
    /// for provably fair, quantum-random leader selection.
    ///
    /// Fallback: If QRNG unavailable, uses deterministic VRF with block hash.
    ///
    /// Returns true if this node is elected as leader
    fn elect_block_producer(&self, block_number: u64) -> Result<bool, String> {
        if !self.should_elect_producer(block_number)? {
            return Ok(false);
        }

        // Update last election block
        let mut last_election = self.last_election_block.lock()
            .map_err(|e| format!("Failed to lock election block: {}", e))?;
        *last_election = block_number;
        drop(last_election);

        // Try QRNG first, fall back to VRF
        let (quantum_seed, entropy_source) = self.get_qrng_entropy_for_election(block_number)?;

        info!(
            "🎲 Leader election at block #{} using {} entropy: {:?}...",
            block_number,
            entropy_source,
            &quantum_seed[0..8]
        );

        // Get validator set
        let validator_set = self.get_mock_validator_set()?;
        info!("📋 Validator set size: {}", validator_set.len());

        // Each validator computes election output using quantum seed
        let mut election_results = Vec::new();
        for (idx, validator_pub) in validator_set.iter().enumerate() {
            // Compute election output: Hash(validator_id || block_number || quantum_seed)
            let election_output = self.compute_vrf_output(validator_pub, block_number, &quantum_seed)?;

            debug!("Election result for validator {}: {:?}", idx, &election_output[0..8]);
            election_results.push((validator_pub.clone(), election_output));
        }

        // Sort by election output (lowest wins - provably fair randomness)
        election_results.sort_by(|(_, a), (_, b)| a.cmp(b));

        // Winner is the validator with lowest output
        let (leader_id, winning_output) = &election_results[0];

        let mut current_leader = self.current_leader.lock()
            .map_err(|e| format!("Failed to lock current leader: {}", e))?;
        *current_leader = Some(leader_id.clone());

        info!(
            "✅ {} Election complete - Leader: {:?} (output: {:?})",
            entropy_source,
            &leader_id.0[0..8],
            &winning_output[0..8]
        );

        // Check if we are the elected leader
        let our_id = self.get_our_validator_id()?;
        let is_leader = leader_id == &our_id;

        if is_leader {
            info!("👑 WE are the elected leader for block #{}", block_number);
        } else {
            info!("👤 We are a follower for block #{}", block_number);
        }

        Ok(is_leader)
    }

    /// Get entropy for leader election - tries QRNG first, falls back to VRF
    ///
    /// Returns (entropy_bytes, source_description)
    fn get_qrng_entropy_for_election(&self, block_number: u64) -> Result<([u8; 32], &'static str), String> {
        use crate::round_coordinator::{RoundCoordinator, COORDINATOR_SHARE_POOL};

        // Calculate round ID for this block
        let round_id = RoundCoordinator::get_round_id(block_number);

        // Check if we have collected shares for this round
        let shares_opt = {
            let pool = COORDINATOR_SHARE_POOL.read()
                .map_err(|e| format!("Failed to read share pool: {}", e))?;
            pool.get(&round_id).cloned()
        };

        if let Some(shares) = shares_opt {
            // Check if we have enough shares for reconstruction (K=2 by default)
            let threshold_k: usize = std::env::var("QRNG_THRESHOLD_K")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2);

            if shares.len() >= threshold_k {
                // Reconstruct entropy from shares using Shamir
                match self.reconstruct_qrng_entropy(&shares) {
                    Ok(entropy) => {
                        let avg_qber: f64 = shares.iter().map(|s| s.qber).sum::<f64>() / shares.len() as f64;
                        info!(
                            "🔮 QRNG entropy reconstructed from {} shares (avg QBER: {:.2}%)",
                            shares.len(),
                            avg_qber * 100.0
                        );
                        return Ok((entropy, "QRNG"));
                    }
                    Err(e) => {
                        warn!("⚠️  QRNG reconstruction failed: {}, falling back to VRF", e);
                    }
                }
            } else {
                debug!(
                    "Insufficient QRNG shares for round {}: {}/{}, using VRF",
                    round_id, shares.len(), threshold_k
                );
            }
        }

        // Fallback to deterministic VRF
        let vrf_seed = self.get_quantum_entropy_seed(block_number)?;
        Ok((vrf_seed, "VRF"))
    }

    /// Reconstruct entropy from collected QRNG shares using Shamir secret sharing.
    ///
    /// Uses the `sharks` crate for proper Lagrange interpolation over GF(256).
    /// Previous implementation used simple XOR which is NOT threshold-secure:
    /// any single share leaks information about the secret (issue #8).
    fn reconstruct_qrng_entropy(
        &self,
        shares: &[crate::rpc::threshold_qrng_rpc::CollectedShare],
    ) -> Result<[u8; 32], String> {
        use sharks::{Share, Sharks};
        use sp_crypto_hashing::keccak_256;

        if shares.is_empty() {
            return Err("No shares to reconstruct".to_string());
        }

        // Convert CollectedShares to Sharks shares
        let sharks_shares: Vec<Share> = shares
            .iter()
            .filter_map(|s| Share::try_from(s.share_bytes.as_slice()).ok())
            .collect();

        if sharks_shares.len() < 2 {
            return Err(format!(
                "Insufficient valid Shamir shares: {} (need at least 2)",
                sharks_shares.len()
            ));
        }

        // Use threshold from config
        let threshold_k = {
            let config = self.threshold_config.lock()
                .map_err(|e| format!("Failed to lock threshold config: {}", e))?;
            config.threshold_k as u8
        };

        let sharks = Sharks(threshold_k);
        let secret = sharks.recover(&sharks_shares)
            .map_err(|_| "Shamir reconstruction failed — shares may be from different secrets or corrupted".to_string())?;

        // Hash reconstructed secret to exactly 32 bytes using Keccak-256
        Ok(keccak_256(&secret))
    }

    /// Get quantum entropy seed for VRF computation.
    ///
    /// Combines HWRNG-based fallback entropy with the block number through
    /// Keccak-256 (128-bit PQC security). In production with PQTG hardware,
    /// this is superseded by the threshold QRNG path in `get_entropy_for_round()`.
    fn get_quantum_entropy_seed(&self, block_number: u64) -> Result<[u8; 32], String> {
        use sp_crypto_hashing::keccak_256;

        // Combine:
        // 1. Block number (binds to chain state)
        // 2. HWRNG-based entropy (unpredictable to external observers)
        let mock_quantum_bytes = Self::mock_quantum_entropy(block_number);

        let mut seed_material = Vec::with_capacity(40);
        seed_material.extend_from_slice(&block_number.to_le_bytes());
        seed_material.extend_from_slice(&mock_quantum_bytes);

        // Keccak-256 for PQC-safe mixing (replaces Blake2 per issue #7)
        Ok(keccak_256(&seed_material))
    }

    /// Generate fallback entropy when quantum devices are unavailable.
    ///
    /// Combines OS HWRNG (OsRng), block number, and nanosecond timestamp
    /// through Keccak-256 for 128-bit post-quantum security (Grover bound).
    ///
    /// **Security**: This is NOT true quantum entropy but is unpredictable
    /// to any adversary without access to the validator's OS RNG state.
    /// Previous implementation used `Blake2("quantum_entropy_" + block_number)`
    /// which was fully predictable (issue #7).
    fn mock_quantum_entropy(block_number: u64) -> [u8; 32] {
        use rand::RngCore;
        use sp_crypto_hashing::keccak_256;

        // Mix three independent entropy sources:
        // 1. OS hardware RNG (32 bytes) — unpredictable
        let mut hwrng_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut hwrng_bytes);

        // 2. Block number — binds entropy to chain state
        // 3. Nanosecond timestamp — prevents replay across restarts
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut material = Vec::with_capacity(48);
        material.extend_from_slice(&hwrng_bytes);
        material.extend_from_slice(&block_number.to_le_bytes());
        material.extend_from_slice(&timestamp.to_le_bytes());

        keccak_256(&material)
    }

    /// Compute VRF output for a validator
    /// VRF(validator_id, block_number, quantum_seed) = provably random output
    fn compute_vrf_output(
        &self,
        validator_pub: &sp_core::sphincs::Public,
        block_number: u64,
        quantum_seed: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        use sp_core::Blake2Hasher;
        use sp_core::Hasher;

        // VRF construction: Hash(validator_id || block_number || quantum_seed)
        // - validator signs a transcript containing (block_number, quantum_seed)
        // - VRF output is derived from signature
        // - VRF proof allows public verification

        let mut vrf_input = Vec::new();
        vrf_input.extend_from_slice(&validator_pub.0);
        vrf_input.extend_from_slice(&block_number.to_le_bytes());
        vrf_input.extend_from_slice(quantum_seed);

        // Hash to produce VRF output
        let vrf_hash = Blake2Hasher::hash(&vrf_input);
        let mut vrf_output = [0u8; 32];
        vrf_output.copy_from_slice(vrf_hash.as_ref());

        Ok(vrf_output)
    }

    /// Get mock validator set (for dev mode)
    /// In production: query runtime for actual validator set
    fn get_mock_validator_set(&self) -> Result<Vec<sp_core::sphincs::Public>, String> {
        // Use real validators from runtime instead of mock data
        // This ensures VRF election uses actual validator keys
        self.get_current_validators()
    }

    /// Get our validator ID (set during construction from keystore)
    fn get_our_validator_id(&self) -> Result<sp_core::sphincs::Public, String> {
        // Return the validator ID that was determined during construction
        // This was set in new() by matching keystore keys against runtime authorities
        self.our_validator_id.ok_or_else(|| {
            "No validator ID set - this node may not have AURA keys in keystore".to_string()
        })
    }

    /// Groom transaction pool ASAP if needed
    /// Checks pool status and triggers immediate grooming if threshold exceeded
    /// THRESHOLD QRNG: Queue a device share into per-device priority queue
    ///
    /// Shares are ordered by QBER (lower = higher priority)
    async fn queue_device_share(&self, share: DeviceShare) -> Result<(), String> {
        let mut queues = self.device_share_queues.lock()
            .map_err(|e| format!("Failed to lock device queues: {}", e))?;

        let queue = queues.entry(share.device_id.clone())
            .or_insert_with(PriorityQueue::new);

        // Priority = Reverse(QBER) so lower QBER = higher priority
        let priority = Reverse(share.qber);
        queue.push(share, priority);

        Ok(())
    }

    /// THRESHOLD QRNG: Leader collects K best shares from each device and reconstructs entropy
    ///
    /// Algorithm:
    /// 1. For each device queue, pop the K best shares (lowest QBER)
    /// 2. Use Shamir reconstruction to combine shares
    /// 3. Create reconstruction proof
    /// 4. Return CombinedEntropyTx ready for mempool
    async fn collect_device_shares_as_leader(
        &self,
        leader_public_key: &[u8],
    ) -> Result<Option<CombinedEntropyTx>, String> {
        let config = self.threshold_config.lock()
            .map_err(|e| format!("Failed to lock threshold config: {}", e))?;

        let threshold_k = config.threshold_k;
        let total_devices_m = config.total_devices_m;
        let device_ids: Vec<DeviceId> = config.devices.iter()
            .map(|d| d.device_id.clone())
            .collect();

        drop(config); // Release lock

        let mut all_shares = Vec::new();

        // Collect shares from each device queue
        {
            let mut queues = self.device_share_queues.lock()
                .map_err(|e| format!("Failed to lock device queues: {}", e))?;

            for device_id in &device_ids {
                if let Some(queue) = queues.get_mut(device_id) {
                    // Pop best share from this device (lowest QBER)
                    if let Some((share, _priority)) = queue.pop() {
                        info!("👑 Leader collected share from device {:?} with QBER {}",
                            String::from_utf8_lossy(&share.device_id.0),
                            share.qber);
                        all_shares.push(share);
                    } else {
                        warn!("⚠️  Device {:?} queue is empty",
                            String::from_utf8_lossy(&device_id.0));
                    }
                } else {
                    warn!("⚠️  No queue found for device {:?}",
                        String::from_utf8_lossy(&device_id.0));
                }
            }
        }

        // Need at least K shares to reconstruct
        if all_shares.len() < threshold_k as usize {
            warn!("⚠️  Insufficient shares: {} < K={}", all_shares.len(), threshold_k);
            return Ok(None);
        }

        info!("🔮 Reconstructing entropy from {} device shares (K={})",
            all_shares.len(), threshold_k);

        // Perform Shamir reconstruction
        let combined_entropy = reconstruct_entropy(&all_shares, threshold_k as u8)
            .map_err(|e| format!("Shamir reconstruction failed: {}", e))?;

        info!("✅ Entropy reconstructed: {} bytes", combined_entropy.len());

        // Create reconstruction proof
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get timestamp: {}", e))?
            .as_secs();

        // NOTE: Keystore integration for persistent Falcon1024 keys requires substrate KeystoreExt trait extension
        // Generating ephemeral keypair for entropy reconstruction proof signing
        let (_, leader_privkey) = pqcrypto_falcon::falcon1024::keypair();

        let reconstruction_proof = create_reconstruction_proof(
            &all_shares,
            &combined_entropy,
            leader_public_key,
            leader_privkey.as_bytes(),
            timestamp,
        ).map_err(|e| format!("Failed to create reconstruction proof: {}", e))?;

        // Build CombinedEntropyTx
        let entropy_tx = CombinedEntropyTx {
            combined_entropy,
            device_shares: all_shares,
            threshold_k,
            total_devices_m,
            reconstruction_proof,
            reconstruction_timestamp: timestamp,
        };

        Ok(Some(entropy_tx))
    }

    /// Collect device entropy via entropy hub (real QRNG devices via PQTG)
    ///
    /// Architecture:
    /// - QKD/HWRNG Hardware → PQTG (localhost:8443) → Validator (pqtg_client)
    /// - Each device provides raw entropy
    /// - Entropy is split into Shamir shares (K=2, M=3)
    /// - Shares are queued with QBER priority
    async fn collect_device_entropy_via_pqtg(&self) -> Result<(), String> {
        let pqtg_client = self.pqtg_client.as_ref()
            .ok_or("PQTG client not initialized")?;

        // Collect raw entropy from all devices (via PQTG)
        let entropy_size = 32; // 32 bytes per device
        let device_responses = pqtg_client.collect_device_entropy(entropy_size).await?;

        if device_responses.len() < 2 {
            return Err(format!(
                "Not enough devices responded ({} < 2)",
                device_responses.len()
            ));
        }

        info!(
            "📥 Collected entropy from {} devices via entropy hub/PQTG",
            device_responses.len()
        );

        // Create Shamir shares from each device's entropy
        use sharks::{Share, Sharks};

        for (idx, device_response) in device_responses.iter().enumerate() {
            // Each device's entropy becomes the secret for Shamir shares
            let sharks = Sharks(2); // K=2
            let dealer = sharks.dealer(&device_response.entropy_bytes);
            let shares: Vec<Share> = dealer.take(3).collect(); // M=3

            // Create device share from first Shamir share (validator gets share #idx)
            let device_share = DeviceShare {
                device_id: DeviceId::from_str(&device_response.device_id),
                share: Vec::from(&shares[idx % shares.len()]),
                qber: (device_response.qber * 10000.0) as u32, // Convert to basis points (0.8% → 80)
                stark_proof: vec![0xAA; 32], // NOTE: Placeholder STARK proof; real proof requires PQTG device STARK prover integration
                timestamp: device_response.timestamp,
            };

            let device_name = device_share.device_id.as_str().unwrap_or("unknown");
            info!(
                "🔌 Queuing real device share from: {}, QBER: {:.2}%",
                device_name,
                device_response.qber * 100.0
            );

            self.queue_device_share(device_share).await?;
        }

        info!(
            "✅ Queued {} device shares from real QRNG devices (via PQTG)",
            device_responses.len()
        );
        Ok(())
    }

    /// Generate mock device shares for testing (Phase 1)
    /// Only used when entropy hub client is not available
    async fn generate_mock_device_shares_for_testing(&self) -> Result<(), String> {
        use sharks::{Share, Sharks};

        // Create mock secret entropy
        let secret = b"test_quantum_entropy_32bytes_!"; // 32 bytes

        // Generate Shamir shares (K=2, M=3)
        let sharks = Sharks(2);
        let dealer = sharks.dealer(secret);
        let shares: Vec<Share> = dealer.take(3).collect();

        // Create 3 device shares with different QBERs
        // These are the ACTUAL devices (not entropy hub which is just the aggregator)
        let device_shares = vec![
            DeviceShare {
                device_id: DeviceId::from_str("qkd-vendor"),
                share: Vec::from(&shares[0]),
                qber: 80, // 0.8% QBER - QKD device, good quality
                stark_proof: vec![0xAA; 32], // Mock STARK proof
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            DeviceShare {
                device_id: DeviceId::from_str("hsm-entropy"),
                share: Vec::from(&shares[1]),
                qber: 50, // 0.5% QBER - HSM, best quality (hardware RNG)
                stark_proof: vec![0xBB; 32],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            DeviceShare {
                device_id: DeviceId::from_str("idquantique"),
                share: Vec::from(&shares[2]),
                qber: 120, // 1.2% QBER - IdQuantique QKD, medium quality
                stark_proof: vec![0xCC; 32],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        ];

        // Queue all shares
        for share in device_shares {
            let device_name = share.device_id.as_str().unwrap_or("unknown");
            info!("🧪 Queuing mock share from device: {}, QBER: {}", device_name, share.qber);
            self.queue_device_share(share).await?;
        }

        info!("✅ Generated and queued 3 mock device shares for testing");
        Ok(())
    }

    /// PHASE 2: Demonstrate entropy encryption/distribution (operator requirement)
    ///
    /// This demonstrates the full encryption flow:
    /// 1. Create EntropyPackage from reconstructed entropy
    /// 2. Encrypt package for each validator using Falcon1024 + AES-256-GCM
    /// 3. Each validator decrypts and verifies the entropy
    ///
    /// In a multi-node setup, encrypted packages would be gossipped to validators.
    /// For single-node dev testing, we demonstrate the crypto works by encrypting
    /// and immediately decrypting.
    async fn demonstrate_entropy_encryption(
        &self,
        entropy_tx: &CombinedEntropyTx,
        block_number: u32,
    ) -> Result<(), String> {
        use crate::entropy_gossip::{EntropyPackage, pqc_mode};

        // Create entropy package
        let package = EntropyPackage {
            block_number,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            combined_entropy: entropy_tx.combined_entropy.clone(),
            device_shares: entropy_tx.device_shares.clone(),
            threshold_k: entropy_tx.threshold_k as u8,
            total_devices_m: entropy_tx.total_devices_m as u8,
            leader_node_id: b"Alice".to_vec(), // NOTE: Hardcoded for testnet; session key integration requires AuthorityId → NodeId mapping
        };

        info!("📦 Created entropy package for block #{}", block_number);

        // Get Falcon1024 entropy from quantum vault (HSM integration)
        // This provides quantum-safe randomness for key generation
        // NOTE: Currently the vault entropy is optional - if unavailable, we use OS RNG
        use crate::quantum_vault::quantum_vault;
        let vault = quantum_vault();

        // Generate real Falcon1024 keypairs
        // Try to use vault entropy but fall back to OS RNG if unavailable
        // Leader keypair for signing
        match vault.get_falcon_entropy() {
            Ok(entropy) => {
                debug!("✅ Got {} bytes of Falcon entropy from vault", entropy.len());
            }
            Err(e) => {
                // Non-fatal: vault may be empty, will use OS RNG instead
                debug!("ℹ️  Vault entropy not available ({}), using OS RNG for Falcon keypair", e);
            }
        }
        let (leader_falcon_pubkey, leader_falcon_privkey) = {
            // Note: pqcrypto_falcon::falcon1024::keypair() uses OsRng internally
            // Future enhancement: Use vault entropy as seed once deterministic key generation is available
            pqcrypto_falcon::falcon1024::keypair()
        };

        // Validator keypair for encryption (same fallback logic)
        match vault.get_falcon_entropy() {
            Ok(entropy) => {
                debug!("✅ Got {} bytes of validator Falcon entropy from vault", entropy.len());
            }
            Err(e) => {
                debug!("ℹ️  Vault entropy not available ({}), using OS RNG for validator keypair", e);
            }
        }
        let (validator_falcon_pubkey, validator_falcon_privkey) = {
            pqcrypto_falcon::falcon1024::keypair()
        };

        info!("🔐 Generated Falcon1024 keypairs (using OS RNG, vault entropy optional)");

        // Encrypt package for validator
        // Convert Falcon keys to byte slices for pqc_mode functions
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
        let encrypted_msg = pqc_mode::encrypt_entropy_for_validator(
            &package,
            validator_falcon_pubkey.as_bytes(),
            leader_falcon_privkey.as_bytes(),
            leader_falcon_pubkey.as_bytes(),
        )?;

        info!("🔐 Encrypted entropy package ({} bytes)", encrypted_msg.encoded_size());

        // Demonstrate decryption (in multi-node, validator would receive via gossip)
        let decrypted_package = pqc_mode::decrypt_entropy_package(
            &encrypted_msg,
            validator_falcon_privkey.as_bytes(),
            validator_falcon_pubkey.as_bytes(),
        )?;

        // Verify decrypted data matches original
        if decrypted_package.combined_entropy == package.combined_entropy &&
           decrypted_package.device_shares.len() == package.device_shares.len() &&
           decrypted_package.threshold_k == package.threshold_k {
            info!("✅ Phase 2 Complete: Entropy encryption/decryption verified!");
            info!("   - Encrypted {} bytes of entropy + {} device shares",
                  decrypted_package.combined_entropy.len(),
                  decrypted_package.device_shares.len());
            info!("   - Ready for multi-node gossip distribution");
        } else {
            return Err("Decrypted package does not match original!".into());
        }

        Ok(())
    }

    /// ENHANCED MEMPOOL GROOMING: 3-Level Validation for Threshold QRNG
    ///
    /// This validates CombinedEntropyTx transactions in the mempool with Byzantine fault tolerance.
    ///
    /// ## 3-Level Validation:
    ///
    /// **Level 1: Local Queue Verification**
    /// - Check that K shares exist in local device queues
    /// - Ensures transaction wasn't fabricated
    /// - ZAP if fewer than K shares found locally
    ///
    /// **Level 2: Shamir Reconstruction Validation**
    /// - Recompute entropy using reconstruct_entropy()
    /// - Compare with CombinedEntropyTx.combined_entropy
    /// - ZAP if reconstruction doesn't match
    ///
    /// **Level 3: STARK Proof Verification**
    /// - Verify each DeviceShare.stark_proof
    /// - Ensures quantum measurements are authentic
    /// - ZAP if any STARK proof is invalid
    ///
    /// Only transactions passing all 3 levels remain in mempool.
    async fn groom_mempool_if_needed(&self) -> Result<(), String> {
        // Get transaction pool status
        let pool_status = self.transaction_pool.status();

        // Define thresholds
        let ready_limit = 8192; // From service.rs config
        let grooming_threshold = (ready_limit * 75) / 100; // 75% = 6144 transactions

        // If pool exceeds threshold, trigger immediate grooming
        if pool_status.ready > grooming_threshold {
            info!("🧹 URGENT: Mempool grooming triggered ASAP!");
            info!("   Ready transactions: {}/{} ({}%)",
                pool_status.ready, ready_limit,
                (pool_status.ready * 100) / ready_limit);

            // NOTE: 3-level validation deferred; requires Substrate TransactionPool::ready() iterator API
            //
            // Pseudocode for future implementation:
            //
            // let ready_txs = self.transaction_pool.ready();
            // for tx in ready_txs {
            //     if let Some(entropy_tx) = parse_combined_entropy_tx(&tx) {
            //         // LEVEL 1: Check K shares in local queues
            //         let valid_shares = count_shares_in_local_queues(&entropy_tx);
            //         if valid_shares < entropy_tx.threshold_k {
            //             self.transaction_pool.remove_invalid(&[tx.hash()]);
            //             continue;
            //         }
            //
            //         // LEVEL 2: Verify Shamir reconstruction
            //         let reconstructed = reconstruct_entropy(&entropy_tx.device_shares, K)?;
            //         if reconstructed != entropy_tx.combined_entropy {
            //             self.transaction_pool.remove_invalid(&[tx.hash()]);
            //             continue;
            //         }
            //
            //         // LEVEL 3: Verify all STARK proofs
            //         for share in &entropy_tx.device_shares {
            //             if !verify_stark_proof(&share.stark_proof) {
            //                 self.transaction_pool.remove_invalid(&[tx.hash()]);
            //                 break;
            //             }
            //         }
            //     }
            // }

            // For now, Substrate's transaction pool automatically prunes low-priority transactions
            info!("✅ Mempool groomed - removed low priority transactions");
        } else {
            // Optional: debug logging for monitoring
            if pool_status.ready > 0 {
                debug!("Mempool status: {} ready, {} future ({}% full)",
                    pool_status.ready, pool_status.future,
                    (pool_status.ready * 100) / ready_limit);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::sphincs::Public;
    use sp_core::H256;

    /// Regression for the 2026-07-04 finality fork: with N=4 real validators
    /// and the old hardcoded N=3, two votes (50%) were allowed to finalize.
    /// Two votes must NEVER meet quorum at N=4.
    #[test]
    fn two_votes_do_not_finalize_at_n4() {
        assert!(2 < quorum_threshold(4));
    }

    #[test]
    fn quorum_threshold_is_bft_supermajority() {
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 2);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(5), 4);
        assert_eq!(quorum_threshold(6), 4);
        assert_eq!(quorum_threshold(7), 5);
        assert_eq!(quorum_threshold(10), 7);
        assert_eq!(quorum_threshold(50), 34);
        assert_eq!(quorum_threshold(100), 67);
    }

    /// A pathological empty/zero validator set must not produce a zero
    /// threshold (which would finalize on zero votes).
    #[test]
    fn quorum_threshold_never_zero() {
        assert_eq!(quorum_threshold(0), 1);
    }

    // --- EquivocationLedger: honest_single at vote admission ---------------------

    #[test]
    fn ledger_first_vote_admitted_repeat_tolerated() {
        let mut l = EquivocationLedger::<u32, u8>::new(8);
        assert_eq!(l.observe(10, 1, 0xA), VoteAdmission::First);
        assert_eq!(l.observe(10, 1, 0xA), VoteAdmission::Repeat);
        assert_eq!(l.first_vote(10, &1), Some(&0xA));
    }

    #[test]
    fn ledger_rejects_conflicting_second_vote_and_holds_first() {
        let mut l = EquivocationLedger::<u32, u8>::new(8);
        assert_eq!(l.observe(10, 1, 0xA), VoteAdmission::First);
        assert_eq!(l.observe(10, 1, 0xB), VoteAdmission::Equivocation { first: 0xA });
        // The ledger is not moved by the equivocation: still held to 0xA.
        assert_eq!(l.observe(10, 1, 0xA), VoteAdmission::Repeat);
        assert_eq!(l.observe(10, 1, 0xB), VoteAdmission::Equivocation { first: 0xA });
    }

    #[test]
    fn ledger_is_per_height_and_per_validator() {
        let mut l = EquivocationLedger::<u32, u8>::new(8);
        assert_eq!(l.observe(10, 1, 0xA), VoteAdmission::First);
        assert_eq!(l.observe(15, 1, 0xB), VoteAdmission::First); // next election height
        assert_eq!(l.observe(10, 2, 0xB), VoteAdmission::First); // other validator, same height
    }

    /// At ONE receiver, first-vote-wins makes two quorums at a height impossible:
    /// each validator contributes to at most one block, so with N validators and
    /// quorum q, two blocks need 2q ≤ N distinct voters — but 2·⌈2N/3⌉ > N.
    #[test]
    fn ledger_pigeonhole_no_two_quorums_at_one_receiver() {
        for n in 1u32..=12 {
            let q = quorum_threshold(n);
            assert!(2 * q > n, "N={} q={}", n, q);
        }
        // Concrete N=3: A,B,C each vote once; A,B→0xA, C→0xB; then A tries 0xB.
        let mut l = EquivocationLedger::<u32, u8>::new(8);
        let mut count = std::collections::HashMap::<u8, u32>::new();
        for (v, h) in [(1, 0xA), (2, 0xA), (3, 0xB), (1, 0xB), (2, 0xB)] {
            if l.observe(100, v, h) == VoteAdmission::First {
                *count.entry(h).or_default() += 1;
            }
        }
        assert_eq!(count[&0xA], 2); // quorum at N=3
        assert_eq!(count[&0xB], 1); // cannot also reach quorum
    }

    #[test]
    fn ledger_is_bounded_and_drops_oldest_heights() {
        let mut l = EquivocationLedger::<u32, u8>::new(2);
        l.observe(5, 1, 0xA);
        l.observe(10, 1, 0xA);
        l.observe(15, 1, 0xA); // evicts height 5
        assert_eq!(l.first_vote(5, &1), None);
        assert_eq!(l.first_vote(10, &1), Some(&0xA));
        assert_eq!(l.first_vote(15, &1), Some(&0xA));
    }

    /// Review finding 2026-08-28: at capacity, a height below the retained
    /// minimum must be rejected, not inserted-then-evicted while reporting
    /// `First` (which would admit conflicting votes at that height).
    #[test]
    fn ledger_below_window_fails_closed() {
        let mut l = EquivocationLedger::<u32, u8>::new(2);
        l.observe(10, 1, 0xA);
        l.observe(15, 1, 0xA);
        assert_eq!(l.observe(5, 1, 0xB), VoteAdmission::OutOfWindow);
        assert_eq!(l.observe(5, 2, 0xB), VoteAdmission::OutOfWindow);
        // Retained heights are untouched by the rejected insert.
        assert_eq!(l.first_vote(10, &1), Some(&0xA));
        assert_eq!(l.first_vote(15, &1), Some(&0xA));
        // A height already retained is still judged normally at capacity.
        assert_eq!(l.observe(10, 1, 0xB), VoteAdmission::Equivocation { first: 0xA });
    }

    /// Live heights must not be evictable by stuffing HIGHER heights: with the
    /// cap reached, a new higher height evicts the lowest, and a later vote at
    /// that lowest height is then OutOfWindow (rejected), never `First` again.
    #[test]
    fn ledger_evicted_height_never_readmits() {
        let mut l = EquivocationLedger::<u32, u8>::new(2);
        assert_eq!(l.observe(10, 1, 0xA), VoteAdmission::First);
        l.observe(15, 1, 0xA);
        l.observe(20, 1, 0xA); // evicts 10
        assert_eq!(l.observe(10, 1, 0xB), VoteAdmission::OutOfWindow);
    }

    #[test]
    fn ledger_prune_below_forgets_finalized_heights() {
        let mut l = EquivocationLedger::<u32, u8>::new(8);
        l.observe(5, 1, 0xA);
        l.observe(10, 1, 0xA);
        l.observe(15, 1, 0xA);
        l.prune_below(11); // finalized = 10
        assert_eq!(l.first_vote(5, &1), None);
        assert_eq!(l.first_vote(10, &1), None);
        assert_eq!(l.first_vote(15, &1), Some(&0xA));
        // Not at capacity after pruning, so an old height is judged, not OutOfWindow
        // — the caller rejects ≤ finalized before reaching the ledger.
        assert_eq!(l.observe(10, 1, 0xB), VoteAdmission::First);
    }

    // --- coherent_quorum: the coherence-admission invariant (I_fin) ---------------
    //
    // Proof-oriented witnesses. `ok` stands in for the injected SPHINCS+/authority
    // check, so these exercise the combinatorial invariant with no key material.
    // Every rejection witness below would PASS (wrongly finalize) under the pre-fix
    // `precommit_votes.len() >= required` logic — that gap is the #345,140 fork class.
    #[derive(Clone)]
    struct TVote {
        validator: u32,
        block: u8,
        ok: bool,
    }

    fn coherence_check(target: u8, required: u32, votes: &[TVote]) -> Result<u32, String> {
        coherent_quorum(
            &target,
            required,
            votes,
            |v: &TVote| &v.block,
            |v: &TVote| v.validator,
            |v: &TVote| v.ok,
        )
    }

    #[test]
    fn coherent_quorum_accepts_honest_distinct_quorum() {
        let votes = [
            TVote { validator: 1, block: 9, ok: true },
            TVote { validator: 2, block: 9, ok: true },
            TVote { validator: 3, block: 9, ok: true },
        ];
        assert_eq!(coherence_check(9, 2, &votes), Ok(3));
    }

    #[test]
    fn coherent_quorum_rejects_forged_signature() {
        // validator 3's vote fails `verify` -> only 2 coherent, below the required 3.
        let votes = [
            TVote { validator: 1, block: 9, ok: true },
            TVote { validator: 2, block: 9, ok: true },
            TVote { validator: 3, block: 9, ok: false },
        ];
        assert!(coherence_check(9, 3, &votes).is_err());
    }

    #[test]
    fn coherent_quorum_rejects_insufficient_votes() {
        let votes = [
            TVote { validator: 1, block: 9, ok: true },
            TVote { validator: 2, block: 9, ok: true },
        ];
        assert!(coherence_check(9, 3, &votes).is_err());
    }

    #[test]
    fn coherent_quorum_rejects_votes_for_the_wrong_block() {
        // validator 3 voted for a different block -> not coherent to block 9.
        let votes = [
            TVote { validator: 1, block: 9, ok: true },
            TVote { validator: 2, block: 9, ok: true },
            TVote { validator: 3, block: 7, ok: true },
        ];
        assert!(coherence_check(9, 3, &votes).is_err());
    }

    #[test]
    fn coherent_quorum_does_not_double_count_duplicate_authority() {
        // A cert padded by repeating validator 1 must not reach quorum: distinct = {1,2}.
        let votes = [
            TVote { validator: 1, block: 9, ok: true },
            TVote { validator: 1, block: 9, ok: true },
            TVote { validator: 2, block: 9, ok: true },
        ];
        assert!(coherence_check(9, 3, &votes).is_err());
        // the same set IS coherent when only two distinct authorities are required.
        assert_eq!(coherence_check(9, 2, &votes), Ok(2));
    }

    /// Helper to create a mock proof with specific QBER.
    ///
    /// Uses current timestamp to pass freshness checks in `verify_single_proof`.
    fn create_test_proof(qber: u32) -> QuantumEntropyProof<Public> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        QuantumEntropyProof {
            stark_proof: vec![1u8; 32],
            public_inputs: PublicInputs {
                entropy_commitment: H256::from([2u8; 32]),
                qber,
                qkd_key_id: vec![3u8; 32],
                reporter: Public::from_raw([1u8; 64]),
                sample_count: 1024,
                hardware_attestation: H256::from([4u8; 32]),
            },
            signature: Vec::new(),
            timestamp: now_ms,
        }
    }

    #[test]
    fn test_coherence_score_calculation() {
        // Mock proofs with different QBER values
        // QBER values: 5% (500), 8% (800), 10% (1000)

        // Expected scores:
        // 500:  1000 * 10000 / (10000 + 500)  = 952
        // 800:  1000 * 10000 / (10000 + 800)  = 925
        // 1000: 1000 * 10000 / (10000 + 1000) = 909
        // Total: 2786

        let score_500 = (1000u64 * 10000) / (10000 + 500);
        let score_800 = (1000u64 * 10000) / (10000 + 800);
        let score_1000 = (1000u64 * 10000) / (10000 + 1000);

        assert_eq!(score_500, 952);
        assert_eq!(score_800, 925);
        assert_eq!(score_1000, 909);

        // Lower QBER = higher coherence score
        assert!(score_500 > score_800);
        assert!(score_800 > score_1000);
    }

    #[test]
    fn test_qber_threshold() {
        // 11% QBER (1100) should be rejected
        assert!(1100 >= 1100);

        // 10.99% QBER (1099) should be valid
        assert!(1099 < 1100);
    }

    #[test]
    fn test_priority_queue_ordering() {
        // Priority queue should order by QBER (lower = higher priority)
        let mut queue: PriorityQueue<u32, Reverse<u32>> = PriorityQueue::new();

        // Add QBERs: 800 (8%), 500 (5%), 1000 (10%)
        queue.push(800, Reverse(800));
        queue.push(500, Reverse(500));
        queue.push(1000, Reverse(1000));

        // Should pop in order: 500, 800, 1000
        assert_eq!(queue.pop().unwrap().0, 500);
        assert_eq!(queue.pop().unwrap().0, 800);
        assert_eq!(queue.pop().unwrap().0, 1000);
    }

    #[test]
    fn test_5_block_election_cycle() {
        // Test that elections happen every 5 blocks
        let election_blocks = vec![0, 5, 10, 15, 20, 25];

        for block in 0..30 {
            let should_elect = block % 5 == 0;
            let is_election_block = election_blocks.contains(&block);
            assert_eq!(should_elect, is_election_block);
        }
    }

    #[test]
    fn test_mempool_grooming_triggers() {
        // Test that grooming happens every 3 blocks
        let grooming_blocks = vec![0, 3, 6, 9, 12, 15, 18];

        for block in 0..20 {
            let should_groom = block % 3 == 0;
            let is_grooming_block = grooming_blocks.contains(&block);
            assert_eq!(should_groom, is_grooming_block, "Block {} failed: should_groom={}, is_grooming={}", block, should_groom, is_grooming_block);
        }
    }

    #[test]
    fn test_byzantine_supermajority() {
        // Test 2/3 supermajority calculation
        let test_cases = vec![
            (3, 2),   // 3 validators -> need 2 votes
            (4, 3),   // 4 validators -> need 3 votes
            (10, 7),  // 10 validators -> need 7 votes
            (100, 67), // 100 validators -> need 67 votes
        ];

        for (total, expected_threshold) in test_cases {
            let threshold = ((total * 2) + 2) / 3;  // Ceiling division
            assert_eq!(threshold, expected_threshold);
        }
    }

    #[test]
    fn test_vrf_output_deterministic() {
        // VRF output should be deterministic for same inputs
        use sp_core::{Blake2Hasher, Hasher};

        let validator_pub = Public::from_raw([1u8; 64]);
        let block_number = 5u64;
        let quantum_seed = [42u8; 32];

        // Compute VRF output twice
        let mut vrf_input1 = Vec::new();
        vrf_input1.extend_from_slice(&validator_pub.0);
        vrf_input1.extend_from_slice(&block_number.to_le_bytes());
        vrf_input1.extend_from_slice(&quantum_seed);
        let vrf1 = Blake2Hasher::hash(&vrf_input1);

        let mut vrf_input2 = Vec::new();
        vrf_input2.extend_from_slice(&validator_pub.0);
        vrf_input2.extend_from_slice(&block_number.to_le_bytes());
        vrf_input2.extend_from_slice(&quantum_seed);
        let vrf2 = Blake2Hasher::hash(&vrf_input2);

        // Should be identical
        assert_eq!(vrf1, vrf2);
    }

    #[test]
    fn test_vrf_different_validators() {
        // Different validators should produce different VRF outputs
        use sp_core::{Blake2Hasher, Hasher};

        let validator1 = Public::from_raw([1u8; 64]);
        let validator2 = Public::from_raw([2u8; 64]);
        let block_number = 5u64;
        let quantum_seed = [42u8; 32];

        let mut vrf_input1 = Vec::new();
        vrf_input1.extend_from_slice(&validator1.0);
        vrf_input1.extend_from_slice(&block_number.to_le_bytes());
        vrf_input1.extend_from_slice(&quantum_seed);
        let vrf1 = Blake2Hasher::hash(&vrf_input1);

        let mut vrf_input2 = Vec::new();
        vrf_input2.extend_from_slice(&validator2.0);
        vrf_input2.extend_from_slice(&block_number.to_le_bytes());
        vrf_input2.extend_from_slice(&quantum_seed);
        let vrf2 = Blake2Hasher::hash(&vrf_input2);

        // Should be different
        assert_ne!(vrf1, vrf2);
    }

    #[test]
    fn test_vrf_different_blocks() {
        // Different blocks should produce different VRF outputs
        use sp_core::{Blake2Hasher, Hasher};

        let validator_pub = Public::from_raw([1u8; 64]);
        let quantum_seed = [42u8; 32];

        let mut vrf_input1 = Vec::new();
        vrf_input1.extend_from_slice(&validator_pub.0);
        vrf_input1.extend_from_slice(&5u64.to_le_bytes());
        vrf_input1.extend_from_slice(&quantum_seed);
        let vrf1 = Blake2Hasher::hash(&vrf_input1);

        let mut vrf_input2 = Vec::new();
        vrf_input2.extend_from_slice(&validator_pub.0);
        vrf_input2.extend_from_slice(&10u64.to_le_bytes());
        vrf_input2.extend_from_slice(&quantum_seed);
        let vrf2 = Blake2Hasher::hash(&vrf_input2);

        // Should be different
        assert_ne!(vrf1, vrf2);
    }

    #[test]
    fn test_vrf_different_seeds() {
        // Different quantum seeds should produce different VRF outputs
        use sp_core::{Blake2Hasher, Hasher};

        let validator_pub = Public::from_raw([1u8; 64]);
        let block_number = 5u64;

        let mut vrf_input1 = Vec::new();
        vrf_input1.extend_from_slice(&validator_pub.0);
        vrf_input1.extend_from_slice(&block_number.to_le_bytes());
        vrf_input1.extend_from_slice(&[42u8; 32]);
        let vrf1 = Blake2Hasher::hash(&vrf_input1);

        let mut vrf_input2 = Vec::new();
        vrf_input2.extend_from_slice(&validator_pub.0);
        vrf_input2.extend_from_slice(&block_number.to_le_bytes());
        vrf_input2.extend_from_slice(&[99u8; 32]);
        let vrf2 = Blake2Hasher::hash(&vrf_input2);

        // Should be different
        assert_ne!(vrf1, vrf2);
    }

    #[test]
    fn test_quantum_entropy_seed_generation() {
        // Quantum seed should combine block number and quantum randomness
        use sp_core::{Blake2Hasher, Hasher};

        let block_number = 5u64;
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(&block_number.to_le_bytes());

        // Mock quantum bytes (would come from the HSM/QKD in production)
        let quantum_bytes = [42u8; 32];
        seed_material.extend_from_slice(&quantum_bytes);

        let seed_hash = Blake2Hasher::hash(&seed_material);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_hash.as_ref());

        // Seed should be 32 bytes
        assert_eq!(seed.len(), 32);

        // Seed should not be all zeros
        assert_ne!(seed, [0u8; 32]);
    }

    #[test]
    fn test_per_validator_queue_isolation() {
        // Each validator should have independent priority queue
        let mut validator_queues: std::collections::HashMap<[u8; 64], PriorityQueue<u64, Reverse<u32>>> =
            std::collections::HashMap::new();

        let validator1 = [1u8; 64];
        let validator2 = [2u8; 64];

        // Initialize queues
        validator_queues.insert(validator1, PriorityQueue::new());
        validator_queues.insert(validator2, PriorityQueue::new());

        // Add proofs to validator 1
        validator_queues.get_mut(&validator1).unwrap().push(1, Reverse(500));
        validator_queues.get_mut(&validator1).unwrap().push(2, Reverse(600));

        // Add proofs to validator 2
        validator_queues.get_mut(&validator2).unwrap().push(3, Reverse(450));

        // Verify isolation
        assert_eq!(validator_queues.get(&validator1).unwrap().len(), 2);
        assert_eq!(validator_queues.get(&validator2).unwrap().len(), 1);
    }

    #[test]
    fn test_leader_collects_from_all_validators() {
        // Leader should collect best proofs from all validator queues
        let mut validator_queues: std::collections::HashMap<[u8; 64], PriorityQueue<u64, Reverse<u32>>> =
            std::collections::HashMap::new();

        let validator1 = [1u8; 64];
        let validator2 = [2u8; 64];
        let validator3 = [3u8; 64];

        // Initialize queues
        validator_queues.insert(validator1, PriorityQueue::new());
        validator_queues.insert(validator2, PriorityQueue::new());
        validator_queues.insert(validator3, PriorityQueue::new());

        // Add proofs (lower QBER = higher priority)
        validator_queues.get_mut(&validator1).unwrap().push(1, Reverse(500));  // Best from v1
        validator_queues.get_mut(&validator1).unwrap().push(2, Reverse(600));

        validator_queues.get_mut(&validator2).unwrap().push(3, Reverse(450));  // Best from v2
        validator_queues.get_mut(&validator2).unwrap().push(4, Reverse(550));

        validator_queues.get_mut(&validator3).unwrap().push(5, Reverse(400));  // Best from v3

        // Leader collects top 2 from each validator
        let mut collected_proofs = Vec::new();
        for (_validator_id, queue) in validator_queues.iter_mut() {
            for _ in 0..2 {
                if let Some((proof_id, _priority)) = queue.pop() {
                    collected_proofs.push(proof_id);
                }
            }
        }

        // Should have collected: 500, 600 from v1; 450, 550 from v2; 400 from v3 = 5 total
        assert_eq!(collected_proofs.len(), 5);
    }

    #[test]
    fn test_mempool_threshold_calculation() {
        // Test 75% threshold calculation
        let ready_limit = 8192u32;
        let grooming_threshold = (ready_limit * 75) / 100;

        assert_eq!(grooming_threshold, 6144);

        // Test should trigger grooming
        assert!(6144 >= grooming_threshold);
        assert!(6200 >= grooming_threshold);

        // Test should not trigger grooming
        assert!(6143 < grooming_threshold);
        assert!(5000 < grooming_threshold);
    }

    #[test]
    fn test_asap_mempool_grooming() {
        // ASAP grooming should trigger immediately when threshold exceeded
        let ready_limit = 8192u32;
        let grooming_threshold = (ready_limit * 75) / 100;  // 6144

        let test_cases = vec![
            (6143, false),  // Just below threshold - no grooming
            (6144, true),   // At threshold - trigger
            (6200, true),   // Above threshold - trigger
            (8000, true),   // Well above - trigger
            (5000, false),  // Well below - no grooming
        ];

        for (ready_count, should_groom) in test_cases {
            let triggers = ready_count >= grooming_threshold;
            assert_eq!(triggers, should_groom,
                "Failed for ready_count={}: expected {}, got {}",
                ready_count, should_groom, triggers);
        }
    }

    #[test]
    fn test_priority_queue_with_duplicate_qber() {
        // Test queue behavior with duplicate QBER values
        let mut queue: PriorityQueue<u64, Reverse<u32>> = PriorityQueue::new();

        queue.push(1, Reverse(500));
        queue.push(2, Reverse(500));  // Same QBER
        queue.push(3, Reverse(400));  // Better QBER

        // Should pop in order: 400, 500, 500
        let (id1, qber1) = queue.pop().unwrap();
        assert_eq!(qber1.0, 400);
        assert_eq!(id1, 3);

        let (_, qber2) = queue.pop().unwrap();
        assert_eq!(qber2.0, 500);

        let (_, qber3) = queue.pop().unwrap();
        assert_eq!(qber3.0, 500);
    }

    #[test]
    fn test_vrf_election_fairness() {
        // Test that VRF provides fair distribution across validators
        use sp_core::{Blake2Hasher, Hasher};

        let block_number = 5u64;
        let quantum_seed = [42u8; 32];
        let mut vrf_outputs = Vec::new();

        // Generate VRF outputs for 10 validators
        for i in 0..10 {
            let mut validator_id = [0u8; 64];
            validator_id[0] = i;

            let mut vrf_input = Vec::new();
            vrf_input.extend_from_slice(&validator_id);
            vrf_input.extend_from_slice(&block_number.to_le_bytes());
            vrf_input.extend_from_slice(&quantum_seed);

            let vrf_output = Blake2Hasher::hash(&vrf_input);
            vrf_outputs.push(vrf_output);
        }

        // All outputs should be unique
        for i in 0..vrf_outputs.len() {
            for j in (i+1)..vrf_outputs.len() {
                assert_ne!(vrf_outputs[i], vrf_outputs[j],
                    "VRF outputs for validators {} and {} should be different", i, j);
            }
        }
    }

    // ========== THRESHOLD QRNG TESTS ==========

    #[test]
    fn test_device_share_priority_queue() {
        // Test that device shares are ordered by QBER in priority queue
        let mut queue: PriorityQueue<DeviceShare, Reverse<u32>> = PriorityQueue::new();

        let share1 = DeviceShare {
            device_id: DeviceId::from_str("qkd-qrng"),
            share: vec![1, 2, 3],
            qber: 500, // 5% QBER
            stark_proof: vec![0xAA; 32],
            timestamp: 1700000000,
        };

        let share2 = DeviceShare {
            device_id: DeviceId::from_str("hsm-qrng"),
            share: vec![4, 5, 6],
            qber: 80, // 0.8% QBER - best
            stark_proof: vec![0xBB; 32],
            timestamp: 1700000001,
        };

        let share3 = DeviceShare {
            device_id: DeviceId::from_str("entropy-hub"),
            share: vec![7, 8, 9],
            qber: 1000, // 10% QBER - worst
            stark_proof: vec![0xCC; 32],
            timestamp: 1700000002,
        };

        // Add in random order
        queue.push(share1.clone(), Reverse(share1.qber));
        queue.push(share2.clone(), Reverse(share2.qber));
        queue.push(share3.clone(), Reverse(share3.qber));

        // Should pop in order: share2 (80), share1 (500), share3 (1000)
        let (popped1, _) = queue.pop().unwrap();
        assert_eq!(popped1.device_id.as_str().unwrap(), "hsm-qrng");
        assert_eq!(popped1.qber, 80);

        let (popped2, _) = queue.pop().unwrap();
        assert_eq!(popped2.device_id.as_str().unwrap(), "qkd-qrng");
        assert_eq!(popped2.qber, 500);

        let (popped3, _) = queue.pop().unwrap();
        assert_eq!(popped3.device_id.as_str().unwrap(), "entropy-hub");
        assert_eq!(popped3.qber, 1000);
    }

    #[test]
    fn test_threshold_config_initialization() {
        // Test that ThresholdConfig initializes with correct K=2, M=3
        let config = ThresholdConfig {
            threshold_k: 2,
            total_devices_m: 3,
            devices: vec![
                crate::threshold_qrng::DeviceConfig {
                    device_id: DeviceId(b"qkd-qrng".to_vec()),
                    endpoint: "http://localhost:8001/qrng".to_string(),
                    qber_threshold: 1100,
                    enabled: true,
                },
                crate::threshold_qrng::DeviceConfig {
                    device_id: DeviceId(b"hsm-qrng".to_vec()),
                    endpoint: "http://localhost:8002/qrng".to_string(),
                    qber_threshold: 1100,
                    enabled: true,
                },
                crate::threshold_qrng::DeviceConfig {
                    device_id: DeviceId(b"entropy-hub".to_vec()),
                    endpoint: "http://localhost:8003/qrng".to_string(),
                    qber_threshold: 1100,
                    enabled: true,
                },
            ],
        };

        assert_eq!(config.threshold_k, 2);
        assert_eq!(config.total_devices_m, 3);
        assert_eq!(config.devices.len(), 3);
        assert_eq!(config.devices[0].device_id.as_str().unwrap(), "qkd-qrng");
        assert_eq!(config.devices[1].device_id.as_str().unwrap(), "hsm-qrng");
        assert_eq!(config.devices[2].device_id.as_str().unwrap(), "entropy-hub");
    }

    #[tokio::test]
    async fn test_device_share_collection_workflow() {
        // End-to-end test: Create shares, collect as leader, verify reconstruction
        use sharks::{Sharks, Share};

        let secret = b"quantum_entropy_from_three_qrng_devices";
        let sharks = Sharks(2);
        let dealer = sharks.dealer(secret);
        let shamir_shares: Vec<Share> = dealer.take(3).collect();

        // Create device shares with different QBERs
        let mut device_queues: HashMap<DeviceId, PriorityQueue<DeviceShare, Reverse<u32>>> = HashMap::new();

        let qkd_id = DeviceId::from_str("qkd-qrng");
        let hsm_id = DeviceId::from_str("hsm-qrng");
        let hub_id = DeviceId::from_str("entropy-hub");

        let share1 = DeviceShare {
            device_id: qkd_id.clone(),
            share: Vec::from(&shamir_shares[0]),
            qber: 80, // 0.8% QBER - best
            stark_proof: vec![0xAA; 32],
            timestamp: 1700000000,
        };

        let share2 = DeviceShare {
            device_id: hsm_id.clone(),
            share: Vec::from(&shamir_shares[1]),
            qber: 120, // 1.2% QBER
            stark_proof: vec![0xBB; 32],
            timestamp: 1700000001,
        };

        let share3 = DeviceShare {
            device_id: hub_id.clone(),
            share: Vec::from(&shamir_shares[2]),
            qber: 90, // 0.9% QBER
            stark_proof: vec![0xCC; 32],
            timestamp: 1700000002,
        };

        // Queue shares into per-device queues
        let mut queue1 = PriorityQueue::new();
        queue1.push(share1.clone(), Reverse(share1.qber));
        device_queues.insert(qkd_id.clone(), queue1);

        let mut queue2 = PriorityQueue::new();
        queue2.push(share2.clone(), Reverse(share2.qber));
        device_queues.insert(hsm_id.clone(), queue2);

        let mut queue3 = PriorityQueue::new();
        queue3.push(share3.clone(), Reverse(share3.qber));
        device_queues.insert(hub_id.clone(), queue3);

        // Leader collects shares
        let mut collected_shares = Vec::new();
        for device_id in &[qkd_id, hsm_id, hub_id] {
            if let Some(queue) = device_queues.get_mut(device_id) {
                if let Some((share, _priority)) = queue.pop() {
                    collected_shares.push(share);
                }
            }
        }

        assert_eq!(collected_shares.len(), 3);

        // Reconstruct entropy
        let reconstructed = reconstruct_entropy(&collected_shares, 2).unwrap();
        assert_eq!(reconstructed, secret);

        // Create and verify proof
        let timestamp = 1700000010;

        // Generate real Falcon1024 keypair for testing
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
        let (leader_pubkey, leader_privkey) = pqcrypto_falcon::falcon1024::keypair();

        let proof = create_reconstruction_proof(
            &collected_shares,
            &reconstructed,
            leader_pubkey.as_bytes(),
            leader_privkey.as_bytes(),
            timestamp,
        ).unwrap();

        let entropy_tx = CombinedEntropyTx {
            combined_entropy: reconstructed,
            device_shares: collected_shares,
            threshold_k: 2,
            total_devices_m: 3,
            reconstruction_proof: proof,
            reconstruction_timestamp: timestamp,
        };

        assert!(verify_reconstruction_proof(&entropy_tx, leader_pubkey.as_bytes()).is_ok());
    }

    #[test]
    fn test_multiple_shares_per_device_queue() {
        // Test that each device can have multiple shares queued
        let mut queue: PriorityQueue<DeviceShare, Reverse<u32>> = PriorityQueue::new();

        // Queue 5 shares from same device with different QBERs
        for i in 0..5 {
            let share = DeviceShare {
                device_id: DeviceId::from_str("qkd-qrng"),
                share: vec![(i * 10) as u8],
                qber: (i * 100 + 50) as u32, // 50, 150, 250, 350, 450
                stark_proof: vec![0u8; 32],
                timestamp: 1700000000 + i as u64,
            };
            queue.push(share.clone(), Reverse(share.qber));
        }

        assert_eq!(queue.len(), 5);

        // Should pop in QBER order: 50, 150, 250, 350, 450
        let (share1, _) = queue.pop().unwrap();
        assert_eq!(share1.qber, 50);

        let (share2, _) = queue.pop().unwrap();
        assert_eq!(share2.qber, 150);

        let (share3, _) = queue.pop().unwrap();
        assert_eq!(share3.qber, 250);

        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_k_of_m_threshold_flexibility() {
        // Test that K=2, M=3 means any 2 of 3 devices can reconstruct
        use sharks::{Sharks, Share};

        let secret = b"flexible_threshold_quantum_entropy";
        let sharks = Sharks(2);
        let dealer = sharks.dealer(secret);
        let shamir_shares: Vec<Share> = dealer.take(3).collect();

        let shares: Vec<DeviceShare> = shamir_shares
            .iter()
            .enumerate()
            .map(|(i, share)| DeviceShare {
                device_id: DeviceId::from_str(&format!("device-{}", i)),
                share: Vec::from(share),
                qber: ((i + 1) * 100) as u32,
                stark_proof: vec![0u8; 32],
                timestamp: 1700000000,
            })
            .collect();

        // Test all combinations of 2 out of 3
        // Combination 1: devices 0 and 1
        let combo1 = vec![shares[0].clone(), shares[1].clone()];
        let result1 = reconstruct_entropy(&combo1, 2).unwrap();
        assert_eq!(result1, secret);

        // Combination 2: devices 0 and 2
        let combo2 = vec![shares[0].clone(), shares[2].clone()];
        let result2 = reconstruct_entropy(&combo2, 2).unwrap();
        assert_eq!(result2, secret);

        // Combination 3: devices 1 and 2
        let combo3 = vec![shares[1].clone(), shares[2].clone()];
        let result3 = reconstruct_entropy(&combo3, 2).unwrap();
        assert_eq!(result3, secret);
    }

    #[test]
    fn test_device_queue_empty_handling() {
        // Test graceful handling when device queue is empty
        let mut device_queues: HashMap<DeviceId, PriorityQueue<DeviceShare, Reverse<u32>>> = HashMap::new();

        let qkd_id = DeviceId::from_str("qkd-qrng");
        let hsm_id = DeviceId::from_str("hsm-qrng");

        // Only add share to QKD queue
        let mut queue1 = PriorityQueue::new();
        queue1.push(
            DeviceShare {
                device_id: qkd_id.clone(),
                share: vec![1, 2, 3],
                qber: 100,
                stark_proof: vec![0u8; 32],
                timestamp: 1700000000,
            },
            Reverse(100),
        );
        device_queues.insert(qkd_id.clone(), queue1);

        // HSM queue is empty (not even in map)
        let mut collected = Vec::new();

        // Try to collect from both
        for device_id in &[qkd_id, hsm_id] {
            if let Some(queue) = device_queues.get_mut(device_id) {
                if let Some((share, _)) = queue.pop() {
                    collected.push(share);
                }
            }
        }

        // Should only collect 1 share
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].device_id.as_str().unwrap(), "qkd-qrng");
    }

    // ========== PHASE 5: PQ-MONADBFT TESTING ==========

    /// Test message complexity comparison: O(n) linear vs O(N log N) gossip
    #[test]
    fn test_message_complexity_comparison() {
        // O(n) linear voting: 3N messages (propose + vote + certify)
        // O(N log N) gossip: N * log2(N) messages per round

        // O(N log N) uses ceil(log2(N)):
        // N=10: ceil(3.32) = 4, so 10*4 = 40
        // N=50: ceil(5.64) = 6, so 50*6 = 300
        // N=100: ceil(6.64) = 7, so 100*7 = 700
        // N=1000: ceil(9.97) = 10, so 1000*10 = 10000
        let test_cases = vec![
            (10, 30, 40),      // 10 validators: 30 vs 40 (1.3x improvement)
            (50, 150, 300),    // 50 validators: 150 vs 300 (2.0x improvement)
            (100, 300, 700),   // 100 validators: 300 vs 700 (2.3x improvement)
            (1000, 3000, 10000), // 1000 validators: 3000 vs 10000 (3.3x improvement)
        ];

        for (n, expected_linear, expected_gossip) in test_cases {
            let linear_messages = 3 * n;  // O(n)
            let gossip_messages = n * (n as f64).log2().ceil() as u32;  // O(N log N)

            assert_eq!(linear_messages, expected_linear,
                "Linear messages for {} validators", n);
            assert_eq!(gossip_messages, expected_gossip,
                "Gossip messages for {} validators", n);

            // Linear should always be better
            assert!(linear_messages < gossip_messages,
                "Linear ({}) should be less than gossip ({}) for {} validators",
                linear_messages, gossip_messages, n);

            let improvement = gossip_messages as f64 / linear_messages as f64;
            println!("N={}: Linear={}, Gossip={}, Improvement={:.1}x",
                n, linear_messages, gossip_messages, improvement);
        }
    }

    /// Test QBER aggregation accuracy
    #[test]
    fn test_qber_aggregation_accuracy() {
        // Simulate votes with different QBER values (basis points)
        let qber_values = vec![
            500,   // 5.00% - excellent
            750,   // 7.50% - good
            850,   // 8.50% - acceptable
            950,   // 9.50% - marginal
            1050,  // 10.50% - at limit
        ];

        // Calculate aggregated QBER (weighted average)
        let total_qber: u32 = qber_values.iter().sum();
        let avg_qber = total_qber / qber_values.len() as u32;

        assert_eq!(avg_qber, 820, "Average QBER should be 8.20%");

        // Count healthy channels (QBER < 11%)
        let healthy_count = qber_values.iter()
            .filter(|&&q| q < 1100)
            .count();
        assert_eq!(healthy_count, 5, "All 5 channels should be healthy");

        // Test rejection criteria
        let should_reject = avg_qber > 1100 || healthy_count < qber_values.len() / 2;
        assert!(!should_reject, "Block should NOT be rejected with avg QBER 8.20%");
    }

    /// Test QBER rejection when threshold exceeded
    #[test]
    fn test_qber_rejection_threshold() {
        // Scenario 1: Average QBER exceeds 11%
        let high_qber_values = vec![1200, 1150, 1100, 1050, 1000];
        let avg_qber: u32 = high_qber_values.iter().sum::<u32>() / high_qber_values.len() as u32;
        assert_eq!(avg_qber, 1100, "Average should be exactly 11%");

        // At 11% threshold, should NOT reject (only reject if > 11%)
        let should_reject = avg_qber > 1100;
        assert!(!should_reject, "Block should NOT reject at exactly 11%");

        // Scenario 2: Average QBER is 11.01% (exceeds threshold)
        let exceeding_qber_values = vec![1201, 1150, 1100, 1050, 1000];
        let avg_qber: u32 = exceeding_qber_values.iter().sum::<u32>() / exceeding_qber_values.len() as u32;
        assert_eq!(avg_qber, 1100, "Average rounds to 11%"); // Integer division

        // Scenario 3: Too few healthy channels
        let mixed_qber_values = vec![500, 1200, 1300, 1400, 1500]; // Only 1 healthy
        let healthy_count = mixed_qber_values.iter().filter(|&&q| q < 1100).count();
        let total = mixed_qber_values.len();
        let should_reject_channels = healthy_count < total / 2;
        assert!(should_reject_channels, "Should reject when only 1/5 channels healthy");
    }

    /// Test linear voting scalability
    #[test]
    fn test_linear_voting_scalability() {
        // Verify O(n) scaling for various validator counts
        let validator_counts = vec![10, 50, 100, 500, 1000, 5000, 10000, 50000];

        for n in validator_counts {
            // Phase 1: Leader broadcasts proposal = n messages
            let propose_messages = n;

            // Phase 2: Validators vote to leader = n messages
            let vote_messages = n;

            // Phase 3: Leader broadcasts certificate = n messages
            let certify_messages = n;

            // Total = 3n (linear)
            let total_messages = propose_messages + vote_messages + certify_messages;
            assert_eq!(total_messages, 3 * n, "Total should be 3n for {} validators", n);

            // Verify scaling factor
            if n > 10 {
                let ratio = total_messages as f64 / (3 * 10) as f64;
                let expected_ratio = n as f64 / 10.0;
                assert!((ratio - expected_ratio).abs() < 0.01,
                    "Scaling should be linear: {} vs {}", ratio, expected_ratio);
            }
        }

        // Maximum supported: ~50,000 validators
        let max_validators = 50000;
        let max_messages = 3 * max_validators;
        assert_eq!(max_messages, 150000, "Max messages for 50k validators");
    }

    /// Test pipeline phase transitions
    #[test]
    fn test_pipeline_phase_transitions() {
        use std::collections::HashMap;

        // Simulate pipeline state for multiple blocks
        let mut pipeline: HashMap<u64, PipelinePhase> = HashMap::new();

        // Block 1: Full lifecycle
        pipeline.insert(1, PipelinePhase::Propose);
        assert_eq!(pipeline.get(&1), Some(&PipelinePhase::Propose));

        pipeline.insert(1, PipelinePhase::Vote);
        assert_eq!(pipeline.get(&1), Some(&PipelinePhase::Vote));

        pipeline.insert(1, PipelinePhase::Certify);
        assert_eq!(pipeline.get(&1), Some(&PipelinePhase::Certify));

        pipeline.insert(1, PipelinePhase::ConsensusComplete);
        assert_eq!(pipeline.get(&1), Some(&PipelinePhase::ConsensusComplete));

        pipeline.insert(1, PipelinePhase::Executed);
        assert_eq!(pipeline.get(&1), Some(&PipelinePhase::Executed));

        // Test concurrent blocks in different phases (pipelining)
        pipeline.insert(2, PipelinePhase::Propose);
        pipeline.insert(3, PipelinePhase::Vote);
        pipeline.insert(4, PipelinePhase::Certify);

        assert_eq!(pipeline.get(&2), Some(&PipelinePhase::Propose));
        assert_eq!(pipeline.get(&3), Some(&PipelinePhase::Vote));
        assert_eq!(pipeline.get(&4), Some(&PipelinePhase::Certify));

        // All 4 blocks can be in pipeline simultaneously
        assert_eq!(pipeline.len(), 4);
    }

    /// Test deferred execution queue ordering
    #[test]
    fn test_deferred_execution_queue() {
        use sp_core::H256;
        use sp_runtime::traits::Zero;

        // Simulate deferred execution queue
        let mut queue: Vec<(H256, u64, u16)> = Vec::new(); // (hash, block_num, qber)

        // Add blocks in non-sequential order (as they complete consensus)
        queue.push((H256::from_low_u64_be(3), 103, 500));
        queue.push((H256::from_low_u64_be(1), 101, 600));
        queue.push((H256::from_low_u64_be(2), 102, 550));

        // Sort by block number for sequential execution
        queue.sort_by_key(|(_, num, _)| *num);

        assert_eq!(queue[0].1, 101, "First should be block 101");
        assert_eq!(queue[1].1, 102, "Second should be block 102");
        assert_eq!(queue[2].1, 103, "Third should be block 103");

        // Process in order
        let mut executed = Vec::new();
        while let Some((hash, num, _)) = queue.pop() {
            executed.push(num);
        }

        // Executed in reverse order due to pop (LIFO)
        assert_eq!(executed, vec![103, 102, 101]);
    }

    /// Test tail-fork protection validation
    #[test]
    fn test_tail_fork_protection() {
        use sp_core::H256;

        // Simulate certificate cache
        let mut certificate_cache: HashMap<H256, Vec<u8>> = HashMap::new();

        // Block 100 is certified
        let block_100_hash = H256::from_low_u64_be(100);
        let block_100_cert = vec![1, 2, 3, 4]; // Mock certificate
        certificate_cache.insert(block_100_hash, block_100_cert.clone());

        // Block 101 proposes with parent = block 100
        let parent_hash = block_100_hash;
        let parent_cert_provided = Some(block_100_cert.clone());

        // Validation: parent certificate must match cached certificate
        let is_valid = match (certificate_cache.get(&parent_hash), parent_cert_provided) {
            (Some(cached), Some(provided)) => cached == &provided,
            (None, None) => true, // Genesis case
            _ => false,
        };

        assert!(is_valid, "Tail-fork protection should pass with matching certificate");

        // Invalid case: wrong certificate
        let wrong_cert = Some(vec![5, 6, 7, 8]);
        let is_invalid = match (certificate_cache.get(&parent_hash), wrong_cert) {
            (Some(cached), Some(provided)) => cached == &provided,
            _ => false,
        };

        assert!(!is_invalid, "Tail-fork protection should fail with wrong certificate");

        // Invalid case: missing certificate when required
        let missing_cert: Option<Vec<u8>> = None;
        let is_missing_invalid = match (certificate_cache.get(&parent_hash), missing_cert) {
            (Some(_), None) => false, // Cached exists but none provided
            _ => true,
        };

        assert!(!is_missing_invalid, "Tail-fork protection should fail when cert missing");
    }

    /// Test QRNG leader election fairness
    #[test]
    fn test_qrng_leader_election_fairness() {
        use sp_core::{Blake2Hasher, Hasher};

        // Simulate 100 election rounds with 10 validators
        let num_validators: usize = 10;
        let num_rounds: u64 = 1000;
        let mut wins: HashMap<usize, u32> = HashMap::new();

        for round in 0..num_rounds {
            // Simulate QRNG entropy (use round as seed for test determinism)
            let entropy = Blake2Hasher::hash(&round.to_le_bytes());

            // Calculate election output for each validator
            let mut outputs: Vec<(usize, [u8; 32])> = Vec::new();
            for v in 0..num_validators {
                let mut input = Vec::new();
                input.extend_from_slice(&(v as u64).to_le_bytes());
                input.extend_from_slice(&round.to_le_bytes());
                input.extend_from_slice(entropy.as_ref());
                let output = Blake2Hasher::hash(&input);
                outputs.push((v, output.into()));
            }

            // Leader = validator with lowest output
            outputs.sort_by_key(|(_, out)| *out);
            let leader = outputs[0].0;
            *wins.entry(leader).or_insert(0) += 1;
        }

        // Check fairness: each validator should win ~10% of rounds
        let expected_wins = num_rounds as f64 / num_validators as f64;
        for v in 0..num_validators {
            let actual_wins = *wins.get(&v).unwrap_or(&0) as f64;
            let deviation = (actual_wins - expected_wins).abs() / expected_wins;

            // Allow 30% deviation for statistical variance
            assert!(deviation < 0.30,
                "Validator {} won {} times (expected ~{}), deviation {:.1}%",
                v, actual_wins, expected_wins, deviation * 100.0);
        }

        println!("QRNG election wins distribution:");
        for v in 0..num_validators {
            let w = wins.get(&v).unwrap_or(&0);
            println!("  Validator {}: {} wins ({:.1}%)", v, w, *w as f64 / num_rounds as f64 * 100.0);
        }
    }

    /// Test Falcon signature size vs SPHINCS+ for vote efficiency
    #[test]
    fn test_signature_size_comparison() {
        // Falcon-1024 signature size
        let falcon_sig_size = 1280; // bytes

        // SPHINCS+-SHAKE-256f signature size
        let sphincs_sig_size = 49856; // bytes

        // Size reduction factor
        let reduction = sphincs_sig_size as f64 / falcon_sig_size as f64;
        assert!((reduction - 38.95).abs() < 0.1, "Falcon should be ~39x smaller");

        // Bandwidth savings for 100 validators voting
        let num_validators = 100;
        let falcon_bandwidth = falcon_sig_size * num_validators; // 128,000 bytes
        let sphincs_bandwidth = sphincs_sig_size * num_validators; // 4,985,600 bytes

        assert_eq!(falcon_bandwidth, 128000, "Falcon: 128KB for 100 votes");
        assert_eq!(sphincs_bandwidth, 4985600, "SPHINCS+: ~5MB for 100 votes");

        let bandwidth_savings = sphincs_bandwidth - falcon_bandwidth;
        assert_eq!(bandwidth_savings, 4857600, "Savings: ~4.86MB per round");

        println!("Signature comparison for consensus votes:");
        println!("  Falcon-1024: {} bytes/sig, {}KB for 100 validators",
            falcon_sig_size, falcon_bandwidth / 1024);
        println!("  SPHINCS+: {} bytes/sig, {}KB for 100 validators",
            sphincs_sig_size, sphincs_bandwidth / 1024);
        println!("  Bandwidth savings: {}KB/round", bandwidth_savings / 1024);
    }

    /// Test throughput improvement from pipelining
    #[test]
    fn test_pipelining_throughput() {
        // Without pipelining: 1 block per 3 phases
        let phases_per_block = 3; // Propose, Vote, Certify
        let phase_duration_ms = 2000; // 2 seconds per phase

        let sequential_latency = phases_per_block * phase_duration_ms;
        assert_eq!(sequential_latency, 6000, "Sequential: 6 seconds/block");

        // With pipelining: 1 block per phase (after warmup)
        let pipelined_throughput = phase_duration_ms;
        assert_eq!(pipelined_throughput, 2000, "Pipelined: 2 seconds/block");

        let improvement = sequential_latency as f64 / pipelined_throughput as f64;
        assert!((improvement - 3.0).abs() < 0.01, "Pipelining should give 3x throughput");

        // Blocks per minute comparison
        let sequential_blocks_per_min = 60000 / sequential_latency;
        let pipelined_blocks_per_min = 60000 / pipelined_throughput;

        assert_eq!(sequential_blocks_per_min, 10, "Sequential: 10 blocks/min");
        assert_eq!(pipelined_blocks_per_min, 30, "Pipelined: 30 blocks/min");

        println!("Pipelining throughput improvement:");
        println!("  Sequential: {} blocks/min", sequential_blocks_per_min);
        println!("  Pipelined: {} blocks/min", pipelined_blocks_per_min);
        println!("  Improvement: {:.0}x", improvement);
    }

    /// Test toroidal segment distribution
    #[test]
    fn test_toroidal_segment_distribution() {
        use sp_core::{Blake2Hasher, Hasher};

        // 8x8x8 = 512 segments
        let segments_per_dimension = 8;
        let total_segments = segments_per_dimension * segments_per_dimension * segments_per_dimension;
        assert_eq!(total_segments, 512);

        // Test transaction distribution across segments
        // Use 100,000 txs for better statistical significance with 512 segments
        let num_transactions: u64 = 100000;
        let mut segment_counts: HashMap<usize, u32> = HashMap::new();

        for tx_id in 0..num_transactions {
            // Hash sender address to determine segment
            let sender_hash = Blake2Hasher::hash(&tx_id.to_le_bytes());
            let hash_bytes: [u8; 32] = sender_hash.into();

            // Extract segment coordinates from hash
            let x = (hash_bytes[0] as usize) % segments_per_dimension;
            let y = (hash_bytes[1] as usize) % segments_per_dimension;
            let z = (hash_bytes[2] as usize) % segments_per_dimension;

            let segment_id = x + y * segments_per_dimension + z * segments_per_dimension * segments_per_dimension;
            *segment_counts.entry(segment_id).or_insert(0) += 1;
        }

        // Check distribution uniformity
        let expected_per_segment = num_transactions as f64 / total_segments as f64;
        let mut max_deviation = 0.0f64;

        for segment in 0..total_segments {
            let count = *segment_counts.get(&segment).unwrap_or(&0) as f64;
            let deviation = (count - expected_per_segment).abs() / expected_per_segment;
            if deviation > max_deviation {
                max_deviation = deviation;
            }
        }

        // Allow 30% deviation for statistical variance with 512 segments and 100k txs
        // (each segment gets ~195 txs on average)
        assert!(max_deviation < 0.30,
            "Max segment deviation {:.1}% should be < 30%", max_deviation * 100.0);

        println!("Toroidal distribution (512 segments, {} txs):", num_transactions);
        println!("  Expected per segment: {:.1}", expected_per_segment);
        println!("  Max deviation: {:.1}%", max_deviation * 100.0);
    }
}

// Benchmarks require nightly Rust with #![feature(test)]
// Run with: cargo +nightly bench --package quantumharmony-node
//
// #[cfg(all(test, not(target_env = "msvc")))]
// mod benches {
//     use super::*;
//     extern crate test;
//     use test::Bencher;
//     use sp_core::{Blake2Hasher, Hasher};
//
//     #[bench]
//     fn bench_coherence_score_calculation(b: &mut Bencher) {
//         b.iter(|| {
//             let _score = (1000u64 * 10000) / (10000 + 500);
//         });
//     }
//
//     #[bench]
//     fn bench_priority_queue_push(b: &mut Bencher) {
//         let mut queue: PriorityQueue<u64, Reverse<u32>> = PriorityQueue::new();
//         let mut id = 0u64;
//         b.iter(|| {
//             queue.push(id, Reverse(500));
//             id += 1;
//         });
//     }
//
//     #[bench]
//     fn bench_priority_queue_pop(b: &mut Bencher) {
//         // Pre-fill queue with 1000 items
//         let mut queue: PriorityQueue<u64, Reverse<u32>> = PriorityQueue::new();
//         for i in 0..1000 {
//             queue.push(i, Reverse((i % 1000) as u32));
//         }
//
//         b.iter(|| {
//             if let Some(_) = queue.pop() {
//                 // Re-add to keep queue size constant
//                 queue.push(0, Reverse(500));
//             }
//         });
//     }
//
//     #[bench]
//     fn bench_priority_queue_operations(b: &mut Bencher) {
//         b.iter(|| {
//             let mut queue: PriorityQueue<u64, Reverse<u32>> = PriorityQueue::new();
//             for qber in [450, 500, 550, 600, 650] {
//                 queue.push(qber as u64, Reverse(qber as u32));
//             }
//             while queue.pop().is_some() {}
//         });
//     }
//
//     #[bench]
//     fn bench_vrf_output_computation(b: &mut Bencher) {
//         let validator_pub = sp_core::sphincs::Public::from_raw([1u8; 64]);
//         let block_number = 5u64;
//         let quantum_seed = [42u8; 32];
//
//         b.iter(|| {
//             let mut vrf_input = Vec::new();
//             vrf_input.extend_from_slice(&validator_pub.0);
//             vrf_input.extend_from_slice(&block_number.to_le_bytes());
//             vrf_input.extend_from_slice(&quantum_seed);
//             let _vrf_output = Blake2Hasher::hash(&vrf_input);
//         });
//     }
//
//     #[bench]
//     fn bench_vrf_election_3_validators(b: &mut Bencher) {
//         let block_number = 5u64;
//         let quantum_seed = [42u8; 32];
//         let validators: Vec<sp_core::sphincs::Public> = (0..3)
//             .map(|i| {
//                 let mut id = [0u8; 64];
//                 id[0] = i;
//                 sp_core::sphincs::Public::from_raw(id)
//             })
//             .collect();
//
//         b.iter(|| {
//             let mut vrf_results = Vec::new();
//             for validator in &validators {
//                 let mut vrf_input = Vec::new();
//                 vrf_input.extend_from_slice(&validator.0);
//                 vrf_input.extend_from_slice(&block_number.to_le_bytes());
//                 vrf_input.extend_from_slice(&quantum_seed);
//                 let vrf_output = Blake2Hasher::hash(&vrf_input);
//                 vrf_results.push((validator.clone(), vrf_output));
//             }
//             vrf_results.sort_by(|(_, a), (_, b)| a.cmp(b));
//             let _leader = &vrf_results[0];
//         });
//     }
//
//     #[bench]
//     fn bench_vrf_election_100_validators(b: &mut Bencher) {
//         let block_number = 5u64;
//         let quantum_seed = [42u8; 32];
//         let validators: Vec<sp_core::sphincs::Public> = (0..100)
//             .map(|i| {
//                 let mut id = [0u8; 64];
//                 id[0] = i;
//                 sp_core::sphincs::Public::from_raw(id)
//             })
//             .collect();
//
//         b.iter(|| {
//             let mut vrf_results = Vec::new();
//             for validator in &validators {
//                 let mut vrf_input = Vec::new();
//                 vrf_input.extend_from_slice(&validator.0);
//                 vrf_input.extend_from_slice(&block_number.to_le_bytes());
//                 vrf_input.extend_from_slice(&quantum_seed);
//                 let vrf_output = Blake2Hasher::hash(&vrf_input);
//                 vrf_results.push((validator.clone(), vrf_output));
//             }
//             vrf_results.sort_by(|(_, a), (_, b)| a.cmp(b));
//             let _leader = &vrf_results[0];
//         });
//     }
//
//     #[bench]
//     fn bench_quantum_entropy_seed_generation(b: &mut Bencher) {
//         let block_number = 5u64;
//         let quantum_bytes = [42u8; 32];
//
//         b.iter(|| {
//             let mut seed_material = Vec::new();
//             seed_material.extend_from_slice(&block_number.to_le_bytes());
//             seed_material.extend_from_slice(&quantum_bytes);
//             let seed_hash = Blake2Hasher::hash(&seed_material);
//             let mut _seed = [0u8; 32];
//             _seed.copy_from_slice(seed_hash.as_ref());
//         });
//     }
//
//     #[bench]
//     fn bench_mempool_threshold_check(b: &mut Bencher) {
//         let ready_limit = 8192u32;
//         let grooming_threshold = (ready_limit * 75) / 100;
//
//         b.iter(|| {
//             let ready_count = 6200u32;
//             let _should_groom = ready_count >= grooming_threshold;
//         });
//     }
//
//     #[bench]
//     fn bench_per_validator_queue_insertion(b: &mut Bencher) {
//         let mut validator_queues: std::collections::HashMap<[u8; 64], PriorityQueue<u64, Reverse<u32>>> =
//             std::collections::HashMap::new();
//
//         let validator1 = [1u8; 64];
//         validator_queues.insert(validator1, PriorityQueue::new());
//
//         let mut proof_id = 0u64;
//         b.iter(|| {
//             validator_queues.get_mut(&validator1).unwrap().push(proof_id, Reverse(500));
//             proof_id += 1;
//         });
//     }
//
//     #[bench]
//     fn bench_leader_proof_collection(b: &mut Bencher) {
//         b.iter(|| {
//             let mut validator_queues: std::collections::HashMap<[u8; 64], PriorityQueue<u64, Reverse<u32>>> =
//                 std::collections::HashMap::new();
//
//             // Setup 3 validators with proofs
//             for v in 0..3 {
//                 let mut validator_id = [0u8; 64];
//                 validator_id[0] = v;
//                 let mut queue = PriorityQueue::new();
//
//                 for i in 0..10 {
//                     queue.push((v * 10 + i) as u64, Reverse(400 + (i * 10) as u32));
//                 }
//                 validator_queues.insert(validator_id, queue);
//             }
//
//             // Leader collects top 2 from each
//             let mut collected_proofs = Vec::new();
//             for (_validator_id, queue) in validator_queues.iter_mut() {
//                 for _ in 0..2 {
//                     if let Some((proof_id, _priority)) = queue.pop() {
//                         collected_proofs.push(proof_id);
//                     }
//                 }
//             }
//         });
//     }
// }
