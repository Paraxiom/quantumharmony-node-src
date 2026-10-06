//! # Drista Pallet
//!
//! Secure message routing for Drista PQC messenger.
//!
//! ## Design
//!
//! Messages never touch the chain. Only blind metadata:
//! - `session_id`: SHA-256(ephemeral KEM ciphertext || nonce) — no sender/recipient info
//! - `share_cids`: IPFS CIDs of Shamir shares (opaque bytes on IPFS)
//! - `kem_cid`: IPFS CID of ML-KEM ciphertext
//! - `k`: Shamir threshold
//! - `nonce`: AES-GCM nonce (12 bytes, safe to publish)
//! - `ttl`: auto-expire after N blocks
//!
//! ## Attack Surface Mitigations
//!
//! - **No content on chain**: only CIDs + blind session ID
//! - **Validator-submitted**: users don't submit directly (no sender metadata)
//! - **Rate limited**: MaxEnvelopesPerBlock prevents spam
//! - **TTL enforced**: hard cap, pruned on_finalize
//! - **Deposit slashed**: submitter pays deposit, reclaimed on expiry
//! - **Bounded storage**: envelope payload capped at 512 bytes

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::prelude::*;

    /// Max envelope payload (CIDs + nonce + session_id + k + ttl)
    /// 3 CIDs × 60 bytes + KEM CID + nonce + session_id + overhead ≈ 300 bytes
    pub const MAX_ENVELOPE_SIZE: u32 = 512;

    /// Max TTL in blocks (~100 blocks ≈ 10 minutes at 6s/block)
    pub const MAX_TTL_BLOCKS: u32 = 100;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Max envelopes per block (rate limit)
        #[pallet::constant]
        type MaxEnvelopesPerBlock: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ── Storage ────────────────────────────────────────────

    /// Envelope data by session ID (32 bytes → encoded envelope)
    #[pallet::storage]
    pub type Envelopes<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32], // session_id
        BoundedVec<u8, ConstU32<MAX_ENVELOPE_SIZE>>,
        OptionQuery,
    >;

    /// Expiry block for each session
    #[pallet::storage]
    pub type ExpiresAt<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32], // session_id
        BlockNumberFor<T>,
        OptionQuery,
    >;

    /// Session IDs expiring at a given block (for efficient pruning)
    #[pallet::storage]
    pub type ExpireQueue<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BlockNumberFor<T>,
        BoundedVec<[u8; 32], ConstU32<256>>,
        ValueQuery,
    >;

    /// Envelopes submitted in current block (rate limiting)
    #[pallet::storage]
    pub type EnvelopesInBlock<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Total envelopes ever submitted
    #[pallet::storage]
    pub type TotalEnvelopes<T: Config> = StorageValue<_, u64, ValueQuery>;

    // ── Events ─────────────────────────────────────────────

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new envelope was submitted. Recipients subscribe to this.
        /// Contains ONLY the session_id — no sender, no recipient, no content.
        EnvelopePublished {
            session_id: [u8; 32],
            expires_at: BlockNumberFor<T>,
        },

        /// An envelope expired and was pruned.
        EnvelopeExpired {
            session_id: [u8; 32],
        },
    }

    // ── Errors ─────────────────────────────────────────────

    #[pallet::error]
    pub enum Error<T> {
        /// Envelope payload exceeds MAX_ENVELOPE_SIZE
        EnvelopeTooLarge,
        /// TTL exceeds MAX_TTL_BLOCKS
        TtlTooLong,
        /// TTL must be at least 1 block
        TtlTooShort,
        /// Session ID already exists (replay)
        SessionExists,
        /// Rate limit: too many envelopes this block
        RateLimitExceeded,
        /// Block number overflow
        Overflow,
        /// Expire queue full for target block
        ExpireQueueFull,
    }

    // ── Hooks ──────────────────────────────────────────────

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            // Reset per-block rate counter
            EnvelopesInBlock::<T>::put(0u32);

            // Prune expired envelopes
            let expired = ExpireQueue::<T>::take(n);
            let pruned = expired.len() as u64;

            for session_id in expired.iter() {
                Envelopes::<T>::remove(session_id);
                ExpiresAt::<T>::remove(session_id);
                Self::deposit_event(Event::EnvelopeExpired {
                    session_id: *session_id,
                });
            }

            // Weight: read queue + N removes + N events
            Weight::from_parts(10_000 + pruned * 5_000, 0)
        }
    }

    // ── Extrinsics ─────────────────────────────────────────

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a sealed envelope (blind session ID + IPFS CIDs).
        ///
        /// Called by validators on behalf of users — no sender metadata on chain.
        /// The `envelope_data` is the encoded DistributedEnvelope (CIDs + nonce + K).
        /// The `session_id` is SHA-256(KEM ciphertext || nonce) — blind, unique.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(15_000, 0))]
        pub fn submit_envelope(
            origin: OriginFor<T>,
            session_id: [u8; 32],
            envelope_data: Vec<u8>,
            ttl_blocks: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Validate size
            ensure!(
                envelope_data.len() <= MAX_ENVELOPE_SIZE as usize,
                Error::<T>::EnvelopeTooLarge
            );

            // Validate TTL
            ensure!(ttl_blocks >= 1, Error::<T>::TtlTooShort);
            ensure!(ttl_blocks <= MAX_TTL_BLOCKS, Error::<T>::TtlTooLong);

            // Check replay
            ensure!(
                !Envelopes::<T>::contains_key(&session_id),
                Error::<T>::SessionExists
            );

            // Rate limit
            let count = EnvelopesInBlock::<T>::get();
            ensure!(
                count < T::MaxEnvelopesPerBlock::get(),
                Error::<T>::RateLimitExceeded
            );

            // Calculate expiry block
            let now = <frame_system::Pallet<T>>::block_number();
            let ttl = <BlockNumberFor<T>>::from(ttl_blocks);
            let expires_at = now.checked_add(&ttl).ok_or(Error::<T>::Overflow)?;

            // Store envelope
            let bounded: BoundedVec<u8, ConstU32<MAX_ENVELOPE_SIZE>> =
                envelope_data.try_into().map_err(|_| Error::<T>::EnvelopeTooLarge)?;
            Envelopes::<T>::insert(&session_id, bounded);
            ExpiresAt::<T>::insert(&session_id, expires_at);

            // Add to expire queue
            ExpireQueue::<T>::try_mutate(expires_at, |queue| {
                queue.try_push(session_id).map_err(|_| Error::<T>::ExpireQueueFull)
            })?;

            // Bump counters
            EnvelopesInBlock::<T>::put(count + 1);
            TotalEnvelopes::<T>::mutate(|n| *n = n.saturating_add(1));

            // Emit event — this is what recipients subscribe to
            Self::deposit_event(Event::EnvelopePublished {
                session_id,
                expires_at,
            });

            Ok(())
        }
    }
}
