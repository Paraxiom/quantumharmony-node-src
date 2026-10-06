//! Chunked Runtime Upgrade RPC
//!
//! RPC interface for uploading runtime upgrades in chunks to bypass BlockLength limits.
//!
//! ## Flow
//! 1. Client calls `initiate_chunked_upgrade` with WASM hash and chunk count
//! 2. Client uploads each chunk via `upload_chunk` (each chunk signed with SPHINCS+)
//! 3. Client calls `finalize_chunked_upgrade` to assemble and apply the upgrade
//!
//! Each chunk transaction is ~115KB (64KB data + 50KB SPHINCS+ signature + overhead),
//! well under the 256KB BlockLength limit.

use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    types::error::ErrorObject,
};
use jsonrpsee_types::ErrorObjectOwned;
use sp_api::{Core, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use quantumharmony_runtime::{RuntimeCall, Runtime, SignedExtra, SignedPayload, UncheckedExtrinsic};
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
use scale_codec::{Encode, Decode};
use std::sync::Arc;
use log;
use hex;

use sp_core::{Pair, sphincs::Pair as SphincsPair, sphincs::SignatureWithPublic, H256};
use sp_core::crypto::AccountId32;
use frame_system_rpc_runtime_api::AccountNonceApi;
use sp_runtime::{generic::Era, MultiAddress, MultiSignature};

use pallet_runtime_segmentation::chunked_upgrade::{MAX_CHUNK_SIZE, MAX_CHUNKS, PendingUpgradeMeta};
use sc_client_api::StorageProvider;
use sp_core::storage::StorageKey;

/// Chunked upgrade status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkedUpgradeStatus {
    pub upgrade_id: String,
    pub chunks_received: u8,
    pub total_chunks: u8,
    pub expected_size: u32,
    pub ready_to_finalize: bool,
}

#[rpc(client, server)]
pub trait ChunkedUpgradeApi {
    /// Initiate a chunked runtime upgrade
    ///
    /// # Parameters
    /// - `wasm_hex`: Complete WASM blob (hex encoded) - will be split into chunks
    /// - `secret_key`: SPHINCS+ 128-byte secret key (hex encoded)
    ///
    /// # Returns
    /// Upgrade ID and number of chunks to upload
    #[method(name = "chunkedUpgrade_initiate", with_extensions)]
    async fn initiate_chunked_upgrade(
        &self,
        wasm_hex: String,
        secret_key: String,
    ) -> RpcResult<ChunkedUpgradeStatus>;

    /// Upload a single chunk
    ///
    /// # Parameters
    /// - `chunk_index`: 0-based index of this chunk
    /// - `chunk_hex`: Chunk data (hex encoded)
    /// - `secret_key`: SPHINCS+ 128-byte secret key (hex encoded)
    ///
    /// # Returns
    /// Transaction hash
    #[method(name = "chunkedUpgrade_uploadChunk", with_extensions)]
    async fn upload_chunk(
        &self,
        chunk_index: u8,
        chunk_hex: String,
        secret_key: String,
    ) -> RpcResult<String>;

    /// Finalize the chunked upgrade
    ///
    /// # Parameters
    /// - `secret_key`: SPHINCS+ 128-byte secret key (hex encoded)
    ///
    /// # Returns
    /// Transaction hash
    #[method(name = "chunkedUpgrade_finalize", with_extensions)]
    async fn finalize_chunked_upgrade(
        &self,
        secret_key: String,
    ) -> RpcResult<String>;

    /// Get current upgrade status
    #[method(name = "chunkedUpgrade_status")]
    async fn get_status(&self) -> RpcResult<Option<ChunkedUpgradeStatus>>;

    /// Cancel pending upgrade
    #[method(name = "chunkedUpgrade_cancel", with_extensions)]
    async fn cancel_upgrade(
        &self,
        secret_key: String,
    ) -> RpcResult<String>;

    /// Calculate how many chunks are needed for a WASM of given size
    #[method(name = "chunkedUpgrade_calculateChunks")]
    async fn calculate_chunks(&self, wasm_size: u32) -> RpcResult<u8>;

    /// One-shot validator onboarding via sudo.
    ///
    /// Performs three extrinsic submissions, each signed with the sudo key:
    /// 1. `sudo.sudoUncheckedWeight(balances.transferKeepAlive(new_validator, fund_amount))`
    /// 2. `sudo.sudoAs(new_validator, session.setKeys(SessionKeys{aura: aura_pub}, vec![]))`
    /// 3. `sudo.sudoUncheckedWeight(validator_set.addValidator(new_validator))`
    ///
    /// # Parameters
    /// - `sudo_secret_key`: sudo holder's SPHINCS+ 128-byte secret key (hex, 0x-prefixed)
    /// - `new_validator_account_hex`: target validator's AccountId32 (32 bytes, hex, 0x-prefixed)
    ///                                — this is Keccak256 of the validator's 64-byte SPHINCS+ pubkey
    /// - `new_validator_aura_pub_hex`: target validator's SPHINCS+ Aura pubkey (64 bytes, hex, 0x-prefixed)
    /// - `fund_amount`: balance to transfer (as decimal string, to handle u128)
    ///
    /// # Returns
    /// Vector of three extrinsic hashes, in submission order.
    #[method(name = "validatorSet_addValidatorFlow")]
    async fn add_validator_flow(
        &self,
        sudo_secret_key: String,
        new_validator_account_hex: String,
        new_validator_aura_pub_hex: String,
        fund_amount: String,
    ) -> RpcResult<Vec<String>>;

    /// Read `TransparenceDeliverables::Recorder` from on-chain storage.
    ///
    /// Exists so the mandatory post-upgrade step can be *verified*, not just
    /// performed. Until the recorder is set, every `transparence_record*` call
    /// fails with `NotRecorder`, and nothing in those calls' responses says why.
    ///
    /// Returns the account as `0x`-prefixed hex, or `None` if recording is off.
    #[method(name = "transparence_recorderStatus")]
    async fn transparence_recorder_status(&self) -> RpcResult<Option<String>>;

    /// `sudo(TransparenceDeliverables::set_recorder(recorder))`.
    ///
    /// `set_recorder` is root-only (call index 7) and had **no RPC at all**
    /// before 2026-09-27, so the one step that has to follow a runtime upgrade
    /// could not be performed with the node's own tooling. The sudo key is
    /// SPHINCS+, so no external signer could build the call either.
    ///
    /// Pass `recorder_account_hex` as the 32-byte account in hex to authorise a
    /// writer, or `None` to stop all recording.
    ///
    /// ⚠️ Like every sudo call here, the returned hash means *submitted*, not
    /// *executed*. Confirm with `transparence_recorderStatus`.
    #[method(name = "transparence_setRecorder")]
    async fn transparence_set_recorder(
        &self,
        sudo_secret_key: String,
        recorder_account_hex: Option<String>,
    ) -> RpcResult<String>;
}

use std::sync::atomic::{AtomicU32, Ordering};

pub struct ChunkedUpgradeRpc<C, P, Block, BE> {
    client: Arc<C>,
    pool: Arc<P>,
    /// The next nonce to use, as an ABSOLUTE value, not an offset.
    ///
    /// This used to be an offset added to a freshly re-read on-chain nonce,
    /// which double-counted every inclusion. Submitting 16 chunks produced:
    ///
    ///     Using nonce 14 (on-chain: 0,  offset: 14)
    ///     Using nonce 29 (on-chain: 14, offset: 15)   <-- jumps 14 -> 29
    ///
    /// Nonces 15..=28 would never exist, so everything from that point on sat
    /// in the pool as future transactions that could never become ready. The
    /// RPC still returned a hash for each, so the uploads looked successful
    /// while 2 of 16 chunks silently never landed. `u32::MAX` means unset.
    next_nonce: AtomicU32,
    _phantom: std::marker::PhantomData<(Block, BE)>,
}

impl<C, P, Block, BE> ChunkedUpgradeRpc<C, P, Block, BE> {
    pub fn new(client: Arc<C>, pool: Arc<P>) -> Self {
        Self {
            client,
            pool,
            next_nonce: AtomicU32::new(u32::MAX),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Forget the locally tracked nonce, so the next submission re-reads the
    /// chain. Call when abandoning a sequence of submissions.
    fn reset_nonce_offset(&self) {
        self.next_nonce.store(u32::MAX, Ordering::SeqCst);
    }

    /// Claim the next nonce for a submission.
    ///
    /// Takes whichever is greater: the nonce the chain already reflects, or the
    /// one after our last submission. Both matter. The chain's value alone
    /// repeats a nonce for transactions still queued; ours alone goes stale if
    /// something else spends from the account. Never add them together.
    fn claim_nonce(&self, on_chain_nonce: u32) -> u32 {
        let mut claimed = on_chain_nonce;
        let _ = self.next_nonce.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |tracked| {
            claimed = if tracked == u32::MAX || on_chain_nonce > tracked {
                on_chain_nonce
            } else {
                tracked
            };
            Some(claimed + 1)
        });
        claimed
    }
}

impl<C, P, Block, BE> ChunkedUpgradeRpc<C, P, Block, BE>
where
    Block: BlockT,
    BE: sc_client_api::Backend<Block> + Send + Sync + 'static,
    C: Send + Sync + 'static + HeaderBackend<Block> + StorageProvider<Block, BE>,
{
    /// Read a plain `StorageValue` by pallet and item name.
    ///
    /// The key of a StorageValue is twox_128(pallet) ++ twox_128(item), where
    /// the pallet name is the one used in `construct_runtime!` — here
    /// `ChunkedUpgrade` (runtime/src/lib.rs). `Ok(None)` means the value is
    /// genuinely absent, which callers must distinguish from an error.
    fn storage_value(
        &self,
        at: Block::Hash,
        pallet: &[u8],
        item: &[u8],
    ) -> Result<Option<Vec<u8>>, sp_blockchain::Error> {
        let mut key = sp_core::twox_128(pallet).to_vec();
        key.extend_from_slice(&sp_core::twox_128(item));
        Ok(self.client.storage(at, &StorageKey(key))?.map(|data| data.0))
    }
}

#[async_trait]
impl<C, P, Block, BE> ChunkedUpgradeApiServer for ChunkedUpgradeRpc<C, P, Block, BE>
where
    Block: BlockT,
    BE: sc_client_api::Backend<Block> + Send + Sync + 'static,
    C: Send + Sync + 'static
        + ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + StorageProvider<Block, BE>,
    C::Api: AccountNonceApi<Block, AccountId32, u32> + Core<Block>,
    P: Send + Sync + 'static + TransactionPool<Block = Block>,
{
    async fn initiate_chunked_upgrade(
        &self, ext: &jsonrpsee::Extensions,
        wasm_hex: String,
        secret_key: String,
    ) -> RpcResult<ChunkedUpgradeStatus> {
        // Node administration: refused unless the node runs --rpc-methods Unsafe.
        sc_rpc_api::check_if_safe(ext)?;
        log::info!("🔄 Chunked upgrade initiation requested");

        // Reset nonce offset for new upgrade session
        self.reset_nonce_offset();

        // Decode WASM
        let wasm_code = hex::decode(wasm_hex.trim_start_matches("0x"))
            .map_err(|e| error_object(-32602, format!("Invalid WASM hex: {}", e)))?;

        let wasm_size = wasm_code.len() as u32;
        log::info!("   WASM size: {} bytes ({} KB)", wasm_size, wasm_size / 1024);

        // Calculate chunks needed
        let total_chunks = ((wasm_size + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE) as u8;
        if total_chunks > MAX_CHUNKS as u8 {
            return Err(error_object(-32602, format!(
                "WASM too large: {} bytes requires {} chunks, max is {}",
                wasm_size, total_chunks, MAX_CHUNKS
            )));
        }

        log::info!("   Will split into {} chunks of max {}KB each", total_chunks, MAX_CHUNK_SIZE / 1024);

        // Hash the blob with the RUNTIME's configured hasher, not a hardcoded one.
        //
        // This was `sp_core::hashing::blake2_256`, while the pallet's
        // finalize_chunked_upgrade compares against `T::Hashing::hash(..)`. This
        // fork sets `type Hashing = QuantumHasher` (runtime/src/lib.rs:188),
        // which is keccak_256, so the two values could never be equal:
        //
        //   blake2_256(blob)  a62808fb…   <- was stored as ExpectedWasmHash
        //   keccak_256(blob)  f638e2b1…   <- what finalize actually computes
        //
        // Every chunked upgrade therefore failed with WasmHashMismatch, and the
        // failure was invisible because sudo_unchecked_weight reports an inner
        // error as a successful extrinsic carrying Sudid(Err(..)).
        //
        // Deriving the hasher from the runtime type means this tracks any future
        // change to `Hashing` instead of silently diverging again.
        use sp_runtime::traits::Hash as HashT;
        let wasm_hash_h256 =
            <<Runtime as frame_system::Config>::Hashing as HashT>::hash(&wasm_code);

        log::info!("   WASM hash: 0x{}", hex::encode(wasm_hash_h256.as_bytes()));

        // Load keypair
        let keypair = load_sphincs_keypair(&secret_key)?;
        log::info!("   SPHINCS+ keypair loaded");

        // Build the initiate_chunked_upgrade call
        // ChunkedUpgrade::initiate_chunked_upgrade(total_chunks, expected_size, wasm_hash, chunk_hashes, chunk_sizes)
        let call = RuntimeCall::ChunkedUpgrade(
            pallet_runtime_segmentation::chunked_upgrade::pallet::Call::initiate_chunked_upgrade {
                total_chunks,
                expected_size: wasm_size,
                wasm_hash: wasm_hash_h256,
                chunk_hashes: None,  // Optional: will be verified if provided
                chunk_sizes: None,   // Optional: will be verified if provided
            }
        );

        // Submit transaction
        let tx_hash = self.submit_sudo_call(call, &keypair).await?;

        log::info!("✅ Chunked upgrade initiated: {}", tx_hash);

        Ok(ChunkedUpgradeStatus {
            // NOTE: this is the blob hash. `get_status` instead reports the
            // pallet's own CurrentUpgradeId, which is a different value.
            upgrade_id: format!("0x{}", hex::encode(wasm_hash_h256.as_bytes())),
            chunks_received: 0,
            total_chunks,
            expected_size: wasm_size,
            ready_to_finalize: false,
        })
    }

    async fn upload_chunk(
        &self, ext: &jsonrpsee::Extensions,
        chunk_index: u8,
        chunk_hex: String,
        secret_key: String,
    ) -> RpcResult<String> {
        // Node administration: refused unless the node runs --rpc-methods Unsafe.
        sc_rpc_api::check_if_safe(ext)?;
        log::info!("📦 Uploading chunk {}", chunk_index);

        // Decode chunk data
        let chunk_data = hex::decode(chunk_hex.trim_start_matches("0x"))
            .map_err(|e| error_object(-32602, format!("Invalid chunk hex: {}", e)))?;

        if chunk_data.len() > MAX_CHUNK_SIZE as usize {
            return Err(error_object(-32602, format!(
                "Chunk too large: {} bytes, max is {}",
                chunk_data.len(), MAX_CHUNK_SIZE
            )));
        }

        log::info!("   Chunk {} size: {} bytes", chunk_index, chunk_data.len());

        // Load keypair
        let keypair = load_sphincs_keypair(&secret_key)?;

        // Build the upload_chunk call
        let call = RuntimeCall::ChunkedUpgrade(
            pallet_runtime_segmentation::chunked_upgrade::pallet::Call::upload_chunk {
                chunk_index,
                chunk_data,
            }
        );

        // Submit transaction
        let tx_hash = self.submit_sudo_call(call, &keypair).await?;

        log::info!("✅ Chunk {} uploaded: {}", chunk_index, tx_hash);

        Ok(tx_hash)
    }

    async fn finalize_chunked_upgrade(
        &self, ext: &jsonrpsee::Extensions,
        secret_key: String,
    ) -> RpcResult<String> {
        // Node administration: refused unless the node runs --rpc-methods Unsafe.
        sc_rpc_api::check_if_safe(ext)?;
        log::info!("🚀 Finalizing chunked upgrade");

        // Load keypair
        let keypair = load_sphincs_keypair(&secret_key)?;

        // Build the finalize_chunked_upgrade call
        let call = RuntimeCall::ChunkedUpgrade(
            pallet_runtime_segmentation::chunked_upgrade::pallet::Call::finalize_chunked_upgrade {}
        );

        // Submit transaction
        let tx_hash = self.submit_sudo_call(call, &keypair).await?;

        log::info!("✅ Chunked upgrade finalized: {}", tx_hash);

        Ok(tx_hash)
    }

    async fn get_status(&self) -> RpcResult<Option<ChunkedUpgradeStatus>> {
        // Reads the ChunkedUpgrade pallet's own storage at the best block.
        //
        // This was a hardcoded `Ok(None)` until 2026-09-26, commented
        // "Placeholder until pallet integration complete". That made the one
        // method an operator would use to check whether an upgrade is actually
        // progressing incapable of ever saying anything, and it made
        // `test_chunked_upgrade_status_no_pending` a test that cannot fail.
        // A chunked upgrade was run in which every call returned success and
        // the spec version never moved; with this returning None there was no
        // way to see that from the outside.
        let best_hash = self.client.info().best_hash;

        let pending_raw = self
            .storage_value(best_hash, b"ChunkedUpgrade", b"CurrentPendingUpgrade")
            .map_err(|e| error_object(-32603, format!("Failed to read CurrentPendingUpgrade: {}", e)))?;

        // No pending upgrade is a legitimate answer, not an error.
        let Some(bytes) = pending_raw else { return Ok(None) };

        let meta = PendingUpgradeMeta::decode(&mut &bytes[..]).map_err(|e| {
            error_object(-32603, format!("Failed to decode PendingUpgradeMeta: {}", e))
        })?;

        // The upgrade id is a separate StorageValue and may legitimately be
        // absent; report it empty rather than failing the whole call.
        let upgrade_id = match self.storage_value(best_hash, b"ChunkedUpgrade", b"CurrentUpgradeId") {
            Ok(Some(raw)) => H256::decode(&mut &raw[..])
                .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                .unwrap_or_default(),
            _ => String::new(),
        };

        Ok(Some(ChunkedUpgradeStatus {
            upgrade_id,
            chunks_received: meta.chunks_received,
            total_chunks: meta.total_chunks,
            expected_size: meta.expected_size,
            ready_to_finalize: meta.total_chunks > 0
                && meta.chunks_received >= meta.total_chunks,
        }))
    }

    async fn cancel_upgrade(
        &self, ext: &jsonrpsee::Extensions,
        secret_key: String,
    ) -> RpcResult<String> {
        // Node administration: refused unless the node runs --rpc-methods Unsafe.
        sc_rpc_api::check_if_safe(ext)?;
        log::info!("❌ Cancelling chunked upgrade");

        // Reset nonce offset
        self.reset_nonce_offset();

        // Load keypair
        let keypair = load_sphincs_keypair(&secret_key)?;

        // Build the cancel call
        let call = RuntimeCall::ChunkedUpgrade(
            pallet_runtime_segmentation::chunked_upgrade::pallet::Call::cancel_chunked_upgrade {}
        );

        // Submit transaction
        let tx_hash = self.submit_sudo_call(call, &keypair).await?;

        log::info!("✅ Chunked upgrade cancelled: {}", tx_hash);

        Ok(tx_hash)
    }

    async fn calculate_chunks(&self, wasm_size: u32) -> RpcResult<u8> {
        let chunks = ((wasm_size + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE) as u8;
        Ok(chunks)
    }

    async fn add_validator_flow(
        &self,
        sudo_secret_key: String,
        new_validator_account_hex: String,
        new_validator_aura_pub_hex: String,
        fund_amount: String,
    ) -> RpcResult<Vec<String>> {
        use frame_support::weights::Weight;
        use quantumharmony_runtime::{SudoCall, opaque::SessionKeys};
        use sp_core::sphincs::Public as SphincsPublic;

        log::info!("🔐 [ADD-VALIDATOR-FLOW] starting");

        // Reset nonce offset — we'll submit 3 txs in sequence, each needs its own nonce
        self.reset_nonce_offset();

        // Parse sudo keypair
        let keypair = load_sphincs_keypair(&sudo_secret_key)?;
        log::info!("🔐 [ADD-VALIDATOR-FLOW] sudo keypair loaded, pk=0x{}...", hex::encode(&keypair.public().as_ref()[..8]));

        // Parse target AccountId
        let account_bytes = hex::decode(new_validator_account_hex.trim_start_matches("0x"))
            .map_err(|e| error_object(-32602, format!("Invalid new_validator_account_hex: {}", e)))?;
        if account_bytes.len() != 32 {
            return Err(error_object(-32602, format!(
                "new_validator_account_hex must be 32 bytes, got {}",
                account_bytes.len()
            )));
        }
        let new_validator_account = AccountId32::new(
            account_bytes.try_into()
                .map_err(|_| error_object(-32602, "account bytes to array failed".to_string()))?
        );
        log::info!("🔐 [ADD-VALIDATOR-FLOW] new_validator_account=0x{}", hex::encode(AsRef::<[u8; 32]>::as_ref(&new_validator_account)));

        // Parse target Aura pubkey
        let aura_pub_bytes = hex::decode(new_validator_aura_pub_hex.trim_start_matches("0x"))
            .map_err(|e| error_object(-32602, format!("Invalid new_validator_aura_pub_hex: {}", e)))?;
        if aura_pub_bytes.len() != 64 {
            return Err(error_object(-32602, format!(
                "new_validator_aura_pub_hex must be 64 bytes, got {}",
                aura_pub_bytes.len()
            )));
        }
        let aura_pub_arr: [u8; 64] = aura_pub_bytes.try_into()
            .map_err(|_| error_object(-32602, "aura pubkey bytes to array failed".to_string()))?;
        let aura_public = SphincsPublic::from_raw(aura_pub_arr);
        log::info!("🔐 [ADD-VALIDATOR-FLOW] new_validator_aura_pub=0x{}...", hex::encode(&aura_pub_arr[..8]));

        // Parse fund amount
        let amount: u128 = fund_amount.parse()
            .map_err(|e| error_object(-32602, format!("Invalid fund_amount (must be decimal u128): {}", e)))?;
        log::info!("🔐 [ADD-VALIDATOR-FLOW] fund_amount={}", amount);

        // ===== STEP 1: fund the new validator via direct (Alice-signed) transfer =====
        // NOTE: transferKeepAlive requires a Signed origin — wrapping in sudo would
        // give Root origin and fail. Alice (as the sudo holder) holds genesis balance,
        // so we sign the transfer directly with her key and skip the sudo wrapper.
        log::info!("🔐 [ADD-VALIDATOR-FLOW] step 1/3: funding new validator (direct transfer)");
        let transfer_call = RuntimeCall::Balances(
            pallet_balances::Call::transfer_keep_alive {
                dest: MultiAddress::Id(new_validator_account.clone()),
                value: amount,
            }
        );
        let transfer_hash = self.submit_signed_raw_call(transfer_call, &keypair).await?;
        log::info!("🔐 [ADD-VALIDATOR-FLOW] step 1/3 tx: {}", transfer_hash);

        // ===== STEP 2: register session keys via sudo.sudoAs(new_validator, session.setKeys(...)) =====
        log::info!("🔐 [ADD-VALIDATOR-FLOW] step 2/3: registering session keys as new validator");
        // Convert SphincsPublic to the AuthorityId type expected by SessionKeys.aura
        use sp_core::crypto::ByteArray;
        let aura_auth_id = sp_consensus_aura::sphincs::AuthorityId::from_slice(aura_public.as_ref())
            .map_err(|_| error_object(-32603, "failed to convert SPHINCS+ pubkey to AuraId".to_string()))?;
        let inner_set_keys = RuntimeCall::Session(
            pallet_session::Call::set_keys {
                keys: SessionKeys { aura: aura_auth_id },
                proof: sp_std::vec::Vec::new(),
            }
        );
        let sudo_as_call = RuntimeCall::Sudo(
            SudoCall::sudo_as {
                who: MultiAddress::Id(new_validator_account.clone()),
                call: Box::new(inner_set_keys),
            }
        );
        let set_keys_hash = self.submit_signed_raw_call(sudo_as_call, &keypair).await?;
        log::info!("🔐 [ADD-VALIDATOR-FLOW] step 2/3 tx: {}", set_keys_hash);

        // ===== STEP 3: admit to validator set via sudo(validator_set.addValidator) =====
        log::info!("🔐 [ADD-VALIDATOR-FLOW] step 3/3: admitting to validator set");
        let add_validator_call = RuntimeCall::ValidatorSet(
            substrate_validator_set::Call::add_validator {
                validator_id: new_validator_account.clone(),
            }
        );
        let add_hash = self.submit_sudo_call(add_validator_call, &keypair).await?;
        log::info!("🔐 [ADD-VALIDATOR-FLOW] step 3/3 tx: {}", add_hash);

        log::info!("✅ [ADD-VALIDATOR-FLOW] all 3 extrinsics submitted");
        Ok(vec![transfer_hash, set_keys_hash, add_hash])
    }

    async fn transparence_recorder_status(&self) -> RpcResult<Option<String>> {
        let best_hash = self.client.info().best_hash;
        let raw = self
            .storage_value(best_hash, b"TransparenceDeliverables", b"Recorder")
            .map_err(|e| error_object(-32603, format!("Failed to read Recorder: {}", e)))?;

        // Absent means recording is switched off, which is a legitimate answer.
        let Some(bytes) = raw else { return Ok(None) };
        let account = AccountId32::decode(&mut &bytes[..])
            .map_err(|e| error_object(-32603, format!("Failed to decode Recorder: {}", e)))?;
        Ok(Some(format!("0x{}", hex::encode(AsRef::<[u8; 32]>::as_ref(&account)))))
    }

    async fn transparence_set_recorder(
        &self,
        sudo_secret_key: String,
        recorder_account_hex: Option<String>,
    ) -> RpcResult<String> {
        let recorder = match recorder_account_hex {
            None => None,
            Some(h) => {
                let bytes = hex::decode(h.trim_start_matches("0x"))
                    .map_err(|e| error_object(-32602, format!("Invalid account hex: {}", e)))?;
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    error_object(
                        -32602,
                        format!("Account must be 32 bytes, got {}", bytes.len()),
                    )
                })?;
                Some(AccountId32::from(arr))
            }
        };

        match &recorder {
            Some(a) => log::info!(
                "📝 set_recorder -> 0x{}",
                hex::encode(AsRef::<[u8; 32]>::as_ref(a))
            ),
            None => log::warn!("📝 set_recorder -> None: this STOPS all Transparence recording"),
        }

        let keypair = load_sphincs_keypair(&sudo_secret_key)?;
        let call = RuntimeCall::TransparenceDeliverables(
            pallet_transparence_deliverables::Call::set_recorder { recorder },
        );
        let tx_hash = self.submit_sudo_call(call, &keypair).await?;
        log::info!("✅ set_recorder submitted: {} (verify with transparence_recorderStatus)", tx_hash);
        Ok(tx_hash)
    }
}

impl<C, P, Block, BE> ChunkedUpgradeRpc<C, P, Block, BE>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: AccountNonceApi<Block, AccountId32, u32> + Core<Block>,
    P: Send + Sync + 'static + TransactionPool<Block = Block>,
{
    /// Submit a sudo-wrapped call with SPHINCS+ signature.
    ///
    /// Wraps `inner_call` in `sudo.sudoUncheckedWeight(...)` then delegates to
    /// `submit_signed_raw_call` for the actual signing+submit. If you need a
    /// different wrapper (e.g. `sudo.sudoAs`), build the call yourself and
    /// call `submit_signed_raw_call` directly.
    async fn submit_sudo_call(
        &self,
        inner_call: RuntimeCall,
        keypair: &SphincsPair,
    ) -> RpcResult<String> {
        use frame_support::weights::Weight;
        use quantumharmony_runtime::SudoCall;

        // Wrap in sudo.sudoUncheckedWeight
        let call = RuntimeCall::Sudo(
            SudoCall::sudo_unchecked_weight {
                call: Box::new(inner_call),
                weight: Weight::from_parts(0, 0),
            }
        );

        self.submit_signed_raw_call(call, keypair).await
    }

    /// Sign and submit a fully-formed RuntimeCall with the given SPHINCS+ keypair.
    ///
    /// Does NOT wrap the call in anything — the caller is responsible for any
    /// sudo/sudoAs/proxy wrapping. Handles nonce, era, genesis hash, and runtime
    /// version binding automatically.
    async fn submit_signed_raw_call(
        &self,
        call: RuntimeCall,
        keypair: &SphincsPair,
    ) -> RpcResult<String> {
        // Get signer account
        use sp_runtime::traits::IdentifyAccount;
        use sp_runtime::MultiSigner;
        let public_key = keypair.public();
        log::info!("   DEBUG: Public key (first 16 bytes): {:02x?}", &public_key.as_ref()[..16]);
        log::info!("   DEBUG: Public key (full): 0x{}", hex::encode(public_key.as_ref()));
        let signer_account = MultiSigner::from(public_key).into_account();
        log::info!("   DEBUG: Signer AccountId: 0x{}", hex::encode(AsRef::<[u8; 32]>::as_ref(&signer_account)));

        // Get nonce from chain + pending offset
        let best_hash = self.client.info().best_hash;
        let on_chain_nonce = self.client
            .runtime_api()
            .account_nonce(best_hash, signer_account.clone())
            .map_err(|e| error_object(-32603, format!("Failed to get nonce: {}", e)))?;

        // Take max(chain, our own next), never chain + offset.
        let nonce = self.claim_nonce(on_chain_nonce);
        log::info!("   Using nonce {} (on-chain: {})", nonce, on_chain_nonce);

        // Get genesis hash
        let genesis_hash = {
            let hash = self.client.info().genesis_hash;
            sp_core::H256::from_slice(hash.as_ref())
        };

        // Get runtime version
        let runtime_version = self.client
            .runtime_api()
            .version(best_hash)
            .map_err(|e| error_object(-32603, format!("Failed to get runtime version: {}", e)))?;

        let spec_version = runtime_version.spec_version;
        let transaction_version = runtime_version.transaction_version;

        // Build SignedExtra
        let extra: SignedExtra = (
            frame_system::CheckNonZeroSender::<Runtime>::new(),
            frame_system::CheckSpecVersion::<Runtime>::new(),
            frame_system::CheckTxVersion::<Runtime>::new(),
            frame_system::CheckGenesis::<Runtime>::new(),
            frame_system::CheckEra::<Runtime>::from(Era::Immortal),
            frame_system::CheckNonce::<Runtime>::from(nonce),
            frame_system::CheckWeight::<Runtime>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
        );

        // Create signed payload
        let raw_payload = SignedPayload::from_raw(
            call.clone(),
            extra.clone(),
            (
                (),
                spec_version,
                transaction_version,
                genesis_hash,
                genesis_hash,
                (),
                (),
                (),
            ),
        );

        // Sign with SPHINCS+
        let signature = raw_payload.using_encoded(|payload| keypair.sign(payload));
        let sig_with_pub = SignatureWithPublic::new(signature, keypair.public());
        let sphincs_signature = MultiSignature::SphincsPlus(sig_with_pub);

        // Build extrinsic
        let extrinsic = UncheckedExtrinsic::new_signed(
            call,
            MultiAddress::Id(signer_account),
            sphincs_signature,
            extra,
        );

        // Encode and submit
        let encoded = extrinsic.encode();
        log::info!("   Extrinsic size: {} bytes", encoded.len());

        let block_extrinsic = Block::Extrinsic::decode(&mut &encoded[..])
            .map_err(|e| error_object(-32603, format!("Failed to decode extrinsic: {}", e)))?;

        let xt_hash = self.pool
            .submit_one(
                best_hash,
                TransactionSource::Local,
                block_extrinsic,
            )
            .await
            .map_err(|e| error_object(-32603, format!("Failed to submit transaction: {}", e)))?;

        Ok(format!("{:?}", xt_hash))
    }
}

/// Load SPHINCS+ keypair from hex-encoded 128-byte secret key
fn load_sphincs_keypair(secret_key: &str) -> RpcResult<SphincsPair> {
    let key_bytes = hex::decode(secret_key.trim_start_matches("0x"))
        .map_err(|e| error_object(-32602, format!("Invalid secret key hex: {}", e)))?;

    if key_bytes.len() != 128 {
        return Err(error_object(-32602, format!(
            "Invalid SPHINCS+ key size: {} bytes. Expected 128 bytes.",
            key_bytes.len()
        )));
    }

    let secret: [u8; 128] = key_bytes.try_into()
        .map_err(|_| error_object(-32602, "Failed to convert secret key to array".to_string()))?;

    Ok(SphincsPair::from_secret(secret))
}

/// Helper to create error objects
fn error_object(code: i32, message: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, message, None::<()>)
}
