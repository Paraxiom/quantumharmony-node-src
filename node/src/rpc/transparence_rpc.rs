//! Transparence RPC — milestone validation & payment authorisation
//!
//! Write path for the Transparence deliverables pallet.
//! Mirrors `notarial_rpc.rs`: the extrinsic envelope is signed **in the
//! keystore** with a dedicated key type, so no secret key ever crosses the
//! RPC boundary.
//!
//! This exists because the only pre-existing generic route,
//! `quantumharmony_submitSignedExtrinsic`, takes the caller's raw 128-byte
//! SPHINCS+ secret as a parameter. That is acceptable for an operator running
//! a one-off script on the box; it is not acceptable for `trust-services`,
//! which would then have to hold and transmit a chain private key to release
//! contract payments. See the audit note in
//! `docs/specs/transparence-milestone-release-wiring.md`.
//!
//! Methods:
//! - `transparence_recordValidationResult`  — record a milestone verdict
//! - `transparence_recordPaymentAuthorized` — authorise a milestone payment
//!
//! ## On-chain authorisation (spec 46+)
//!
//! `record_validation_result` and `record_payment_authorized` accept only the
//! pallet's `Recorder` account, set by root with
//! `TransparenceDeliverables::set_recorder`. It must be this node's `trsp`
//! account; until it is set, both calls fail with `NotRecorder`.
//!
//! ## Caller authentication
//!
//! Both methods sign as the Transparence writer, so the caller must prove it
//! is trust-services: `signer_fingerprint` must name a key in
//! `--rpc-caller-allowlist`, and `signature_hex` must be that key's Falcon
//! signature over `caller_auth::transparence_message`. See `caller_auth`.
//!
//! That controls who can use this node's `trsp` key; the pallet's `Recorder`
//! check (above) controls who the chain accepts.

use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    types::error::{ErrorCode, ErrorObject},
};
use scale_codec::{Decode, Encode};
use sp_core::crypto::KeyTypeId;
use sp_core::sphincs::SignatureWithPublic;
use sp_keystore::KeystorePtr;
use sp_runtime::{
    generic::Era,
    traits::{Block as BlockT, IdentifyAccount},
    transaction_validity::TransactionSource,
    AccountId32, MultiSignature,
};
use sc_transaction_pool_api::TransactionPool;
use sp_api::{Core, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use std::sync::Arc;
// Needed in scope for `runtime_api().account_nonce(..)` to resolve.
use frame_system_rpc_runtime_api::AccountNonceApi;

/// Dedicated keystore key type for the **Transparence writer**, distinct from
/// the notary (`notr`) and the AURA/validator key — contract execution is
/// separated from notarisation and from consensus.
///
/// Provision the secret with `author_insertKey` using key type `"trsp"`. The
/// key never leaves the keystore.
///
/// Operational note: this account must exist and be funded, and — once the
/// pallet gains its origin check — must be the account the pallet recognises
/// as the authorised recorder.
pub const TRANSPARENCE_KEY_TYPE: KeyTypeId = KeyTypeId(*b"trsp");

#[rpc(client, server)]
pub trait TransparenceApi<BlockHash> {
    /// Record the outcome of a milestone validation ceremony.
    ///
    /// Requires the milestone to be in `ValidationPending`. Returns the
    /// submitted extrinsic hash; inclusion is not awaited.
    ///
    /// `signature_hex` signs `caller_auth::transparence_message(genesis, 0x01,
    /// milestone_id, [passed as u8])`.
    #[method(name = "transparence_recordValidationResult")]
    async fn record_validation_result(
        &self,
        milestone_id: u64,
        passed: bool,
        signer_fingerprint: String,
        signature_hex: String,
    ) -> RpcResult<String>;

    /// Authorise payment for a validated milestone.
    ///
    /// Requires the milestone to be in `Validated`. `ceremony_id` links the
    /// authorisation to the two-man-rule ceremony that produced it. Returns
    /// the submitted extrinsic hash; inclusion is not awaited.
    ///
    /// This records an *authorisation*, not a settlement — money movement
    /// remains with `fiat-bridge`.
    ///
    /// `signature_hex` signs `caller_auth::transparence_message(genesis, 0x02,
    /// milestone_id, ceremony_id as u64 LE)`.
    #[method(name = "transparence_recordPaymentAuthorized")]
    async fn record_payment_authorized(
        &self,
        milestone_id: u64,
        ceremony_id: u64,
        signer_fingerprint: String,
        signature_hex: String,
    ) -> RpcResult<String>;
}

pub struct TransparenceRpc<C, P, Block> {
    client: Arc<C>,
    pool: Arc<P>,
    keystore: KeystorePtr,
    callers: Arc<super::caller_auth::CallerAllowlist>,
    _phantom: std::marker::PhantomData<Block>,
}

impl<C, P, Block> TransparenceRpc<C, P, Block>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block>,
{
    pub fn new(
        client: Arc<C>,
        pool: Arc<P>,
        keystore: KeystorePtr,
        callers: Arc<super::caller_auth::CallerAllowlist>,
    ) -> Self {
        Self {
            client,
            pool,
            keystore,
            callers,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<C, P, Block> TransparenceRpc<C, P, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    C::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::Core<Block>
        + substrate_frame_rpc_system::AccountNonceApi<Block, AccountId32, u32>
        + frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId32, u32>,
    P: TransactionPool<Block = Block> + 'static,
{
    /// Sign an arbitrary runtime call with the `trsp` keystore key and submit
    /// it. Factored out because both methods differ only in the call they
    /// build — the envelope, nonce, era and signature handling are identical
    /// to `notarial_rpc::submit_notarization`.
    /// Refuse unless an allowlisted key signed this exact request.
    fn authorise(
        &self,
        rpc_method: &str,
        method: u8,
        milestone_id: u64,
        arg: &[u8],
        signer_fingerprint: &str,
        signature_hex: &str,
    ) -> RpcResult<()> {
        let signature = hex::decode(signature_hex.trim_start_matches("0x")).map_err(|e| {
            ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                format!("Invalid signature hex: {e}"),
                None::<()>,
            )
        })?;
        let genesis = self.client.info().genesis_hash;
        let message = super::caller_auth::transparence_message(
            genesis.as_ref(),
            method,
            milestone_id,
            arg,
        );
        self.callers.check(rpc_method, signer_fingerprint, &message, &signature)
    }

    async fn sign_and_submit(
        &self,
        call: quantumharmony_runtime::RuntimeCall,
        what: &str,
    ) -> RpcResult<String> {
        // --- Resolve the Transparence writer key (secret never leaves keystore)
        let writer_pub = self
            .keystore
            .sphincs_public_keys(TRANSPARENCE_KEY_TYPE)
            .into_iter()
            .next()
            .ok_or_else(|| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    "No Transparence writer key in keystore — insert one with key type 'trsp' via author_insertKey",
                    None::<()>,
                )
            })?;

        use sp_runtime::MultiSigner;
        let signer_account = MultiSigner::from(writer_pub.clone()).into_account();

        // --- Nonce + runtime metadata for the writer account -------------------
        let best_hash = self.client.info().best_hash;
        let nonce = self
            .client
            .runtime_api()
            .account_nonce(best_hash, signer_account.clone())
            .map_err(|e| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("Failed to get nonce: {e}"),
                    None::<()>,
                )
            })?;
        let genesis_hash = sp_core::H256::from_slice(self.client.info().genesis_hash.as_ref());
        let runtime_version = self.client.runtime_api().version(best_hash).map_err(|e| {
            ErrorObject::owned(
                ErrorCode::InternalError.code(),
                format!("Failed to get runtime version: {e}"),
                None::<()>,
            )
        })?;

        let extra: quantumharmony_runtime::SignedExtra = (
            frame_system::CheckNonZeroSender::<quantumharmony_runtime::Runtime>::new(),
            frame_system::CheckSpecVersion::<quantumharmony_runtime::Runtime>::new(),
            frame_system::CheckTxVersion::<quantumharmony_runtime::Runtime>::new(),
            frame_system::CheckGenesis::<quantumharmony_runtime::Runtime>::new(),
            frame_system::CheckEra::<quantumharmony_runtime::Runtime>::from(Era::Immortal),
            frame_system::CheckNonce::<quantumharmony_runtime::Runtime>::from(nonce),
            frame_system::CheckWeight::<quantumharmony_runtime::Runtime>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<quantumharmony_runtime::Runtime>::from(0),
        );

        use quantumharmony_runtime::SignedPayload;
        let raw_payload = SignedPayload::from_raw(
            call.clone(),
            extra.clone(),
            (
                (),
                runtime_version.spec_version,
                runtime_version.transaction_version,
                genesis_hash,
                genesis_hash,
                (),
                (),
                (),
            ),
        );

        // --- Sign the envelope with the writer key from the keystore -----------
        let signature = raw_payload
            .using_encoded(|payload| {
                self.keystore
                    .sphincs_sign(TRANSPARENCE_KEY_TYPE, &writer_pub, payload)
            })
            .map_err(|e| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("keystore sign failed: {e:?}"),
                    None::<()>,
                )
            })?
            .ok_or_else(|| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    "Transparence writer key has no usable secret in keystore",
                    None::<()>,
                )
            })?;
        let sig_with_pub = SignatureWithPublic::new(signature, writer_pub);
        let sphincs_signature = MultiSignature::SphincsPlus(sig_with_pub);

        // --- Build + submit the extrinsic --------------------------------------
        use quantumharmony_runtime::UncheckedExtrinsic;
        let extrinsic = UncheckedExtrinsic::new_signed(
            call,
            sp_runtime::MultiAddress::Id(signer_account),
            sphincs_signature,
            extra,
        );

        let encoded_extrinsic = extrinsic.encode();
        let block_extrinsic =
            Block::Extrinsic::decode(&mut &encoded_extrinsic[..]).map_err(|e| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("Failed to decode extrinsic: {e}"),
                    None::<()>,
                )
            })?;

        let tx_hash = self
            .pool
            .submit_one(best_hash, TransactionSource::Local, block_extrinsic)
            .await
            .map_err(|e| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("Failed to submit: {e}"),
                    None::<()>,
                )
            })?;

        log::info!("✅ Transparence {what} submitted: {:?}", tx_hash);
        Ok(format!("{:?}", tx_hash))
    }
}

#[async_trait]
impl<C, P, Block> TransparenceApiServer<Block::Hash> for TransparenceRpc<C, P, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    C::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::Core<Block>
        + substrate_frame_rpc_system::AccountNonceApi<Block, AccountId32, u32>
        + frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId32, u32>,
    P: TransactionPool<Block = Block> + 'static,
{
    async fn record_validation_result(
        &self,
        milestone_id: u64,
        passed: bool,
        signer_fingerprint: String,
        signature_hex: String,
    ) -> RpcResult<String> {
        self.authorise("transparence_recordValidationResult", 0x01, milestone_id, &[passed as u8], &signer_fingerprint, &signature_hex)?;

        log::info!(
            "📋 Transparence RPC: recordValidationResult(milestone={milestone_id}, passed={passed})"
        );

        use quantumharmony_runtime::RuntimeCall;
        let call = RuntimeCall::TransparenceDeliverables(
            pallet_transparence_deliverables::Call::record_validation_result {
                milestone_id,
                passed,
            },
        );

        self.sign_and_submit(call, "recordValidationResult").await
    }

    async fn record_payment_authorized(
        &self,
        milestone_id: u64,
        ceremony_id: u64,
        signer_fingerprint: String,
        signature_hex: String,
    ) -> RpcResult<String> {
        self.authorise(
            "transparence_recordPaymentAuthorized",
            0x02,
            milestone_id,
            &ceremony_id.to_le_bytes(),
            &signer_fingerprint,
            &signature_hex,
        )?;

        log::info!(
            "💳 Transparence RPC: recordPaymentAuthorized(milestone={milestone_id}, ceremony={ceremony_id})"
        );

        use quantumharmony_runtime::RuntimeCall;
        let call = RuntimeCall::TransparenceDeliverables(
            pallet_transparence_deliverables::Call::record_payment_authorized {
                milestone_id,
                ceremony_id,
            },
        );

        self.sign_and_submit(call, "recordPaymentAuthorized").await
    }
}
