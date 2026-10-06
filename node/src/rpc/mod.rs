//! A collection of node-specific RPC methods.

use std::sync::Arc;

// Substrate
use sc_client_api::client::BlockchainEvents;
use sc_rpc_api::DenyUnsafe;
use sc_service::TransactionPool;
use sc_transaction_pool_api::TransactionPool as TxPool;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus_aura::sphincs::AuthorityId as AuraId;
use jsonrpsee::RpcModule;
use sp_keystore::KeystorePtr;

// Runtime
use quantumharmony_runtime::{opaque::Block, AccountId, Balance, Nonce};

// Transaction gateway for wallet integration
pub mod transaction_gateway;
use transaction_gateway::{TransactionGateway, TransactionGatewayApiServer};

// Threshold QRNG RPC for real-time device monitoring
pub mod threshold_qrng_rpc;
use threshold_qrng_rpc::{ThresholdQrngRpc, ThresholdQrngApiServer};

// Runtime Segmentation RPC for 512-segment toroidal mesh monitoring
pub mod runtime_segmentation_rpc;
use runtime_segmentation_rpc::{RuntimeSegmentationRpc, RuntimeSegmentationApiServer};
// Re-export the segment routing helper for use by transaction_gateway
pub use runtime_segmentation_rpc::route_and_record_transaction;

// Runtime Upgrade RPC with SPHINCS+ signing
pub mod runtime_upgrade_rpc;
use runtime_upgrade_rpc::{RuntimeUpgradeRpc, RuntimeUpgradeApiServer};

// Chunked Upgrade RPC for large runtime upgrades
pub mod chunked_upgrade_rpc;
use chunked_upgrade_rpc::{ChunkedUpgradeRpc, ChunkedUpgradeApiServer};

// Governance & Rewards RPC for dashboard integration
pub mod governance_rpc;
use governance_rpc::{GovernanceRpc, GovernanceApiServer};

// Notarial RPC for document attestation and verification
pub mod notarial_rpc;
use notarial_rpc::{NotarialRpc, NotarialApiServer};

// Falcon allowlist for RPC methods that sign with a node keystore key
pub mod caller_auth;

// Transparence RPC for milestone validation + payment authorisation
pub mod transparence_rpc;
use transparence_rpc::{TransparenceRpc, TransparenceApiServer};

// Test Upgrade RPC - public endpoint for testing runtime upgrades
// Rate limited, no keys required, dry-run only
pub mod test_upgrade_rpc;
use test_upgrade_rpc::{TestUpgradeRpc, TestUpgradeApiServer};

// Oracle RPC - decentralized CAD price oracle system
pub mod oracle_rpc;
use oracle_rpc::{OracleRpc, OracleApiServer};

// PQC Oracle RPC - Post-Quantum Cryptography oracle with SPHINCS+, QRNG, QKD
pub mod pqc_rpc;
use pqc_rpc::{PqcOracleRpc, PqcOracleApiServer};

// MeshForum RPC - On-chain forum messaging between validators
pub mod mesh_forum_rpc;
use mesh_forum_rpc::{MeshForumRpc, MeshForumApiServer};

// Axiom Attestation RPC - on-chain task attestations for the Axiom AI agent
pub mod axiom_attestation_rpc;
use axiom_attestation_rpc::{AxiomAttestationRpc, AxiomAttestationRpcApiServer};

// BGFL RPC - Blockchain-Governed Federated Learning data plane
// In-memory message bus for FL round configs, client updates, and aggregate results.
// All traffic rides QH's PQ P2P transport (Falcon-1024 + ML-KEM-1024).
pub mod bgfl_rpc;
use bgfl_rpc::{BgflRpc, BgflApiServer};

/// Full client dependencies (governance-only, no Frontier)
pub struct FullDeps<C, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Whether to deny unsafe calls
    pub deny_unsafe: DenyUnsafe,
    /// Keystore for signing transactions (used by MeshForum RPC)
    pub keystore: KeystorePtr,
}

/// Instantiate all Full RPC extensions
pub fn create_full<C, Pool, BE>(
    deps: FullDeps<C, Pool>,
) -> Result<RpcModule<()>, sc_service::Error>
where
    // BE is a type parameter only; no backend instance is needed. It names the
    // backend the client reads storage through, so chunkedUpgrade_status can
    // query the ChunkedUpgrade pallet's storage.
    BE: sc_client_api::Backend<Block> + Send + Sync + 'static,
    C: ProvideRuntimeApi<Block>
        + BlockchainEvents<Block>
        + sc_client_api::StorageProvider<Block, BE>
        + 'static,
    C::Api: sp_block_builder::BlockBuilder<Block>,
    C::Api: sp_consensus_aura::AuraApi<Block, AuraId>,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance>,
    C::Api: quantumharmony_runtime::wallet_api::WalletApi<Block, AccountId, Balance>,
    C::Api: pallet_validator_rewards::runtime_api::ValidatorRewardsApi<Block, AccountId, Balance>,
    C::Api: pallet_mesh_forum::runtime_api::MeshForumApi<Block, AccountId>,
    C::Api: pallet_notarial::runtime_api::NotarialRuntimeApi<Block, AccountId>,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    Pool: TxPool<Block = Block> + 'static,
{
    let mut module = RpcModule::new(());

    // Create transaction gateway instance
    let transaction_gateway = TransactionGateway::new(deps.client.clone(), deps.pool.clone());

    // Merge transaction gateway RPC into module
    module.merge(transaction_gateway.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Transaction Gateway RPC methods registered");

    // Create threshold QRNG RPC instance
    let threshold_qrng_rpc = ThresholdQrngRpc::<Block>::new();

    // Merge threshold QRNG RPC into module
    module.merge(threshold_qrng_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Threshold QRNG RPC methods registered");

    // Create runtime segmentation RPC instance
    let runtime_segmentation_rpc = RuntimeSegmentationRpc::<Block>::new();

    // Merge runtime segmentation RPC into module
    module.merge(runtime_segmentation_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Runtime Segmentation RPC methods registered");

    // Create runtime upgrade RPC instance with SPHINCS+ signing
    let runtime_upgrade_rpc = RuntimeUpgradeRpc::<_, _, Block>::new(deps.client.clone(), deps.pool.clone());

    // Merge runtime upgrade RPC into module
    module.merge(runtime_upgrade_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Runtime Upgrade RPC with SPHINCS+ signing registered");

    // Create chunked upgrade RPC instance for large runtime upgrades
    let chunked_upgrade_rpc = ChunkedUpgradeRpc::<_, _, Block, BE>::new(deps.client.clone(), deps.pool.clone());

    // Merge chunked upgrade RPC into module
    module.merge(chunked_upgrade_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Chunked Upgrade RPC registered (for large runtime upgrades)");

    // Create governance & rewards RPC instance for dashboard integration
    let governance_rpc = GovernanceRpc::<_, _, Block>::new(deps.client.clone(), deps.pool.clone());

    // Merge governance RPC into module
    module.merge(governance_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Governance & Rewards RPC methods registered (quantumharmony_*)");

    // Create notarial RPC instance for document attestation + Transparence anchoring
    let notarial_rpc = NotarialRpc::<_, _, Block>::new(deps.client.clone(), deps.pool.clone(), deps.keystore.clone(), caller_auth::installed());

    // Merge notarial RPC into module
    module.merge(notarial_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Notarial RPC methods registered (notarial_*)");

    // Create Transparence RPC instance for milestone validation + payment
    // authorisation (keystore-signed, key type 'trsp' — no secret over RPC).
    let transparence_rpc = TransparenceRpc::<_, _, Block>::new(deps.client.clone(), deps.pool.clone(), deps.keystore.clone(), caller_auth::installed());

    // Merge Transparence RPC into module
    module.merge(transparence_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Transparence RPC methods registered (transparence_*)");

    // Create test upgrade RPC instance (public, rate-limited, no keys required)
    let test_upgrade_rpc = TestUpgradeRpc::<_, Block>::new(deps.client.clone());

    // Merge test upgrade RPC into module
    module.merge(test_upgrade_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Test Upgrade RPC registered (quantumharmony_testRuntimeUpgrade - PUBLIC, rate-limited)");

    // Create oracle RPC instance for decentralized CAD price feeds
    let oracle_rpc = OracleRpc::<_, Block>::new(deps.client.clone());

    // Merge oracle RPC into module
    module.merge(oracle_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Oracle RPC registered (oracle_* - decentralized CAD price feeds)");

    // Create PQC oracle RPC instance for SPHINCS+, QRNG, QKD operations
    let pqc_oracle_rpc = PqcOracleRpc::<_, Block>::new(deps.client.clone());

    // Merge PQC oracle RPC into module
    module.merge(pqc_oracle_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ PQC Oracle RPC registered (pqc_* - SPHINCS+/QRNG/QKD)");

    // Create MeshForum RPC instance for on-chain forum messaging
    let mesh_forum_rpc = MeshForumRpc::<_, _, Block>::new(deps.client.clone(), deps.pool.clone(), deps.keystore.clone());

    // Merge MeshForum RPC into module
    module.merge(mesh_forum_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ MeshForum RPC registered (forum_* - on-chain validator messaging)");

    // Create Axiom Attestation RPC instance for AI agent task attestations
    let axiom_attestation_rpc = AxiomAttestationRpc::<_, _, Block>::new(deps.client.clone(), deps.pool.clone());

    // Merge Axiom Attestation RPC into module
    module.merge(axiom_attestation_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ Axiom Attestation RPC registered (quantumharmony_submitTaskAttestation)");

    // Create BGFL RPC instance for Federated Learning data plane
    let bgfl_rpc = BgflRpc::<Block>::new();

    // Merge BGFL RPC into module
    module.merge(bgfl_rpc.into_rpc())
        .map_err(|e| sc_service::Error::Application(Box::new(e)))?;

    log::info!("✅ BGFL RPC registered (bgfl_* - Federated Learning data plane)");

    Ok(module)
}
