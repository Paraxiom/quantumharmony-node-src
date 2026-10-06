use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use anyhow::{Context, Result, bail};
use jsonrpsee::{
    core::client::ClientT,
    http_client::HttpClientBuilder,
    rpc_params,
};
use serde::{Deserialize, Serialize};

// REMOVED: Hardcoded SPHINCS+ secret keys have been redacted for security.
// Load keys from environment or keystore instead.
mod test_accounts {
    pub fn get_secret(name: &str) -> Option<[u8; 128]> {
        // REMOVED: Load keys from environment or keystore
        panic!(
            "Hardcoded test keys have been removed. Use --secret-key flag with a hex-encoded key, \
             or load keys from a secure keystore. Requested account: '{}'",
            name
        );
    }
}

#[derive(Parser, Debug)]
#[command(name = "runtime-upgrade")]
#[command(about = "Perform a SPHINCS+ signed runtime upgrade on QuantumHarmony", long_about = None)]
struct Args {
    /// HTTP RPC endpoint of the node
    #[arg(short, long, default_value = "http://127.0.0.1:9944")]
    endpoint: String,

    /// Path to the runtime WASM file
    #[arg(short, long)]
    wasm: PathBuf,

    /// Sudo account name (alice, bob, or charlie)
    #[arg(short, long, default_value = "alice")]
    signer: String,

    /// Custom secret key in hex (128 bytes / 256 hex chars)
    /// If not provided, uses the test account key
    #[arg(long)]
    secret_key: Option<String>,

    /// Block time in seconds (for chunk upload timing)
    #[arg(long, default_value = "6")]
    block_time: u64,

    /// Cancel any pending upgrade before starting
    #[arg(long)]
    cancel_pending: bool,

    /// Dry run - only show what would be done
    #[arg(long)]
    dry_run: bool,
}

/// Response from chunkedUpgrade_initiate
#[derive(Debug, Deserialize)]
struct InitiateResult {
    upgrade_id: String,
    chunks_received: u32,
    total_chunks: u32,
    expected_size: u64,
    ready_to_finalize: bool,
}

/// Response from chunkedUpgrade_status
#[derive(Debug, Deserialize)]
struct StatusResult {
    pending: bool,
    upgrade_id: Option<String>,
    chunks_received: Option<u32>,
    total_chunks: Option<u32>,
    expected_size: Option<u64>,
}

/// Response from chunkedUpgrade_uploadChunk
#[derive(Debug, Deserialize)]
struct ChunkResult {
    chunks_received: u32,
    total_chunks: u32,
    ready_to_finalize: bool,
}

const CHUNK_SIZE: usize = 65536; // 64KB chunks

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║     QuantumHarmony Runtime Upgrade Tool (SPHINCS+)         ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Get secret key
    let secret_key = if let Some(ref hex_key) = args.secret_key {
        let hex_clean = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let bytes = hex::decode(hex_clean)
            .context("Invalid hex format for secret key")?;
        if bytes.len() != 128 {
            bail!("Secret key must be 128 bytes (256 hex chars), got {} bytes", bytes.len());
        }
        let mut arr = [0u8; 128];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        test_accounts::get_secret(&args.signer)
            .with_context(|| format!("Unknown signer '{}'. Use alice, bob, charlie, or provide --secret-key", args.signer))?
    };

    let secret_hex = format!("0x{}", hex::encode(&secret_key));
    println!("🔑 Using {} SPHINCS+ secret key ({} bytes)", args.signer, secret_key.len());
    println!();

    // Read WASM file
    println!("📦 Reading WASM file: {:?}", args.wasm);
    let wasm_code = fs::read(&args.wasm)
        .context("Failed to read WASM file")?;
    let wasm_hex = format!("0x{}", hex::encode(&wasm_code));
    let num_chunks = (wasm_code.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;

    println!("   Size: {} bytes ({} KB)", wasm_code.len(), wasm_code.len() / 1024);
    println!("   Chunks: {} ({}KB each)", num_chunks, CHUNK_SIZE / 1024);
    println!();

    // Build HTTP client with longer timeout
    let http_endpoint = if args.endpoint.starts_with("ws://") {
        args.endpoint.replace("ws://", "http://")
    } else if args.endpoint.starts_with("wss://") {
        args.endpoint.replace("wss://", "https://")
    } else {
        args.endpoint.clone()
    };

    println!("🌐 Connecting to: {}", http_endpoint);
    let client = HttpClientBuilder::default()
        .request_timeout(Duration::from_secs(120))
        .build(&http_endpoint)
        .context("Failed to create HTTP client")?;

    // Get current runtime version
    let version: serde_json::Value = client
        .request("state_getRuntimeVersion", rpc_params![])
        .await
        .context("Failed to get runtime version")?;

    let current_version = version["specVersion"].as_u64().unwrap_or(0);
    println!("   Current spec_version: {}", current_version);
    println!();

    if args.dry_run {
        println!("🔍 DRY RUN - No transactions will be submitted");
        println!();
        println!("Would perform:");
        println!("  1. Cancel any pending upgrade");
        println!("  2. Initiate chunked upgrade");
        for i in 0..num_chunks {
            let start = i * CHUNK_SIZE;
            let end = std::cmp::min(start + CHUNK_SIZE, wasm_code.len());
            println!("  {}. Upload chunk {} ({} bytes)", i + 3, i, end - start);
        }
        println!("  {}. Finalize upgrade", num_chunks + 3);
        return Ok(());
    }

    // Cancel any pending upgrade if requested or by default
    if args.cancel_pending {
        println!("🗑️  Cancelling any pending upgrade...");
        let cancel_result: Result<serde_json::Value, _> = client
            .request("chunkedUpgrade_cancel", rpc_params![&secret_hex])
            .await;
        match cancel_result {
            Ok(_) => println!("   Cancelled"),
            Err(e) => println!("   No pending upgrade or cancel failed: {}", e),
        }
        println!();

        // Wait for transaction to clear
        tokio::time::sleep(Duration::from_secs(args.block_time)).await;
    }

    // Check status - may return null if no pending upgrade
    println!("📊 Checking upgrade status...");
    let status: Option<StatusResult> = client
        .request("chunkedUpgrade_status", rpc_params![])
        .await
        .context("Failed to get upgrade status")?;

    match status {
        Some(s) if s.pending => {
            println!("   ⚠️  Pending upgrade detected: {:?}", s.upgrade_id);
            println!("   Use --cancel-pending to cancel it first");
            bail!("Pending upgrade exists");
        }
        Some(_) => println!("   No pending upgrades"),
        None => println!("   No pending upgrades (empty)"),
    }
    println!();

    // Step 1: Initiate
    println!("[1/3] Initiating chunked upgrade...");
    let init_result: InitiateResult = client
        .request("chunkedUpgrade_initiate", rpc_params![&wasm_hex, &secret_hex])
        .await
        .context("Failed to initiate upgrade")?;

    println!("   Upgrade ID: {}", init_result.upgrade_id);
    println!("   Expected chunks: {}", init_result.total_chunks);
    println!();

    // Step 2: Upload chunks
    // IMPORTANT: Wait for the initiate transaction to be included first
    println!("   Waiting for initiate tx to be included...");
    tokio::time::sleep(Duration::from_secs(args.block_time + 2)).await;

    println!("[2/3] Uploading {} chunks...", num_chunks);
    for i in 0..num_chunks {
        let start = i * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, wasm_code.len());
        let chunk = &wasm_code[start..end];
        let chunk_hex = format!("0x{}", hex::encode(chunk));

        // Retry loop for transaction priority issues
        let mut retries = 3;
        let mut success = false;
        while retries > 0 && !success {
            // The RPC returns a transaction hash string, not a ChunkResult struct
            let chunk_result: Result<String, _> = client
                .request("chunkedUpgrade_uploadChunk", rpc_params![i as u32, &chunk_hex, &secret_hex])
                .await;

            match chunk_result {
                Ok(tx_hash) => {
                    println!("   ✓ Chunk {}/{} ({} bytes) - tx: {}",
                        i + 1, num_chunks, chunk.len(), tx_hash);
                    success = true;
                }
                Err(e) => {
                    let err_str = format!("{}", e);
                    if err_str.contains("priority") || err_str.contains("Too low") {
                        retries -= 1;
                        if retries > 0 {
                            println!("   ⚠ Chunk {} priority conflict, waiting and retrying...", i);
                            tokio::time::sleep(Duration::from_secs(args.block_time)).await;
                        } else {
                            println!("   ❌ Chunk {} failed after retries: {}", i, e);
                            bail!("Chunk upload failed after retries");
                        }
                    } else {
                        println!("   ❌ Chunk {} failed: {}", i, e);
                        bail!("Chunk upload failed");
                    }
                }
            }
        }

        // Wait for block inclusion between chunks
        if i < num_chunks - 1 {
            tokio::time::sleep(Duration::from_secs(args.block_time)).await;
        }
    }
    println!();

    // Step 3: Finalize
    println!("[3/3] Finalizing upgrade...");
    let finalize_result: serde_json::Value = client
        .request("chunkedUpgrade_finalize", rpc_params![&secret_hex])
        .await
        .context("Failed to finalize upgrade")?;

    println!("   Transaction submitted: {:?}", finalize_result);
    println!();

    // Wait and verify
    println!("⏳ Waiting for upgrade to take effect...");
    for i in 0..12 {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let new_version: serde_json::Value = client
            .request("state_getRuntimeVersion", rpc_params![])
            .await
            .context("Failed to get runtime version")?;

        let new_spec = new_version["specVersion"].as_u64().unwrap_or(0);

        if new_spec != current_version {
            println!();
            println!("🎉 UPGRADE SUCCESSFUL!");
            println!("   Old version: {}", current_version);
            println!("   New version: {}", new_spec);
            return Ok(());
        }

        println!("   {}s - still at version {}", (i + 1) * 10, new_spec);
    }

    println!();
    println!("⚠️  Timeout - upgrade may still be processing");
    println!("   Check node logs for errors");
    Ok(())
}
