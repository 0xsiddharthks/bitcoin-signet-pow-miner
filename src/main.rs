mod builder;
mod config;
mod grinder;
mod relay;
mod rpc;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "signet-pow-miner")]
#[command(about = "High-performance parallel PoW miner for Bitcoin Signet faucet coins")]
struct Cli {
    /// Print debug logging
    #[arg(long, global = true)]
    debug: bool,

    /// Only print warnings/errors
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Setup watch-only wallet to track PoW faucet addresses
    SetupWallet {
        /// Wallet name
        #[arg(long, default_value = "powcoins")]
        wallet: String,

        /// bitcoin-cli command
        #[arg(long, default_value = "bitcoin-cli -signet")]
        cli: String,
    },

    /// Claim coins from the PoW faucet
    Claim {
        /// Destination address to receive funds
        address: String,

        /// Wallet name for tracking faucet coins
        #[arg(long, default_value = "powcoins")]
        wallet: String,

        /// bitcoin-cli command
        #[arg(long, default_value = "bitcoin-cli -signet")]
        cli: String,

        /// Peer for OP_CAT transaction relay (e.g. inquisition.bitcoin-signet.net)
        #[arg(long)]
        relay_peer: Option<String>,

        /// Maximum difficulty to attempt (each +1 doubles CPU work)
        #[arg(long, default_value = "26")]
        max_difficulty: u32,

        /// Fee rate in sats/vB (auto-detected if omitted)
        #[arg(long)]
        feerate: Option<u64>,

        /// Number of CPU threads for grinding (default: num_cpus - 4)
        #[arg(long)]
        workers: Option<usize>,

        /// Run continuously, claiming coins in a loop
        #[arg(long)]
        continuous: bool,
    },
}

fn setup_wallet(wallet: &str, cli_str: &str) -> Result<()> {
    let cli = rpc::BitcoinCli::new(cli_str);
    let tap_infos = builder::build_tap_info()?;

    log::info!("Creating watch-only wallet '{}'...", wallet);
    cli.create_wallet(wallet)?;

    let mut descriptors = Vec::new();
    for info in &tap_infos {
        let spk_hex = info.script_pubkey.to_hex_string();
        let decoded = cli.decode_script(&spk_hex)?;
        let addr = decoded["address"]
            .as_str()
            .ok_or_else(|| anyhow!("No address for script"))?;

        log::info!(
            "Faucet address: {} (delay={})",
            addr,
            info.faucet.delay
        );

        let desc_info = cli.get_descriptor_info(addr)?;
        let descriptor = desc_info["descriptor"]
            .as_str()
            .ok_or_else(|| anyhow!("No descriptor"))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let timestamp = now - 600 * 128 * info.faucet.delay as i64;

        descriptors.push(serde_json::json!({
            "desc": descriptor,
            "timestamp": timestamp,
        }));
    }

    let desc_array = serde_json::Value::Array(descriptors);
    cli.import_descriptors(wallet, &desc_array)?;

    log::info!("Wallet '{}' setup complete", wallet);
    Ok(())
}

fn do_claim(
    address: &str,
    wallet: &str,
    cli_str: &str,
    relay_peer: Option<&str>,
    max_difficulty: u32,
    feerate: u64,
    num_threads: usize,
) -> Result<()> {
    let cli = rpc::BitcoinCli::new(cli_str);
    let tap_infos = builder::build_tap_info()?;
    let dest_script = builder::parse_address(address)?;

    // Clear stale locks from prior sessions so all UTXOs are visible
    let _ = cli.unlock_all(wallet);

    // List unspent coins
    let utxos = cli.list_unspent(wallet)?;
    log::debug!("Found {} UTXOs in wallet", utxos.len());

    // Score and pick best coin
    let candidates = builder::score_utxos(&utxos, &tap_infos, max_difficulty)?;
    let best = candidates.last().unwrap(); // highest score is last (sorted ascending)

    // Lock the UTXO
    cli.lock_unspent(wallet, &best.txid_str, best.vout)?;

    // Build, sign, grind, and complete the transaction
    let start = Instant::now();
    let (raw_tx, txid_hash) = builder::build_claim_tx(
        best,
        &tap_infos[best.tap_info_idx],
        &dest_script,
        feerate,
        num_threads,
    )?;
    let elapsed = start.elapsed();

    log::info!(
        "Grind complete in {:.2}s ({} threads)",
        elapsed.as_secs_f64(),
        num_threads
    );

    // Relay or broadcast
    if let Some(peer) = relay_peer {
        let (host, port) = if peer.contains(':') {
            let parts: Vec<&str> = peer.splitn(2, ':').collect();
            (parts[0], parts[1].parse::<u16>().unwrap_or(38333))
        } else {
            (peer, 38333u16)
        };

        relay::relay_transaction(host, port, &txid_hash, &raw_tx)?;
        log::info!("Relayed txid {}", hex::encode(txid_hash.iter().rev().copied().collect::<Vec<_>>()));
    } else {
        let tx_hex = hex::encode(&raw_tx);
        let result = cli.send_raw_transaction(&tx_hex)?;
        log::info!("sendrawtransaction: {}", result);
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.debug {
        "debug"
    } else if cli.quiet {
        "warn"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp(Some(env_logger::TimestampPrecision::Seconds))
        .init();

    match cli.command {
        Commands::SetupWallet { wallet, cli: cli_str } => {
            setup_wallet(&wallet, &cli_str)?;
        }
        Commands::Claim {
            address,
            wallet,
            cli: cli_str,
            relay_peer,
            max_difficulty,
            feerate,
            workers,
            continuous,
        } => {
            let num_threads = workers.unwrap_or_else(|| {
                let cpus = num_cpus::get();
                if cpus > 4 { cpus - 4 } else { 1 }
            });

            let feerate = feerate.unwrap_or(1);

            log::info!(
                "Signet PoW Miner — {} threads, max-diff {}, feerate {} sat/vB",
                num_threads,
                max_difficulty,
                feerate
            );

            if continuous {
                let mut claim_count = 0u32;
                loop {
                    match do_claim(
                        &address,
                        &wallet,
                        &cli_str,
                        relay_peer.as_deref(),
                        max_difficulty,
                        feerate,
                        num_threads,
                    ) {
                        Ok(()) => {
                            claim_count += 1;
                            log::info!(
                                "Claim #{} successful (total: {} claims)",
                                claim_count,
                                claim_count,
                            );
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("too difficult") || msg.contains("empty") {
                                log::warn!("{} — waiting 120s for new blocks...", msg);
                                std::thread::sleep(std::time::Duration::from_secs(120));
                            } else {
                                log::error!("Claim failed: {} — retrying in 10s", msg);
                                std::thread::sleep(std::time::Duration::from_secs(10));
                            }
                        }
                    }
                }
            } else {
                do_claim(
                    &address,
                    &wallet,
                    &cli_str,
                    relay_peer.as_deref(),
                    max_difficulty,
                    feerate,
                    num_threads,
                )?;
            }
        }
    }

    Ok(())
}
