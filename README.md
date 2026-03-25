# bitcoin-signet-pow-miner

High-performance Rust implementation of the [PoW-based Signet faucet](https://delvingbitcoin.org/t/proof-of-work-based-signet-faucet/937) miner.

Reimplementation of [ajtowns/powcoins](https://github.com/ajtowns/powcoins) in Rust with **native multi-threaded PoW grinding** — all CPU cores work together on each coin, rather than running separate single-threaded processes.

## Features

- **Parallel grinding**: All CPU cores grind the same coin simultaneously for faster solutions
- **Native SHA256**: No subprocess overhead (`bitcoin-util grind` not needed)
- **Continuous mode**: `--continuous` flag for hands-off operation
- **P2P relay**: Built-in relay to Inquisition nodes (no local OP_CAT support needed)
- **Single binary**: No Python dependencies

## Prerequisites

- **Bitcoin Core** (v25+) running a signet node with `server=1`
- **bitcoin-cli** in your PATH
- A signet wallet for receiving coins

## Quick Start

```bash
# Build (release mode for optimal grinding performance)
cargo build --release

# 1. Setup the watch-only wallet to track faucet addresses
./target/release/bitcoin-signet-pow-miner setup-wallet

# 2. Claim a single coin
./target/release/bitcoin-signet-pow-miner claim \
  --relay-peer=inquisition.bitcoin-signet.net \
  --max-difficulty=30 \
  --feerate=1 \
  YOUR_SIGNET_ADDRESS

# 3. Run continuously (recommended)
./target/release/bitcoin-signet-pow-miner claim \
  --relay-peer=inquisition.bitcoin-signet.net \
  --max-difficulty=35 \
  --feerate=1 \
  --workers=12 \
  --continuous \
  YOUR_SIGNET_ADDRESS
```

## CLI Reference

```
bitcoin-signet-pow-miner [OPTIONS] <COMMAND>

Commands:
  setup-wallet  Setup watch-only wallet to track PoW faucet addresses
  claim         Claim coins from the PoW faucet

Global Options:
  --debug       Print debug logging
  --quiet       Only print warnings/errors

Claim Options:
  --wallet <NAME>          Watch-only wallet name [default: powcoins]
  --cli <CMD>              bitcoin-cli command [default: "bitcoin-cli -signet"]
  --relay-peer <HOST>      Peer for OP_CAT tx relay (e.g. inquisition.bitcoin-signet.net)
  --max-difficulty <N>     Max difficulty to attempt [default: 26]
  --feerate <N>            Fee rate in sats/vB [default: 1]
  --workers <N>            CPU threads for grinding [default: num_cpus - 4]
  --continuous             Run continuously in a loop
```

## How It Works

Bitcoin Signet block producers fund special faucet addresses every block. These addresses are locked with an OP_CAT script that requires proof-of-work to claim:

1. **Scan**: List unspent faucet coins and pick the best one (highest value / lowest difficulty)
2. **Sign**: Create a Schnorr signature committing to your destination address
3. **Grind**: Find a nonce such that `double_sha256(nonce_prefix || signature || nonce_suffix)` meets the difficulty target — this is the CPU-intensive step, parallelized across all cores
4. **Relay**: Send the claiming transaction to an Inquisition node via P2P

Difficulty decreases as coins age (more block confirmations), so patience is rewarded with easier claims.

## Performance

Tested on Apple M4 Max (16 cores, 12 grinding threads):

| Difficulty | Expected Hashes | Approx Time (12 threads) |
|-----------|----------------|-------------------------|
| 26        | ~67M           | < 1s                    |
| 28        | ~268M          | ~3s                     |
| 30        | ~1B            | ~12s                    |
| 32        | ~4.3B          | ~60-120s                |
| 33        | ~8.6B          | ~30-200s                |
| 35        | ~34B           | ~5-15min                |

Times vary due to the probabilistic nature of PoW.

## Architecture

```
src/
  main.rs      CLI, orchestration, continuous mode
  config.rs    Faucet script definitions and constants
  rpc.rs       bitcoin-cli subprocess wrapper
  grinder.rs   Multi-threaded parallel PoW grinding engine
  builder.rs   Transaction construction, signing, witness assembly
  relay.rs     Bitcoin P2P protocol relay client
```

## License

MIT
