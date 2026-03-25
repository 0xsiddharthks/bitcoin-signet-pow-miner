use anyhow::{anyhow, Result};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::locktime::absolute::LockTime;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use std::str::FromStr;

use crate::config::{FaucetScript, FAUCET_SCRIPTS, IPK_HEX};
use crate::grinder::{self, GrindResult};

/// Taproot info for a faucet address.
pub struct TapInfo {
    pub script_pubkey: ScriptBuf,
    pub tap_script: ScriptBuf,
    pub control_block: ControlBlock,
    pub faucet: &'static FaucetScript,
}

/// Build taproot info for all faucet scripts.
pub fn build_tap_info() -> Result<Vec<TapInfo>> {
    let secp = Secp256k1::new();
    let ipk_bytes = hex::decode(IPK_HEX)?;
    let internal_key = XOnlyPublicKey::from_slice(&ipk_bytes)?;

    let mut infos = Vec::new();

    for faucet in FAUCET_SCRIPTS {
        let script_bytes = hex::decode(faucet.script_hex)?;
        let tap_script = ScriptBuf::from_bytes(script_bytes);

        let builder = TaprootBuilder::new().add_leaf(0, tap_script.clone())?;

        let spend_info = builder
            .finalize(&secp, internal_key)
            .map_err(|e| anyhow!("Taproot finalize failed: {:?}", e))?;

        let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

        let control_block = spend_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow!("Failed to get control block"))?;

        infos.push(TapInfo {
            script_pubkey,
            tap_script,
            control_block,
            faucet,
        });
    }

    Ok(infos)
}

/// A scored UTXO candidate for claiming.
pub struct CoinCandidate {
    pub txid_str: String,
    pub vout: u32,
    pub amount_sat: u64,
    #[allow(dead_code)]
    pub confirmations: u32,
    pub difficulty: u32,
    pub score: f64,
    pub tap_info_idx: usize,
}

/// Score and rank available UTXOs.
pub fn score_utxos(
    utxos: &[serde_json::Value],
    tap_infos: &[TapInfo],
    max_difficulty: u32,
) -> Result<Vec<CoinCandidate>> {
    let mut scored = Vec::new();
    let mut found_any = false;
    let mut easiest: u32 = 99;

    for utxo in utxos {
        let spk = utxo["scriptPubKey"].as_str().unwrap_or("");

        // Find which faucet script this UTXO belongs to
        let tap_idx = tap_infos
            .iter()
            .position(|ti| ti.script_pubkey.to_hex_string() == spk);

        let tap_idx = match tap_idx {
            Some(idx) => idx,
            None => continue, // not a faucet UTXO
        };

        found_any = true;
        let faucet = tap_infos[tap_idx].faucet;

        let confirmations = utxo["confirmations"].as_u64().unwrap_or(0) as u32;
        let amount_btc = utxo["amount"].as_f64().unwrap_or(0.0);
        let amount_sat = (amount_btc * 1e8).round() as u64;

        let conf_scaled = confirmations / faucet.delay;
        let difficulty = faucet.max_diff.saturating_sub(conf_scaled).max(faucet.min_diff);
        easiest = easiest.min(difficulty);

        if difficulty > max_difficulty {
            continue;
        }

        let score =
            (amount_btc).log2() - difficulty as f64 + rand::random::<f64>();

        scored.push(CoinCandidate {
            txid_str: utxo["txid"].as_str().unwrap_or("").to_string(),
            vout: utxo["vout"].as_u64().unwrap_or(0) as u32,
            amount_sat,
            confirmations,
            difficulty,
            score,
            tap_info_idx: tap_idx,
        });
    }

    if !found_any {
        return Err(anyhow!("Faucet is empty"));
    }
    if scored.is_empty() {
        return Err(anyhow!(
            "Faucet is too difficult (min difficulty {})",
            easiest
        ));
    }

    scored.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
    Ok(scored)
}

/// Build, sign, grind, and complete a claim transaction.
///
/// Returns (raw_tx_bytes, txid_bytes).
pub fn build_claim_tx(
    candidate: &CoinCandidate,
    tap_info: &TapInfo,
    dest_script: &ScriptBuf,
    feerate: u64,
    num_threads: usize,
) -> Result<(Vec<u8>, [u8; 32])> {
    let faucet = tap_info.faucet;
    let difficulty = candidate.difficulty;
    let inv_diff = faucet.max_diff - difficulty;
    let csv = inv_diff * faucet.delay;
    let amount_sat = candidate.amount_sat;

    let txid = Txid::from_str(&candidate.txid_str)?;

    // Build transaction skeleton
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid,
                vout: candidate.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(csv),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey: dest_script.clone(),
        }],
    };

    // Compute fee from weight
    let weight_before = tx.weight().to_wu();
    let fee =
        ((weight_before + faucet.extra_weight) as f64 / 4.0 * feerate as f64).ceil() as u64;

    if amount_sat <= fee + 10000 {
        return Err(anyhow!(
            "Fee too large ({} sats), remaining too small",
            fee
        ));
    }
    tx.output[0].value = Amount::from_sat(amount_sat - fee);

    // Sign with private key = 1
    let secp = Secp256k1::new();
    let mut key_bytes = [0u8; 32];
    key_bytes[31] = 1;
    let secret_key = SecretKey::from_slice(&key_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_pubkey, _parity) = keypair.x_only_public_key();

    // Compute sighash
    let prevouts = [TxOut {
        value: Amount::from_sat(amount_sat),
        script_pubkey: tap_info.script_pubkey.clone(),
    }];
    let leaf_hash = TapLeafHash::from_script(&tap_info.tap_script, LeafVersion::TapScript);

    let sighash = SighashCache::new(&tx).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::Default,
    )?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let sig_bytes = signature.serialize();

    // Build the 80-byte fake block header for grinding
    let nbits = build_nbits(difficulty);

    let mut header = [0u8; 80];
    header[0] = 0x03; // version byte (fixed)
    // bytes 1-3: version prefix (will be ground)
    header[4..68].copy_from_slice(&sig_bytes); // signature as prevhash+merkle
    header[68] = 0x0b; // time byte (fixed)
    // bytes 69-71: time upper bytes (zero, will be ground)
    header[72..76].copy_from_slice(&nbits);
    // bytes 76-79: nonce (will be ground)

    log::info!(
        "Grinding difficulty {} for {:.8} BTC (txid: {}:{})",
        difficulty,
        amount_sat as f64 / 1e8,
        candidate.txid_str,
        candidate.vout,
    );

    // PARALLEL GRIND — this is where all cores work together
    let grind_result = grinder::grind_parallel(header, difficulty, num_threads)
        .ok_or_else(|| anyhow!("Grind failed — no solution found"))?;

    let GrindResult {
        header: ground,
        hash: hashed,
    } = grind_result;

    // Verify grind didn't change fixed bytes
    if ground[0] != 0x03 || ground[68] != 0x0b || ground[4..68] != sig_bytes {
        return Err(anyhow!("Grind corrupted fixed header bytes"));
    }

    // Extract witness components
    let prefix = &ground[1..4]; // 3 bytes
    let suffix = &ground[69..80]; // 11 bytes

    let n = (32 - difficulty / 8 - 1) as usize;
    let h_a = &hashed[n..n + 1]; // 1 byte (last non-zero byte)
    let h_b = &hashed[..n]; // n bytes (core hash part)

    // Build witness stack
    let mut witness = Witness::new();
    witness.push(sig_bytes); // signature (64 bytes)
    witness.push(xonly_pubkey.serialize()); // pubkey (32 bytes)
    witness.push(prefix); // nonce prefix (3 bytes)
    witness.push(suffix); // nonce suffix (11 bytes)
    witness.push(h_b); // hash core part
    witness.push(h_a); // last non-zero byte
    witness.push([difficulty as u8]); // difficulty
    witness.push(tap_info.tap_script.as_bytes()); // tapscript
    witness.push(tap_info.control_block.serialize()); // control block

    tx.input[0].witness = witness;

    // Serialize and compute txid
    let raw_tx = serialize(&tx);

    // Bitcoin txid = double SHA256 of non-witness serialization, reversed
    // For P2P INV, we need the hash in internal byte order
    // The tx.compute_txid() returns it in display order (reversed),
    // but for P2P we need the raw hash256 of the non-witness serialization.
    // Actually, bitcoin's Txid stores in internal order, and to_byte_array()
    // gives the internal representation. Let me compute it directly.
    let tx_no_witness = serialize_no_witness(&tx);
    let inv_hash = grinder::double_sha256(&tx_no_witness);

    Ok((raw_tx, inv_hash))
}

/// Serialize a transaction without witness data (for txid computation / INV messages).
fn serialize_no_witness(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::new();

    // Version
    buf.extend_from_slice(&tx.version.0.to_le_bytes());

    // Input count (varint)
    push_varint(&mut buf, tx.input.len() as u64);

    for input in &tx.input {
        // Previous output
        buf.extend_from_slice(&input.previous_output.txid.to_byte_array());
        buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        // Script sig
        push_varint(&mut buf, input.script_sig.len() as u64);
        buf.extend_from_slice(input.script_sig.as_bytes());
        // Sequence
        buf.extend_from_slice(&input.sequence.0.to_le_bytes());
    }

    // Output count (varint)
    push_varint(&mut buf, tx.output.len() as u64);

    for output in &tx.output {
        buf.extend_from_slice(&output.value.to_sat().to_le_bytes());
        push_varint(&mut buf, output.script_pubkey.len() as u64);
        buf.extend_from_slice(output.script_pubkey.as_bytes());
    }

    // Locktime
    buf.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());

    buf
}

fn push_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Build nbits from difficulty (matches Python encoding).
fn build_nbits(difficulty: u32) -> [u8; 4] {
    let exponent = (280 - difficulty) / 8;
    let coefficient = 1u32 << ((280 - difficulty) % 8);
    // Pack as LE u32: coefficient in bytes 0-2 (LE), exponent in byte 3
    let compact = (exponent << 24) | coefficient;
    compact.to_le_bytes()
}

/// Parse a destination address string to ScriptBuf.
pub fn parse_address(addr: &str) -> Result<ScriptBuf> {
    use bitcoin::Address;
    let address: Address<bitcoin::address::NetworkUnchecked> = addr.parse()?;
    // Accept any network (signet uses tb1 prefix like testnet)
    let address = address.assume_checked();
    Ok(address.script_pubkey())
}
