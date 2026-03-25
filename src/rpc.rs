use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::process::Command;

/// Wrapper around bitcoin-cli subprocess calls.
pub struct BitcoinCli {
    cmd_parts: Vec<String>,
}

impl BitcoinCli {
    pub fn new(cli_str: &str) -> Self {
        Self {
            cmd_parts: cli_str.split_whitespace().map(String::from).collect(),
        }
    }

    /// Run a bitcoin-cli command and return raw stdout.
    pub fn call(&self, args: &[&str]) -> Result<String> {
        let mut cmd = Command::new(&self.cmd_parts[0]);
        for part in &self.cmd_parts[1..] {
            cmd.arg(part);
        }
        for arg in args {
            cmd.arg(arg);
        }

        log::debug!("bitcoin-cli: {:?} {:?}", self.cmd_parts, args);

        let output = cmd.output().context("Failed to execute bitcoin-cli")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("bitcoin-cli failed: {}", stderr.trim()));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Run a bitcoin-cli command and parse output as JSON.
    pub fn call_json(&self, args: &[&str]) -> Result<Value> {
        let raw = self.call(args)?;
        serde_json::from_str(&raw).context("Failed to parse bitcoin-cli JSON output")
    }

    /// List unspent outputs from a wallet.
    pub fn list_unspent(&self, wallet: &str) -> Result<Vec<Value>> {
        let val = self.call_json(&[&format!("-rpcwallet={}", wallet), "listunspent"])?;
        val.as_array()
            .cloned()
            .ok_or_else(|| anyhow!("listunspent did not return array"))
    }

    /// Lock a UTXO to prevent double-claiming.
    pub fn lock_unspent(&self, wallet: &str, txid: &str, vout: u32) -> Result<()> {
        let lock_arg = format!(r#"[{{"txid":"{}","vout":{}}}]"#, txid, vout);
        self.call(&[
            &format!("-rpcwallet={}", wallet),
            "lockunspent",
            "false",
            &lock_arg,
        ])?;
        Ok(())
    }

    /// Unlock all locked UTXOs (clears stale locks from prior sessions).
    pub fn unlock_all(&self, wallet: &str) -> Result<()> {
        self.call(&[&format!("-rpcwallet={}", wallet), "lockunspent", "true"])?;
        Ok(())
    }

    /// Decode a script to get its address.
    pub fn decode_script(&self, spk_hex: &str) -> Result<Value> {
        self.call_json(&["decodescript", spk_hex])
    }

    /// Get descriptor info for an address.
    pub fn get_descriptor_info(&self, addr: &str) -> Result<Value> {
        self.call_json(&["getdescriptorinfo", &format!("addr({})", addr)])
    }

    /// Create a watch-only wallet.
    pub fn create_wallet(&self, name: &str) -> Result<()> {
        self.call(&[
            "-named",
            "createwallet",
            &format!("wallet_name={}", name),
            "disable_private_keys=true",
            "descriptors=true",
            "load_on_startup=true",
        ])?;
        Ok(())
    }

    /// Import descriptors into a wallet.
    pub fn import_descriptors(&self, wallet: &str, descriptors: &Value) -> Result<()> {
        let desc_str = serde_json::to_string(descriptors)?;
        self.call(&[
            &format!("-rpcwallet={}", wallet),
            "importdescriptors",
            &desc_str,
        ])?;
        Ok(())
    }

    /// Send raw transaction via local node.
    pub fn send_raw_transaction(&self, tx_hex: &str) -> Result<String> {
        self.call(&["sendrawtransaction", tx_hex])
    }
}
