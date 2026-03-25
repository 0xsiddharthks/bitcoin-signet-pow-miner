use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Signet P2P network magic bytes.
const SIGNET_MAGIC: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40];

const MSG_TX: u32 = 1;
const PROTOCOL_VERSION: u32 = 70016;

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(&first).into()
}

/// Build a P2P message with header.
fn build_message(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(24 + payload.len());

    // Magic
    msg.extend_from_slice(&SIGNET_MAGIC);

    // Command (12 bytes, null-padded)
    let mut cmd = [0u8; 12];
    let cmd_bytes = command.as_bytes();
    cmd[..cmd_bytes.len()].copy_from_slice(cmd_bytes);
    msg.extend_from_slice(&cmd);

    // Payload length
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());

    // Checksum (first 4 bytes of double SHA256 of payload)
    let checksum = double_sha256(payload);
    msg.extend_from_slice(&checksum[..4]);

    // Payload
    msg.extend_from_slice(payload);

    msg
}

/// Build a VERSION message payload.
fn build_version_payload(remote_ip: &[u8; 4], remote_port: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(86);

    // Version
    payload.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    // Services (none)
    payload.extend_from_slice(&0u64.to_le_bytes());
    // Timestamp
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    payload.extend_from_slice(&ts.to_le_bytes());

    // addr_recv: services(8) + ipv6-mapped-ipv4(16) + port(2)
    payload.extend_from_slice(&0u64.to_le_bytes()); // services
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]); // ipv4-in-ipv6
    payload.extend_from_slice(remote_ip);
    payload.extend_from_slice(&remote_port.to_be_bytes());

    // addr_from: services(8) + ip(16) + port(2)
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&[0u8; 16]); // 0.0.0.0
    payload.extend_from_slice(&0u16.to_be_bytes());

    // Nonce
    let nonce: u64 = rand::random();
    payload.extend_from_slice(&nonce.to_le_bytes());

    // User agent (varint length + string)
    let ua = b"/signet-pow-miner:0.1.0/";
    payload.push(ua.len() as u8);
    payload.extend_from_slice(ua);

    // Start height
    payload.extend_from_slice(&0u32.to_le_bytes());

    // Relay
    payload.push(0);

    payload
}

/// Build an INV message payload for a single transaction.
fn build_inv_payload(txid: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(37);
    payload.push(1); // count = 1 (varint)
    payload.extend_from_slice(&MSG_TX.to_le_bytes()); // type = MSG_TX
    payload.extend_from_slice(txid); // hash (internal byte order)
    payload
}

/// Build a TX message payload (just the raw serialized transaction).
fn build_tx_payload(raw_tx: &[u8]) -> Vec<u8> {
    raw_tx.to_vec()
}

/// Build a PING message payload.
fn build_ping_payload() -> Vec<u8> {
    let nonce: u64 = rand::random();
    nonce.to_le_bytes().to_vec()
}

/// Read a complete P2P message from the stream.
/// Returns (command, payload).
fn read_message(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut header = [0u8; 24];
    stream
        .read_exact(&mut header)
        .context("Failed to read P2P message header")?;

    // Verify magic
    if header[0..4] != SIGNET_MAGIC {
        return Err(anyhow!("Bad magic bytes"));
    }

    // Parse command
    let cmd_bytes = &header[4..16];
    let cmd_end = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let command = String::from_utf8_lossy(&cmd_bytes[..cmd_end]).to_string();

    // Parse payload length
    let payload_len = u32::from_le_bytes(header[16..20].try_into()?) as usize;

    // Read payload
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .context("Failed to read P2P message payload")?;
    }

    Ok((command, payload))
}

/// Wait for a specific message type, ignoring others.
/// Returns the payload of the matched message.
fn wait_for_message(stream: &mut TcpStream, target_cmd: &str) -> Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            return Err(anyhow!("Timeout waiting for {}", target_cmd));
        }
        let (cmd, payload) = read_message(stream)?;
        log::debug!("P2P received: {} ({} bytes)", cmd, payload.len());

        // Auto-respond to ping
        if cmd == "ping" && payload.len() == 8 {
            let pong = build_message("pong", &payload);
            stream.write_all(&pong)?;
        }

        if cmd == target_cmd {
            return Ok(payload);
        }

        // Ignore unknown messages (like "sendtemplate" from Inquisition)
    }
}

/// Relay a raw transaction to a signet peer via P2P.
///
/// Performs: VERSION→VERACK handshake, PING/PONG, INV→GETDATA→TX.
pub fn relay_transaction(host: &str, port: u16, txid: &[u8; 32], raw_tx: &[u8]) -> Result<()> {
    // Resolve hostname
    let addr = format!("{}:{}", host, port);

    // Resolve hostname, preferring IPv4
    use std::net::ToSocketAddrs;
    let sock_addr = format!("{}:{}", host, port)
        .to_socket_addrs()
        .context("DNS resolution failed")?
        .find(|s| s.is_ipv4())
        .or_else(|| {
            format!("{}:{}", host, port)
                .to_socket_addrs()
                .ok()?
                .next()
        })
        .ok_or_else(|| anyhow!("Could not resolve {}", host))?;

    let ip4 = match sock_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(_) => [0u8; 4], // fallback for VERSION message
    };

    log::debug!("Connecting to {} ({})", host, sock_addr);
    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(10))
        .context("Failed to connect to relay peer")?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    // Send VERSION
    let version_payload = build_version_payload(&ip4, port);
    let version_msg = build_message("version", &version_payload);
    stream.write_all(&version_msg)?;
    log::debug!("Sent VERSION");

    // Wait for VERSION from peer
    wait_for_message(&mut stream, "version")?;
    log::debug!("Received VERSION");

    // Send VERACK
    let verack = build_message("verack", &[]);
    stream.write_all(&verack)?;
    log::debug!("Sent VERACK");

    // Wait for VERACK
    wait_for_message(&mut stream, "verack")?;
    log::debug!("Received VERACK");

    // PING/PONG to sync
    let ping = build_message("ping", &build_ping_payload());
    stream.write_all(&ping)?;
    wait_for_message(&mut stream, "pong")?;
    log::debug!("PING/PONG sync complete");

    // Send INV
    let inv_payload = build_inv_payload(txid);
    let inv_msg = build_message("inv", &inv_payload);
    stream.write_all(&inv_msg)?;
    log::debug!("Sent INV");

    // Wait for GETDATA
    wait_for_message(&mut stream, "getdata")?;
    log::debug!("Received GETDATA");

    // Send TX
    let tx_payload = build_tx_payload(raw_tx);
    let tx_msg = build_message("tx", &tx_payload);
    stream.write_all(&tx_msg)?;
    log::debug!("Sent TX");

    // Final PING/PONG to ensure delivery
    let ping2 = build_message("ping", &build_ping_payload());
    stream.write_all(&ping2)?;
    let _ = wait_for_message(&mut stream, "pong");

    Ok(())
}
