use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Double SHA256 (hash256) — matches Python's hash256 / Bitcoin's hash function.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(&first).into()
}

/// Check if a hash meets the PoW difficulty target.
///
/// The target is: coefficient * 2^(8*(exponent-3))
/// where exponent = (280-difficulty)/8, coefficient = 1 << ((280-difficulty)%8).
///
/// In practice this means checking that certain trailing bytes of the hash
/// (when interpreted as a LE uint256) are zero.
fn check_pow(hash: &[u8; 32], byte_pos: usize, threshold: u8) -> bool {
    // All bytes above byte_pos must be zero
    for i in (byte_pos + 1)..32 {
        if hash[i] != 0 {
            return false;
        }
    }
    // The byte at byte_pos must be less than threshold
    hash[byte_pos] < threshold
}

/// Result of a successful grind.
pub struct GrindResult {
    pub header: [u8; 80],
    pub hash: [u8; 32],
}

/// Grind a block header in parallel across multiple threads.
///
/// Each thread gets a unique byte[1] value and iterates over bytes[2,3] (outer)
/// and bytes[76-79] (nonce, inner). This gives each thread 2^48 attempts,
/// more than enough for any practical difficulty.
///
/// Returns the solved header and its hash, or None if aborted.
pub fn grind_parallel(
    header_template: [u8; 80],
    difficulty: u32,
    num_threads: usize,
) -> Option<GrindResult> {
    // Precompute check parameters
    let byte_pos = ((280 - difficulty) / 8 - 3) as usize;
    let threshold = 1u8 << ((280 - difficulty) % 8);

    let found = Arc::new(AtomicBool::new(false));
    let result: Arc<Mutex<Option<GrindResult>>> = Arc::new(Mutex::new(None));

    std::thread::scope(|s| {
        for t in 0..num_threads {
            let found = found.clone();
            let result = result.clone();

            s.spawn(move || {
                let mut header = header_template;
                header[1] = t as u8;

                for extra in 0u32.. {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }

                    header[2] = (extra >> 8) as u8;
                    header[3] = extra as u8;

                    for nonce in 0u32..=u32::MAX {
                        // Check abort flag every ~1M iterations
                        if nonce & 0xFFFFF == 0 && found.load(Ordering::Relaxed) {
                            return;
                        }

                        header[76..80].copy_from_slice(&nonce.to_le_bytes());

                        let hash = double_sha256(&header);

                        if check_pow(&hash, byte_pos, threshold) {
                            found.store(true, Ordering::Relaxed);
                            let mut guard = result.lock().unwrap();
                            if guard.is_none() {
                                *guard = Some(GrindResult { header, hash });
                            }
                            return;
                        }
                    }
                }
            });
        }
    });

    Arc::try_unwrap(result).ok()?.into_inner().ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_sha256() {
        // SHA256d of empty string
        let hash = double_sha256(b"");
        assert_eq!(
            hex::encode(hash),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn test_check_pow_easy() {
        // Difficulty 16: byte_pos=30, threshold=1 → hash[30]=0, hash[31]=0
        let mut hash = [0u8; 32];
        hash[0] = 0xFF; // non-zero early byte is fine
        assert!(check_pow(&hash, 30, 1));

        hash[31] = 1; // high byte non-zero → fail
        assert!(!check_pow(&hash, 30, 1));
    }
}
