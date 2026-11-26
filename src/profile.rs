//! Workload size bucketing, startup micro-calibration, and online EMA telemetry.

use crate::crypto::{AeadCipher, Algorithm, CryptoError, KeyRing, NonceGenerator};
use std::hint::black_box;
use std::time::Instant;

/// Five workload size regimes covering small-payload overhead through bulk throughput.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadBucket {
    Tiny = 0,
    Small = 1,
    Medium = 2,
    Large = 3,
    Bulk = 4,
}

impl WorkloadBucket {
    pub const ALL: [WorkloadBucket; 5] = [
        WorkloadBucket::Tiny,
        WorkloadBucket::Small,
        WorkloadBucket::Medium,
        WorkloadBucket::Large,
        WorkloadBucket::Bulk,
    ];

    pub const fn from_size(size_bytes: usize) -> Self {
        match size_bytes {
            0..=512 => Self::Tiny,
            513..=8_192 => Self::Small,
            8_193..=131_072 => Self::Medium,
            131_073..=2_097_152 => Self::Large,
            _ => Self::Bulk,
        }
    }

    pub const fn rep_size_bytes(self) -> usize {
        match self {
            Self::Tiny => 256,
            Self::Small => 4 * 1024,
            Self::Medium => 64 * 1024,
            Self::Large => 1024 * 1024,
            Self::Bulk => 8 * 1024 * 1024,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Bulk => "bulk",
        }
    }

    const fn idx(self) -> usize {
        self as usize
    }
}

fn alg_idx(alg: Algorithm) -> usize {
    match alg {
        Algorithm::Aes128Gcm => 0,
        Algorithm::ChaCha20Poly1305 => 1,
        Algorithm::AsconAead128 => 2,
    }
}

fn median_f64(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

/// Calibrated and EMA-updated latency rate table (`ns / byte`) per `(WorkloadBucket, Algorithm)`.
#[derive(Debug, Clone)]
pub struct RuntimeProfile {
    alpha: f64,
    ns_per_byte: [[f64; 3]; 5],
}

impl RuntimeProfile {
    /// Constructs a profile from explicit per-bucket rates (useful for deterministic unit tests).
    pub fn from_rates(alpha: f64, ns_per_byte: [[f64; 3]; 5]) -> Self {
        Self {
            alpha: alpha.clamp(0.0, 1.0),
            ns_per_byte,
        }
    }

    /// Measures real encryption+decryption latency per representative bucket size on the active build.
    pub fn calibrate(keys: &KeyRing, alpha: f64) -> Result<Self, CryptoError> {
        let mut rates = [[0.0_f64; 3]; 5];
        let mut nonces = NonceGenerator::new();
        let aad = b"calibration-aad";

        for bucket in WorkloadBucket::ALL {
            let size = bucket.rep_size_bytes();
            let payload: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(31) % 256) as u8).collect();
            let (trials, reps) = match bucket {
                WorkloadBucket::Tiny => (9, 400),
                WorkloadBucket::Small => (9, 150),
                WorkloadBucket::Medium => (7, 40),
                WorkloadBucket::Large => (5, 5),
                WorkloadBucket::Bulk => (3, 1),
            };

            for alg in Algorithm::ALL {
                let cipher = AeadCipher::new(alg, keys.key_for(alg))?;
                let mut nonce = vec![0u8; alg.nonce_len()];
                let mut buf = Vec::with_capacity(size + alg.tag_len());

                // Warmup
                for _ in 0..2 {
                    buf.clear();
                    buf.extend_from_slice(&payload);
                    nonces.next_into(&mut nonce);
                    cipher.encrypt_in_place(&nonce, aad, &mut buf)?;
                    cipher.decrypt_in_place(&nonce, aad, &mut buf)?;
                    black_box(&buf);
                }

                let mut samples = Vec::with_capacity(trials);
                for _ in 0..trials {
                    let mut total_ns = 0.0_f64;
                    for _ in 0..reps {
                        buf.clear();
                        buf.extend_from_slice(&payload);
                        nonces.next_into(&mut nonce);
                        let t0 = Instant::now();
                        cipher.encrypt_in_place(black_box(&nonce), black_box(aad), black_box(&mut buf))?;
                        cipher.decrypt_in_place(black_box(&nonce), black_box(aad), black_box(&mut buf))?;
                        total_ns += t0.elapsed().as_nanos() as f64;
                    }
                    samples.push(total_ns / reps as f64);
                }
                let med_ns = median_f64(&mut samples);
                rates[bucket.idx()][alg_idx(alg)] = med_ns / (size.max(1) as f64);
            }
        }

        Ok(Self::from_rates(alpha, rates))
    }

    pub fn ns_per_byte(&self, bucket: WorkloadBucket, alg: Algorithm) -> f64 {
        self.ns_per_byte[bucket.idx()][alg_idx(alg)]
    }

    pub fn predicted_ns(&self, alg: Algorithm, size_bytes: usize) -> f64 {
        let bucket = WorkloadBucket::from_size(size_bytes);
        self.ns_per_byte(bucket, alg) * (size_bytes.max(1) as f64)
    }

    /// Updates the EMA latency rate for `(bucket(size_bytes), alg)` using a real observed duration.
    pub fn observe(&mut self, alg: Algorithm, size_bytes: usize, observed_ns: f64) {
        let bucket = WorkloadBucket::from_size(size_bytes);
        let observed_rate = observed_ns / (size_bytes.max(1) as f64);
        let slot = &mut self.ns_per_byte[bucket.idx()][alg_idx(alg)];
        *slot = self.alpha * observed_rate + (1.0 - self.alpha) * (*slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_classification_boundaries() {
        assert_eq!(WorkloadBucket::from_size(0), WorkloadBucket::Tiny);
        assert_eq!(WorkloadBucket::from_size(512), WorkloadBucket::Tiny);
        assert_eq!(WorkloadBucket::from_size(513), WorkloadBucket::Small);
        assert_eq!(WorkloadBucket::from_size(8192), WorkloadBucket::Small);
        assert_eq!(WorkloadBucket::from_size(8193), WorkloadBucket::Medium);
        assert_eq!(WorkloadBucket::from_size(131_072), WorkloadBucket::Medium);
        assert_eq!(WorkloadBucket::from_size(131_073), WorkloadBucket::Large);
        assert_eq!(WorkloadBucket::from_size(2_097_152), WorkloadBucket::Large);
        assert_eq!(WorkloadBucket::from_size(2_097_153), WorkloadBucket::Bulk);
    }

    #[test]
    fn ema_observation_updates_only_target_bucket_and_algorithm() {
        let rates = [[10.0; 3]; 5];
        let mut profile = RuntimeProfile::from_rates(0.2, rates);
        profile.observe(Algorithm::AsconAead128, 256, 20.0 * 256.0);
        let updated = profile.ns_per_byte(WorkloadBucket::Tiny, Algorithm::AsconAead128);
        assert!((updated - 12.0).abs() < 1e-9);
        assert!((profile.ns_per_byte(WorkloadBucket::Tiny, Algorithm::Aes128Gcm) - 10.0).abs() < 1e-9);
        assert!((profile.ns_per_byte(WorkloadBucket::Small, Algorithm::AsconAead128) - 10.0).abs() < 1e-9);
    }
}
