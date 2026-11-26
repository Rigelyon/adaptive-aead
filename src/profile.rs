//! Workload size bucketing, two-point affine calibration, and bounded EMA scaling.

use crate::crypto::{Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy};
use crate::envelope::{open_envelope_cached, seal_envelope};
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

/// Five workload size regimes covering small-payload fixed overhead through bulk throughput.
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

    /// Low and high anchor payload sizes (bytes) used to fit the affine model per bucket.
    pub const fn anchor_sizes(self) -> (usize, usize) {
        match self {
            Self::Tiny => (64, 512),
            Self::Small => (1024, 8192),
            Self::Medium => (16 * 1024, 128 * 1024),
            Self::Large => (256 * 1024, 2 * 1024 * 1024),
            Self::Bulk => (4 * 1024 * 1024, 16 * 1024 * 1024),
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

/// Affine cost model: `ema_scale * (intercept_ns + slope_ns_per_byte * size_bytes)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AffineCost {
    pub intercept_ns: f64,
    pub slope_ns_per_byte: f64,
    pub ema_scale: f64,
}

impl AffineCost {
    pub fn from_two_points(s_lo: usize, t_lo: f64, s_hi: usize, t_hi: f64) -> Self {
        let ds = (s_hi.saturating_sub(s_lo)).max(1) as f64;
        let slope = ((t_hi - t_lo) / ds).max(0.0);
        let intercept = (t_lo - slope * (s_lo as f64)).max(0.0);
        Self {
            intercept_ns: intercept,
            slope_ns_per_byte: slope,
            ema_scale: 1.0,
        }
    }

    pub fn base_ns(self, size_bytes: usize) -> f64 {
        (self.intercept_ns + self.slope_ns_per_byte * (size_bytes as f64)).max(1.0)
    }

    pub fn predicted_ns(self, size_bytes: usize) -> f64 {
        (self.ema_scale * self.base_ns(size_bytes)).max(1.0)
    }

    pub fn observe(&mut self, size_bytes: usize, observed_ns: f64, alpha: f64) {
        let ratio = (observed_ns / self.base_ns(size_bytes)).clamp(0.25, 4.0);
        self.ema_scale = alpha * ratio + (1.0 - alpha) * self.ema_scale;
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

fn measure_envelope_pair(
    keys: &KeyRing,
    alg: Algorithm,
    size: usize,
    trials: usize,
    reps: usize,
) -> Result<f64, CryptoError> {
    let payload: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(31) % 256) as u8).collect();
    let policy = SecurityPolicy::default();
    let mut enc_cache = CipherCache::new(keys);
    let mut dec_cache = CipherCache::new(keys);
    let mut nonces = NonceGenerator::new();
    let mut nonce = vec![0u8; alg.nonce_len()];
    let mut buf = Vec::with_capacity(size + 64);
    let aad = b"trace-aad";

    // Warmup in exact envelope + cached decrypt path
    for _ in 0..3 {
        buf.clear();
        buf.extend_from_slice(&payload);
        nonces.next_for(alg, &mut nonce);
        let (cipher, _) = enc_cache.prepare(alg)?;
        seal_envelope(cipher, &nonce, aad, &mut buf)?;
        open_envelope_cached(&mut dec_cache, &policy, aad, &mut buf)?;
        black_box(&buf);
    }

    let mut samples = Vec::with_capacity(trials);
    for _ in 0..trials {
        let mut total_ns = 0.0_f64;
        for _ in 0..reps {
            buf.clear();
            buf.extend_from_slice(&payload);
            nonces.next_for(alg, &mut nonce);
            let (cipher, _) = enc_cache.prepare(alg)?;
            let t0 = Instant::now();
            seal_envelope(cipher, black_box(&nonce), black_box(aad), black_box(&mut buf))?;
            open_envelope_cached(&mut dec_cache, &policy, black_box(aad), black_box(&mut buf))?;
            total_ns += t0.elapsed().as_nanos() as f64;
        }
        samples.push(total_ns / (reps as f64));
    }

    Ok(median_f64(&mut samples))
}

fn measure_disk_pair(
    keys: &KeyRing,
    alg: Algorithm,
    size: usize,
    trials: usize,
    scratch_dir: &Path,
) -> Result<f64, CryptoError> {
    let io_err = |_: std::io::Error| CryptoError::AeadFailure;
    fs::create_dir_all(scratch_dir).map_err(io_err)?;
    let in_path = scratch_dir.join(format!("cal_in_{size}.bin"));
    let enc_path = scratch_dir.join(format!("cal_enc_{size}_{}.aead", alg.id()));
    let payload: Vec<u8> = (0..size).map(|i| (i.wrapping_mul(31) % 256) as u8).collect();
    File::create(&in_path).map_err(io_err)?.write_all(&payload).map_err(io_err)?;

    let policy = SecurityPolicy::default();
    let mut enc_cache = CipherCache::new(keys);
    let mut dec_cache = CipherCache::new(keys);
    let mut nonces = NonceGenerator::new();
    let mut nonce = vec![0u8; alg.nonce_len()];
    let mut buf = Vec::with_capacity(size + 64);
    let aad = b"trace-aad";

    // Warmup
    for _ in 0..2 {
        buf.clear();
        File::open(&in_path).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
        nonces.next_for(alg, &mut nonce);
        let (cipher, _) = enc_cache.prepare(alg)?;
        seal_envelope(cipher, &nonce, aad, &mut buf)?;
        File::create(&enc_path).map_err(io_err)?.write_all(&buf).map_err(io_err)?;
        buf.clear();
        File::open(&enc_path).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
        open_envelope_cached(&mut dec_cache, &policy, aad, &mut buf)?;
    }

    let mut samples = Vec::with_capacity(trials);
    for _ in 0..trials {
        buf.clear();
        nonces.next_for(alg, &mut nonce);
        let (cipher, _) = enc_cache.prepare(alg)?;
        let t0 = Instant::now();
        File::open(&in_path).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
        seal_envelope(cipher, &nonce, aad, &mut buf)?;
        File::create(&enc_path).map_err(io_err)?.write_all(&buf).map_err(io_err)?;
        buf.clear();
        File::open(&enc_path).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
        open_envelope_cached(&mut dec_cache, &policy, aad, &mut buf)?;
        samples.push(t0.elapsed().as_nanos() as f64);
    }

    let _ = fs::remove_file(&enc_path);
    let _ = fs::remove_file(&in_path);
    Ok(median_f64(&mut samples))
}

/// Calibrated affine latency profile (`5 buckets × 4 algorithms`) with optional EMA scaling.
#[derive(Debug, Clone)]
pub struct RuntimeProfile {
    alpha: f64,
    models: [[AffineCost; 4]; 5],
}

impl RuntimeProfile {
    pub fn from_models(alpha: f64, models: [[AffineCost; 4]; 5]) -> Self {
        Self {
            alpha: alpha.clamp(0.0, 1.0),
            models,
        }
    }

    /// Convenience constructor for uniform linear rates (`intercept = 0.0`).
    pub fn from_rates(alpha: f64, ns_per_byte: [[f64; 4]; 5]) -> Self {
        let mut models = [[AffineCost {
            intercept_ns: 0.0,
            slope_ns_per_byte: 0.0,
            ema_scale: 1.0,
        }; 4]; 5];
        for (b, row) in ns_per_byte.iter().enumerate() {
            for (a, &rate) in row.iter().enumerate() {
                models[b][a].slope_ns_per_byte = rate;
            }
        }
        Self::from_models(alpha, models)
    }

    /// Calibrates the affine envelope model in-memory across all 5 buckets and 4 algorithms.
    pub fn calibrate_memory(keys: &KeyRing, alpha: f64) -> Result<Self, CryptoError> {
        let mut models = [[AffineCost {
            intercept_ns: 0.0,
            slope_ns_per_byte: 0.0,
            ema_scale: 1.0,
        }; 4]; 5];

        for bucket in WorkloadBucket::ALL {
            let (s_lo, s_hi) = bucket.anchor_sizes();
            let (trials, reps_lo, reps_hi) = match bucket {
                WorkloadBucket::Tiny => (9, 400, 300),
                WorkloadBucket::Small => (9, 150, 80),
                WorkloadBucket::Medium => (7, 40, 15),
                WorkloadBucket::Large => (5, 8, 3),
                WorkloadBucket::Bulk => (3, 2, 1),
            };
            for alg in Algorithm::ALL {
                let t_lo = measure_envelope_pair(keys, alg, s_lo, trials, reps_lo)?;
                let t_hi = measure_envelope_pair(keys, alg, s_hi, trials, reps_hi)?;
                models[bucket.idx()][alg.index()] = AffineCost::from_two_points(s_lo, t_lo, s_hi, t_hi);
            }
        }

        Ok(Self::from_models(alpha, models))
    }

    /// Calibrates the affine model including real disk I/O (`Read -> Seal -> Write -> Read -> Open`).
    pub fn calibrate_disk(keys: &KeyRing, alpha: f64, scratch_dir: &Path) -> Result<Self, CryptoError> {
        let mut models = [[AffineCost {
            intercept_ns: 0.0,
            slope_ns_per_byte: 0.0,
            ema_scale: 1.0,
        }; 4]; 5];

        for bucket in WorkloadBucket::ALL {
            let (s_lo, s_hi) = bucket.anchor_sizes();
            let (s_lo, s_hi, trials) = match bucket {
                WorkloadBucket::Tiny | WorkloadBucket::Small | WorkloadBucket::Medium => (s_lo, s_hi, 7),
                WorkloadBucket::Large => (s_lo, s_hi, 5),
                WorkloadBucket::Bulk => (s_lo, 8 * 1024 * 1024, 3),
            };
            for alg in Algorithm::ALL {
                let t_lo = measure_disk_pair(keys, alg, s_lo, trials, scratch_dir)?;
                let t_hi = measure_disk_pair(keys, alg, s_hi, trials, scratch_dir)?;
                models[bucket.idx()][alg.index()] = AffineCost::from_two_points(s_lo, t_lo, s_hi, t_hi);
            }
        }
        let _ = fs::remove_dir_all(scratch_dir);

        Ok(Self::from_models(alpha, models))
    }

    pub fn model(&self, bucket: WorkloadBucket, alg: Algorithm) -> AffineCost {
        self.models[bucket.idx()][alg.index()]
    }

    pub fn predicted_ns(&self, alg: Algorithm, size_bytes: usize) -> f64 {
        let bucket = WorkloadBucket::from_size(size_bytes);
        self.models[bucket.idx()][alg.index()].predicted_ns(size_bytes)
    }

    /// Updates the EMA scaling factor for `(bucket(size_bytes), alg)` using a domain-matched observation.
    pub fn observe(&mut self, alg: Algorithm, size_bytes: usize, observed_ns: f64) {
        let bucket = WorkloadBucket::from_size(size_bytes);
        self.models[bucket.idx()][alg.index()].observe(size_bytes, observed_ns, self.alpha);
    }

    pub fn serialize(&self) -> String {
        let mut out = format!("{}\n", self.alpha);
        for b in 0..5 {
            for a in 0..4 {
                let m = self.models[b][a];
                out.push_str(&format!(
                    "{},{},{},{},{}\n",
                    b, a, m.intercept_ns, m.slope_ns_per_byte, m.ema_scale
                ));
            }
        }
        out
    }

    pub fn deserialize(text: &str) -> Result<Self, CryptoError> {
        let mut lines = text.lines();
        let alpha: f64 = lines
            .next()
            .and_then(|l| l.trim().parse().ok())
            .ok_or(CryptoError::AeadFailure)?;
        let mut models = [[AffineCost {
            intercept_ns: 0.0,
            slope_ns_per_byte: 0.0,
            ema_scale: 1.0,
        }; 4]; 5];
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() != 5 {
                return Err(CryptoError::AeadFailure);
            }
            let b: usize = parts[0].parse().map_err(|_| CryptoError::AeadFailure)?;
            let a: usize = parts[1].parse().map_err(|_| CryptoError::AeadFailure)?;
            let intercept_ns: f64 = parts[2].parse().map_err(|_| CryptoError::AeadFailure)?;
            let slope_ns_per_byte: f64 = parts[3].parse().map_err(|_| CryptoError::AeadFailure)?;
            let ema_scale: f64 = parts[4].parse().map_err(|_| CryptoError::AeadFailure)?;
            if b >= 5 || a >= 4 {
                return Err(CryptoError::AeadFailure);
            }
            models[b][a] = AffineCost {
                intercept_ns,
                slope_ns_per_byte,
                ema_scale,
            };
        }
        Ok(Self::from_models(alpha, models))
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
    fn affine_cost_and_ema_scale_preserve_small_payload_stability() {
        // Fixed 200 ns overhead + 1.0 ns/B: 64B = 264 ns, 512B = 712 ns
        let mut cost = AffineCost::from_two_points(64, 264.0, 512, 712.0);
        assert!((cost.intercept_ns - 200.0).abs() < 1e-6);
        assert!((cost.slope_ns_per_byte - 1.0).abs() < 1e-6);
        assert!((cost.predicted_ns(64) - 264.0).abs() < 1e-6);
        assert!((cost.predicted_ns(512) - 712.0).abs() < 1e-6);

        // Observing exact 64B cost keeps ema_scale == 1.0 (no 1/S blowup!)
        cost.observe(64, 264.0, 0.2);
        assert!((cost.ema_scale - 1.0).abs() < 1e-9);
        assert!((cost.predicted_ns(512) - 712.0).abs() < 1e-6);

        // Observing 2x slowdown updates ema_scale smoothly to 1.2
        cost.observe(64, 528.0, 0.2);
        assert!((cost.ema_scale - 1.2).abs() < 1e-9);
    }

    #[test]
    fn profile_roundtrip_serialization() {
        let mut models = [[AffineCost {
            intercept_ns: 150.0,
            slope_ns_per_byte: 1.5,
            ema_scale: 1.0,
        }; 4]; 5];
        models[0][3].intercept_ns = 310.25;
        let p = RuntimeProfile::from_models(0.2, models);
        let decoded = RuntimeProfile::deserialize(&p.serialize()).unwrap();
        assert!((decoded.predicted_ns(Algorithm::AsconAead128, 64) - p.predicted_ns(Algorithm::AsconAead128, 64)).abs() < 1e-6);
    }
}
