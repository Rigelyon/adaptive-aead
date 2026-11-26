//! Multi-trial, subprocess-isolated trace evaluation across Memory and DiskBatch domains.

use crate::crypto::{
    Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy,
};
use crate::envelope::{open_envelope_cached, seal_envelope};
use crate::profile::RuntimeProfile;
use crate::selector::{AdaptiveSelector, SelectionPolicy, SwitchReason};
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub const DEFAULT_TRIALS: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadDomain {
    Memory,
    DiskBatch,
}

impl WorkloadDomain {
    pub const ALL: [WorkloadDomain; 2] = [WorkloadDomain::Memory, WorkloadDomain::DiskBatch];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::DiskBatch => "disk_batch",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "memory" => Some(Self::Memory),
            "disk_batch" => Some(Self::DiskBatch),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceKind {
    MixedBurst,
    PolicyShift,
}

impl TraceKind {
    pub const ALL: [TraceKind; 2] = [TraceKind::MixedBurst, TraceKind::PolicyShift];

    pub const fn name(self) -> &'static str {
        match self {
            Self::MixedBurst => "mixed_burst",
            Self::PolicyShift => "policy_shift",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "mixed_burst" => Some(Self::MixedBurst),
            "policy_shift" => Some(Self::PolicyShift),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TraceStep {
    pub step: usize,
    pub file_count: usize,
    pub file_size_bytes: usize,
    pub policy: SecurityPolicy,
}

impl TraceStep {
    pub const fn total_bytes(&self) -> usize {
        self.file_count * self.file_size_bytes
    }
}

#[derive(Debug, Clone)]
pub struct WorkerRunResult {
    pub domain: String,
    pub profile_mode: String,
    pub trace_name: String,
    pub policy_label: String,
    pub trial: usize,
    pub total_bytes: usize,
    pub enc_total_ms: f64,
    pub dec_total_ms: f64,
    pub throughput_mb_s: f64,
    pub peak_rss_kib: u64,
    pub switch_count: usize,
    pub switch_overhead_ms: f64,
    pub policy_compliant: bool,
    pub policy_violations: usize,
    pub step_total_ns: Vec<u64>,
    pub timeline: Vec<TimelineRecord>,
}

#[derive(Debug, Clone)]
pub struct AggregatedSummary {
    pub domain: String,
    pub profile_mode: String,
    pub trace_name: String,
    pub policy_label: String,
    pub total_bytes: usize,
    pub trials: usize,
    pub enc_median_ms: f64,
    pub dec_median_ms: f64,
    pub throughput_median_mb_s: f64,
    pub throughput_iqr_mb_s: f64,
    pub peak_rss_median_kib: f64,
    pub switch_count_median: f64,
    pub switch_overhead_median_ms: f64,
    pub regret_median_ms: Option<f64>,
    pub regret_median_pct: Option<f64>,
    pub regret_iqr_pct: Option<f64>,
    pub policy_compliant: bool,
    pub policy_violations: usize,
}

#[derive(Debug, Clone)]
pub struct TimelineRecord {
    pub domain: String,
    pub profile_mode: String,
    pub trace_name: String,
    pub policy_label: String,
    pub step: usize,
    pub file_count: usize,
    pub file_size_bytes: usize,
    pub min_security_bits: u16,
    pub chosen_alg: String,
    pub switched: bool,
    pub reason: &'static str,
    pub enc_ns: u64,
    pub dec_ns: u64,
    pub switch_ns: u64,
    pub oracle_ns: u64,
}

fn reason_str(reason: SwitchReason) -> &'static str {
    match reason {
        SwitchReason::Initial => "initial",
        SwitchReason::AlreadyOptimal => "already_optimal",
        SwitchReason::HysteresisHeld => "hysteresis_held",
        SwitchReason::ThresholdExceeded => "threshold_exceeded",
        SwitchReason::SecurityOverride => "security_override",
        SwitchReason::StaticFixed => "static_fixed",
    }
}

/// Deterministic 720-step (6x) mixed-size burst trace for the Memory domain,
/// extending runtime into the ~85-100 ms regime on native hardware to suppress OS scheduling jitter.
pub fn build_mixed_burst_trace() -> Vec<TraceStep> {
    let policy = SecurityPolicy::default();
    let pattern: &[usize] = &[
        128, 256, 384, 512, 192, 640, 1024, 3072, 4096, 512,
        128, 320, 4096, 16 * 1024, 64 * 1024, 128, 256, 512, 2048, 8192,
        256 * 1024, 1024 * 1024, 64, 512, 1024, 4096, 65_536, 256, 512, 4 * 1024 * 1024,
    ];
    (0..720)
        .map(|step| TraceStep {
            step,
            file_count: 1,
            file_size_bytes: pattern[step % pattern.len()],
            policy,
        })
        .collect()
}

/// Deterministic 720-step (8x) trace (`128 -> 256 -> 128 bit`, 240 steps per phase) placing a Tiny item
/// at step 239 so step 240 genuinely exercises `SecurityOverride` across all hysteresis thresholds.
pub fn build_policy_shift_trace() -> Vec<TraceStep> {
    let sec_128 = SecurityPolicy::default();
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };
    let sizes: &[usize] = &[128, 512, 4096, 16 * 1024, 64 * 1024, 512 * 1024, 256, 1024, 32 * 1024];
    (0..720)
        .map(|step| {
            let size = if step == 239 {
                128
            } else {
                sizes[step % sizes.len()]
            };
            TraceStep {
                step,
                file_count: 1,
                file_size_bytes: size,
                policy: if (240..480).contains(&step) { sec_256 } else { sec_128 },
            }
        })
        .collect()
}

/// Deterministic batch trace for DiskBatch domain (many small files vs medium/large batches).
pub fn build_disk_batch_trace(kind: TraceKind) -> Vec<TraceStep> {
    let sec_128 = SecurityPolicy::default();
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };
    // (file_count, file_size_bytes)
    let pattern: &[(usize, usize)] = &[
        (32, 256),
        (16, 4 * 1024),
        (4, 64 * 1024),
        (24, 512),
        (1, 1024 * 1024),
        (8, 16 * 1024),
    ];
    let total_steps = match kind {
        TraceKind::MixedBurst => 24,
        TraceKind::PolicyShift => 18,
    };
    (0..total_steps)
        .map(|step| {
            let (cnt, sz) = if kind == TraceKind::PolicyShift && step == 5 {
                (32, 256)
            } else {
                pattern[step % pattern.len()]
            };
            let policy = if kind == TraceKind::PolicyShift && (6..12).contains(&step) {
                sec_256
            } else {
                sec_128
            };
            TraceStep {
                step,
                file_count: cnt,
                file_size_bytes: sz,
                policy,
            }
        })
        .collect()
}

pub fn build_trace(domain: WorkloadDomain, kind: TraceKind) -> Vec<TraceStep> {
    match domain {
        WorkloadDomain::Memory => match kind {
            TraceKind::MixedBurst => build_mixed_burst_trace(),
            TraceKind::PolicyShift => build_policy_shift_trace(),
        },
        WorkloadDomain::DiskBatch => build_disk_batch_trace(kind),
    }
}

pub fn all_policies() -> Vec<SelectionPolicy> {
    let mut list = vec![
        SelectionPolicy::Static(Algorithm::Aes128Gcm),
        SelectionPolicy::Static(Algorithm::Aes256Gcm),
        SelectionPolicy::Static(Algorithm::ChaCha20Poly1305),
        SelectionPolicy::Static(Algorithm::AsconAead128),
    ];
    for &d in &[0.00, 0.05, 0.10, 0.15, 0.25, 0.35] {
        if d == 0.0 {
            list.push(SelectionPolicy::Lookup);
        } else {
            list.push(SelectionPolicy::LookupHysteresis { delta: d });
        }
    }
    for &d in &[0.00, 0.05, 0.10, 0.15, 0.25, 0.35] {
        if d == 0.0 {
            list.push(SelectionPolicy::AdaptiveEma);
        } else {
            list.push(SelectionPolicy::AdaptiveEmaHysteresis { delta: d });
        }
    }
    list
}

fn generate_payload(size: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; size];
    let mut state = seed;
    let mut i = 0;
    while i < size {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        let take = (size - i).min(8);
        out[i..i + take].copy_from_slice(&bytes[..take]);
        i += take;
    }
    out
}

pub fn read_peak_rss_kib() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            if let Some(val) = rest.split_whitespace().next().and_then(|v| v.parse().ok()) {
                return val;
            }
        }
    }
    0
}

fn io_err(_: std::io::Error) -> CryptoError {
    CryptoError::AeadFailure
}

/// Executes a single policy over a trace in the current process (used inside isolated worker subprocesses
/// and directly in unit tests).
pub fn execute_single_policy(
    domain: WorkloadDomain,
    profile_mode: &str,
    trace_kind: TraceKind,
    policy: SelectionPolicy,
    calibrated: RuntimeProfile,
    steps: &[TraceStep],
    trial: usize,
    disk_root: Option<&Path>,
) -> Result<WorkerRunResult, CryptoError> {
    let keys = KeyRing::deterministic_benchmark();
    let mut selector = AdaptiveSelector::new(policy, calibrated);
    let mut enc_cache = CipherCache::new(&keys);
    let mut dec_cache = CipherCache::new(&keys);
    let mut nonces = NonceGenerator::new();

    // Warmup cipher & buffer path before timed loop
    {
        let warm_alg = match policy {
            SelectionPolicy::Static(a) => a,
            _ => Algorithm::Aes128Gcm,
        };
        let mut wbuf = vec![0x5Au8; 1024];
        let mut wnonce = vec![0u8; warm_alg.nonce_len()];
        for _ in 0..3 {
            nonces.next_for(warm_alg, &mut wnonce);
            let (c, _) = enc_cache.prepare(warm_alg)?;
            seal_envelope(c, &wnonce, b"trace-aad", &mut wbuf)?;
            open_envelope_cached(&mut dec_cache, &SecurityPolicy::default(), b"trace-aad", &mut wbuf)?;
            black_box(&wbuf);
        }
    }

    // Prepare reusable payloads for Memory domain or batch paths for DiskBatch
    let mem_payloads: Vec<Vec<u8>> = if domain == WorkloadDomain::Memory {
        steps
            .iter()
            .map(|s| generate_payload(s.file_size_bytes, 0xA5A5_5A5A_0000_0000 ^ s.step as u64))
            .collect()
    } else {
        Vec::new()
    };

    let disk_out_dir = disk_root.map(|r| r.join(format!("out_t{trial}")));
    if let Some(ref out_dir) = disk_out_dir {
        fs::create_dir_all(out_dir).map_err(io_err)?;
    }

    let mut enc_total_ns = 0u64;
    let mut dec_total_ns = 0u64;
    let mut enc_switch_total_ns = 0u64;
    let mut switch_total_ns = 0u64;
    let mut switch_count = 0usize;
    let mut policy_violations = 0usize;
    let mut total_bytes = 0usize;
    let mut step_total_ns = Vec::with_capacity(steps.len());
    let mut timeline = Vec::with_capacity(steps.len());

    let mut buf = Vec::with_capacity(4 * 1024 * 1024 + 64);

    for (idx, step) in steps.iter().enumerate() {
        total_bytes += step.total_bytes();
        let (chosen, switched, reason) = match selector.select_for(step.file_size_bytes, &step.policy) {
            Ok(decision) => (decision.chosen, decision.switched, decision.reason),
            Err(CryptoError::PolicyViolation(_)) => {
                policy_violations += 1;
                let fixed = match policy {
                    SelectionPolicy::Static(a) => a,
                    _ => return Err(CryptoError::PolicyViolation("adaptive failed policy")),
                };
                (fixed, false, SwitchReason::StaticFixed)
            }
            Err(e) => return Err(e),
        };

        if switched {
            switch_count += 1;
        }

        let (cipher, enc_sw_ns) = enc_cache.prepare(chosen)?;
        let mut nonce = vec![0u8; chosen.nonce_len()];
        let step_enc_ns: u64;
        let step_dec_ns: u64;
        let mut dec_sw_ns = 0u64;

        let verify_policy = if step.policy.validate(chosen).is_err() && matches!(policy, SelectionPolicy::Static(_)) {
            SecurityPolicy::default()
        } else {
            step.policy
        };

        match domain {
            WorkloadDomain::Memory => {
                buf.clear();
                buf.extend_from_slice(&mem_payloads[idx]);
                nonces.next_for(chosen, &mut nonce);

                let t_enc = Instant::now();
                seal_envelope(cipher, black_box(&nonce), black_box(b"trace-aad"), black_box(&mut buf))?;
                step_enc_ns = t_enc.elapsed().as_nanos() as u64;

                let t_dec = Instant::now();
                let (_, dsw) = open_envelope_cached(
                    &mut dec_cache,
                    &verify_policy,
                    black_box(b"trace-aad"),
                    black_box(&mut buf),
                )?;
                step_dec_ns = t_dec.elapsed().as_nanos() as u64;
                dec_sw_ns = dsw;
            }
            WorkloadDomain::DiskBatch => {
                let root = disk_root.ok_or(CryptoError::AeadFailure)?;
                let out_dir = disk_out_dir.as_ref().ok_or(CryptoError::AeadFailure)?;
                let batch_in = root.join("in").join(format!("step_{:03}", step.step));

                let mut enc_paths = Vec::with_capacity(step.file_count);
                let t_enc = Instant::now();
                for fidx in 0..step.file_count {
                    buf.clear();
                    File::open(batch_in.join(format!("f_{fidx:03}.bin")))
                        .map_err(io_err)?
                        .read_to_end(&mut buf)
                        .map_err(io_err)?;
                    nonces.next_for(chosen, &mut nonce);
                    seal_envelope(cipher, &nonce, b"trace-aad", &mut buf)?;
                    let ep = out_dir.join(format!("s{idx}_f{fidx}.aead"));
                    File::create(&ep).map_err(io_err)?.write_all(&buf).map_err(io_err)?;
                    enc_paths.push(ep);
                }
                step_enc_ns = t_enc.elapsed().as_nanos() as u64;

                let t_dec = Instant::now();
                for ep in &enc_paths {
                    buf.clear();
                    File::open(ep).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
                    let (_, dsw) = open_envelope_cached(&mut dec_cache, &verify_policy, b"trace-aad", &mut buf)?;
                    dec_sw_ns += dsw;
                    let _ = fs::remove_file(ep);
                }
                step_dec_ns = t_dec.elapsed().as_nanos() as u64;
            }
        }

        // Report total transition overhead across both enc_cache and dec_cache,
        // while keeping dec_sw_ns out of st_total/policy_total_ns since it is already inside step_dec_ns.
        let step_sw_ns = enc_sw_ns + dec_sw_ns;
        enc_switch_total_ns += enc_sw_ns;
        switch_total_ns += step_sw_ns;
        enc_total_ns += step_enc_ns;
        dec_total_ns += step_dec_ns;

        let per_file_observed = (step_enc_ns + step_dec_ns) as f64 / (step.file_count.max(1) as f64);
        selector.observe(chosen, step.file_size_bytes, per_file_observed);

        let st_total = step_enc_ns + step_dec_ns + enc_sw_ns;
        step_total_ns.push(st_total);

        timeline.push(TimelineRecord {
            domain: domain.name().to_string(),
            profile_mode: profile_mode.to_string(),
            trace_name: trace_kind.name().to_string(),
            policy_label: policy.label(),
            step: step.step,
            file_count: step.file_count,
            file_size_bytes: step.file_size_bytes,
            min_security_bits: step.policy.min_security_bits,
            chosen_alg: chosen.name().to_string(),
            switched,
            reason: reason_str(reason),
            enc_ns: step_enc_ns,
            dec_ns: step_dec_ns,
            switch_ns: step_sw_ns,
            oracle_ns: 0,
        });
    }

    if let Some(ref out_dir) = disk_out_dir {
        let _ = fs::remove_dir_all(out_dir);
    }

    let policy_total_ns = enc_total_ns + dec_total_ns + enc_switch_total_ns;
    let total_sec = policy_total_ns as f64 / 1e9;
    let total_mb = total_bytes as f64 / (1024.0 * 1024.0);
    let throughput_mb_s = if total_sec > 0.0 { total_mb / total_sec } else { 0.0 };

    Ok(WorkerRunResult {
        domain: domain.name().to_string(),
        profile_mode: profile_mode.to_string(),
        trace_name: trace_kind.name().to_string(),
        policy_label: policy.label(),
        trial,
        total_bytes,
        enc_total_ms: enc_total_ns as f64 / 1e6,
        dec_total_ms: dec_total_ns as f64 / 1e6,
        throughput_mb_s,
        peak_rss_kib: read_peak_rss_kib(),
        switch_count,
        switch_overhead_ms: switch_total_ns as f64 / 1e6,
        policy_compliant: policy_violations == 0,
        policy_violations,
        step_total_ns,
        timeline,
    })
}

pub fn serialize_worker_result(res: &WorkerRunResult) -> String {
    let mut out = format!(
        "SUMMARY|{},{},{},{},{},{},{:.6},{:.6},{:.4},{},{},{:.6},{},{}\n",
        res.domain,
        res.profile_mode,
        res.trace_name,
        res.policy_label,
        res.trial,
        res.total_bytes,
        res.enc_total_ms,
        res.dec_total_ms,
        res.throughput_mb_s,
        res.peak_rss_kib,
        res.switch_count,
        res.switch_overhead_ms,
        res.policy_compliant,
        res.policy_violations
    );
    for (t, &sns) in res.timeline.iter().zip(res.step_total_ns.iter()) {
        out.push_str(&format!(
            "STEP|{},{},{},{},{},{},{},{},{},{},{}\n",
            t.step,
            t.file_count,
            t.file_size_bytes,
            t.min_security_bits,
            t.chosen_alg,
            t.switched,
            t.reason,
            t.enc_ns,
            t.dec_ns,
            t.switch_ns,
            sns
        ));
    }
    out
}

pub fn deserialize_worker_result(text: &str) -> Result<WorkerRunResult, CryptoError> {
    let mut lines = text.lines();
    let sum_line = lines.next().ok_or(CryptoError::AeadFailure)?;
    let sum_body = sum_line.strip_prefix("SUMMARY|").ok_or(CryptoError::AeadFailure)?;
    let sp: Vec<&str> = sum_body.split(',').collect();
    if sp.len() != 14 {
        return Err(CryptoError::AeadFailure);
    }

    let domain = sp[0].to_string();
    let profile_mode = sp[1].to_string();
    let trace_name = sp[2].to_string();
    let policy_label = sp[3].to_string();
    let trial: usize = sp[4].parse().map_err(|_| CryptoError::AeadFailure)?;
    let total_bytes: usize = sp[5].parse().map_err(|_| CryptoError::AeadFailure)?;
    let enc_total_ms: f64 = sp[6].parse().map_err(|_| CryptoError::AeadFailure)?;
    let dec_total_ms: f64 = sp[7].parse().map_err(|_| CryptoError::AeadFailure)?;
    let throughput_mb_s: f64 = sp[8].parse().map_err(|_| CryptoError::AeadFailure)?;
    let peak_rss_kib: u64 = sp[9].parse().map_err(|_| CryptoError::AeadFailure)?;
    let switch_count: usize = sp[10].parse().map_err(|_| CryptoError::AeadFailure)?;
    let switch_overhead_ms: f64 = sp[11].parse().map_err(|_| CryptoError::AeadFailure)?;
    let policy_compliant: bool = sp[12].parse().map_err(|_| CryptoError::AeadFailure)?;
    let policy_violations: usize = sp[13].parse().map_err(|_| CryptoError::AeadFailure)?;

    let mut timeline = Vec::new();
    let mut step_total_ns = Vec::new();
    for line in lines {
        let Some(body) = line.strip_prefix("STEP|") else {
            continue;
        };
        let p: Vec<&str> = body.split(',').collect();
        if p.len() != 11 {
            return Err(CryptoError::AeadFailure);
        }
        let reason: &'static str = match p[6] {
            "initial" => "initial",
            "already_optimal" => "already_optimal",
            "hysteresis_held" => "hysteresis_held",
            "threshold_exceeded" => "threshold_exceeded",
            "security_override" => "security_override",
            _ => "static_fixed",
        };
        timeline.push(TimelineRecord {
            domain: domain.clone(),
            profile_mode: profile_mode.clone(),
            trace_name: trace_name.clone(),
            policy_label: policy_label.clone(),
            step: p[0].parse().map_err(|_| CryptoError::AeadFailure)?,
            file_count: p[1].parse().map_err(|_| CryptoError::AeadFailure)?,
            file_size_bytes: p[2].parse().map_err(|_| CryptoError::AeadFailure)?,
            min_security_bits: p[3].parse().map_err(|_| CryptoError::AeadFailure)?,
            chosen_alg: p[4].to_string(),
            switched: p[5].parse().map_err(|_| CryptoError::AeadFailure)?,
            reason,
            enc_ns: p[7].parse().map_err(|_| CryptoError::AeadFailure)?,
            dec_ns: p[8].parse().map_err(|_| CryptoError::AeadFailure)?,
            switch_ns: p[9].parse().map_err(|_| CryptoError::AeadFailure)?,
            oracle_ns: 0,
        });
        step_total_ns.push(p[10].parse().map_err(|_| CryptoError::AeadFailure)?);
    }

    Ok(WorkerRunResult {
        domain,
        profile_mode,
        trace_name,
        policy_label,
        trial,
        total_bytes,
        enc_total_ms,
        dec_total_ms,
        throughput_mb_s,
        peak_rss_kib,
        switch_count,
        switch_overhead_ms,
        policy_compliant,
        policy_violations,
        step_total_ns,
        timeline,
    })
}

pub fn prepare_disk_batch_inputs(root: &Path, steps: &[TraceStep]) -> std::io::Result<()> {
    let in_root = root.join("in");
    if in_root.exists() {
        fs::remove_dir_all(&in_root)?;
    }
    for step in steps {
        let dir = in_root.join(format!("step_{:03}", step.step));
        fs::create_dir_all(&dir)?;
        let payload = generate_payload(step.file_size_bytes, 0xBEEF_0000 ^ step.step as u64);
        for fidx in 0..step.file_count {
            File::create(dir.join(format!("f_{fidx:03}.bin")))?.write_all(&payload)?;
        }
    }
    Ok(())
}

fn shuffle_with_seed<T>(slice: &mut [T], seed: u64) {
    let mut state = seed;
    for i in (1..slice.len()).rev() {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let j = (z as usize) % (i + 1);
        slice.swap(i, j);
    }
}

fn quantile_sorted(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let pos = q * ((sorted.len() - 1) as f64);
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let frac = pos - (lo as f64);
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

fn median_and_iqr(values: &[f64]) -> (f64, f64) {
    let mut s = values.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let med = quantile_sorted(&s, 0.5);
    let iqr = quantile_sorted(&s, 0.75) - quantile_sorted(&s, 0.25);
    (med, iqr)
}

/// Computes per-trial VBS oracle across compliant Static runs and aggregates Median + IQR across trials.
pub fn aggregate_trials(
    domain: WorkloadDomain,
    profile_mode: &str,
    trace_kind: TraceKind,
    steps: &[TraceStep],
    trial_runs: &[Vec<WorkerRunResult>],
) -> (Vec<AggregatedSummary>, Vec<TimelineRecord>) {
    let policies = all_policies();
    let num_trials = trial_runs.len();

    // Per-trial VBS oracle across compliant Static baselines
    let mut vbs_per_trial: Vec<Vec<u64>> = Vec::with_capacity(num_trials);
    for runs in trial_runs {
        let mut vbs = vec![u64::MAX; steps.len()];
        for r in runs {
            if !r.policy_label.starts_with("Static(") {
                continue;
            }
            let Some(alg) = Algorithm::ALL.into_iter().find(|a| r.policy_label == format!("Static({})", a.name())) else {
                continue;
            };
            for (i, step) in steps.iter().enumerate() {
                if step.policy.validate(alg).is_ok() && r.step_total_ns[i] < vbs[i] {
                    vbs[i] = r.step_total_ns[i];
                }
            }
        }
        vbs_per_trial.push(vbs);
    }

    let mut summaries = Vec::with_capacity(policies.len());
    let mut median_timelines = Vec::new();

    for policy in &policies {
        let label = policy.label();
        let mut matched: Vec<(usize, &WorkerRunResult)> = Vec::new();
        for (t_idx, runs) in trial_runs.iter().enumerate() {
            if let Some(r) = runs.iter().find(|x| x.policy_label == label) {
                matched.push((t_idx, r));
            }
        }
        if matched.is_empty() {
            continue;
        }

        let enc_vals: Vec<f64> = matched.iter().map(|(_, r)| r.enc_total_ms).collect();
        let dec_vals: Vec<f64> = matched.iter().map(|(_, r)| r.dec_total_ms).collect();
        let tp_vals: Vec<f64> = matched.iter().map(|(_, r)| r.throughput_mb_s).collect();
        let rss_vals: Vec<f64> = matched.iter().map(|(_, r)| r.peak_rss_kib as f64).collect();
        let sw_vals: Vec<f64> = matched.iter().map(|(_, r)| r.switch_count as f64).collect();
        let sw_ov_vals: Vec<f64> = matched.iter().map(|(_, r)| r.switch_overhead_ms).collect();

        let compliant = matched.iter().all(|(_, r)| r.policy_compliant);
        let violations = matched[0].1.policy_violations;

        let (reg_med_ms, reg_med_pct, reg_iqr_pct) = if compliant {
            let mut rms = Vec::with_capacity(matched.len());
            let mut rpct = Vec::with_capacity(matched.len());
            for &(t_idx, r) in &matched {
                let oracle_ns: u64 = vbs_per_trial[t_idx].iter().copied().filter(|&v| v < u64::MAX).sum();
                let pol_ns: u64 = r.step_total_ns.iter().sum();
                let diff_ns = pol_ns as f64 - oracle_ns as f64;
                rms.push(diff_ns / 1e6);
                let pct = if oracle_ns > 0 {
                    (diff_ns / oracle_ns as f64) * 100.0
                } else {
                    0.0
                };
                rpct.push(pct);
            }
            let (m_ms, _) = median_and_iqr(&rms);
            let (m_pct, iqr_pct) = median_and_iqr(&rpct);
            (Some(m_ms), Some(m_pct), Some(iqr_pct))
        } else {
            (None, None, None)
        };

        let (enc_med, _) = median_and_iqr(&enc_vals);
        let (dec_med, _) = median_and_iqr(&dec_vals);
        let (tp_med, tp_iqr) = median_and_iqr(&tp_vals);
        let (rss_med, _) = median_and_iqr(&rss_vals);
        let (sw_med, _) = median_and_iqr(&sw_vals);
        let (sw_ov_med, _) = median_and_iqr(&sw_ov_vals);

        // Pick representative trial closest to median throughput for timeline export
        let &(rep_trial_idx, rep_run) = matched
            .iter()
            .min_by(|a, b| (a.1.throughput_mb_s - tp_med).abs().total_cmp(&(b.1.throughput_mb_s - tp_med).abs()))
            .expect("matched non-empty");
        for (i, rec) in rep_run.timeline.iter().enumerate() {
            let mut r = rec.clone();
            r.oracle_ns = vbs_per_trial[rep_trial_idx][i];
            median_timelines.push(r);
        }

        summaries.push(AggregatedSummary {
            domain: domain.name().to_string(),
            profile_mode: profile_mode.to_string(),
            trace_name: trace_kind.name().to_string(),
            policy_label: label,
            total_bytes: matched[0].1.total_bytes,
            trials: matched.len(),
            enc_median_ms: enc_med,
            dec_median_ms: dec_med,
            throughput_median_mb_s: tp_med,
            throughput_iqr_mb_s: tp_iqr,
            peak_rss_median_kib: rss_med,
            switch_count_median: sw_med,
            switch_overhead_median_ms: sw_ov_med,
            regret_median_ms: reg_med_ms,
            regret_median_pct: reg_med_pct,
            regret_iqr_pct: reg_iqr_pct,
            policy_compliant: compliant,
            policy_violations: violations,
        });
    }

    (summaries, median_timelines)
}

/// Orchestrates isolated subprocess multi-trial evaluation across Memory and DiskBatch domains.
pub fn run_isolated_evaluation(
    profile_mode: &str,
    trials: usize,
    work_dir: &Path,
) -> Result<(Vec<AggregatedSummary>, Vec<TimelineRecord>), CryptoError> {
    let keys = KeyRing::deterministic_benchmark();
    let exe = std::env::current_exe().map_err(io_err)?;

    if work_dir.exists() {
        let _ = fs::remove_dir_all(work_dir);
    }
    fs::create_dir_all(work_dir).map_err(io_err)?;

    let mut all_summaries = Vec::new();
    let mut all_timelines = Vec::new();

    for domain in WorkloadDomain::ALL {
        let cal_profile = match domain {
            WorkloadDomain::Memory => RuntimeProfile::calibrate_memory(&keys, 0.2)?,
            WorkloadDomain::DiskBatch => {
                RuntimeProfile::calibrate_disk(&keys, 0.2, &work_dir.join("cal_disk"))?
            }
        };
        let cal_path = work_dir.join(format!("profile_{}.txt", domain.name()));
        fs::write(&cal_path, cal_profile.serialize()).map_err(io_err)?;

        for trace_kind in TraceKind::ALL {
            let steps = build_trace(domain, trace_kind);
            let disk_root = if domain == WorkloadDomain::DiskBatch {
                let d = work_dir.join("disk_trace");
                prepare_disk_batch_inputs(&d, &steps).map_err(io_err)?;
                Some(d)
            } else {
                None
            };

            let mut trial_runs = Vec::with_capacity(trials);
            for trial in 0..trials {
                let mut policies = all_policies();
                shuffle_with_seed(&mut policies, 0x5EED_CAFE_0000_0000 ^ (trial as u64));

                let mut runs_in_trial = Vec::with_capacity(policies.len());
                for pol in policies {
                    let out_file = work_dir.join("worker_out.txt");
                    let mut cmd = Command::new(&exe);
                    cmd.arg("eval-worker")
                        .arg("--domain")
                        .arg(domain.name())
                        .arg("--profile")
                        .arg(profile_mode)
                        .arg("--trace")
                        .arg(trace_kind.name())
                        .arg("--policy")
                        .arg(pol.key())
                        .arg("--trial")
                        .arg(trial.to_string())
                        .arg("--profile-cache")
                        .arg(&cal_path)
                        .arg("--out")
                        .arg(&out_file);
                    if let Some(ref d) = disk_root {
                        cmd.arg("--disk-root").arg(d);
                    }

                    let status = cmd.status().map_err(io_err)?;
                    if !status.success() {
                        return Err(CryptoError::AeadFailure);
                    }
                    let txt = fs::read_to_string(&out_file).map_err(io_err)?;
                    runs_in_trial.push(deserialize_worker_result(&txt)?);
                }
                trial_runs.push(runs_in_trial);
            }

            if let Some(ref d) = disk_root {
                let _ = fs::remove_dir_all(d);
            }

            let (sums, tls) = aggregate_trials(domain, profile_mode, trace_kind, &steps, &trial_runs);
            all_summaries.extend(sums);
            all_timelines.extend(tls);
        }
    }

    let _ = fs::remove_dir_all(work_dir);
    Ok((all_summaries, all_timelines))
}

fn opt_fmt(v: Option<f64>, decimals: usize) -> String {
    match v {
        Some(x) => format!("{x:.decimals$}"),
        None => "N/A".to_string(),
    }
}

pub fn write_evaluation_csvs(
    results_dir: &Path,
    profile_label: &str,
    summaries: &[AggregatedSummary],
    timeline: &[TimelineRecord],
) -> std::io::Result<()> {
    fs::create_dir_all(results_dir)?;

    let mut summary_csv = String::from(
        "domain,profile_mode,trace,policy,total_bytes,trials,enc_median_ms,dec_median_ms,throughput_median_mb_s,throughput_iqr_mb_s,peak_rss_median_kib,switch_count_median,switch_overhead_median_ms,regret_median_ms,regret_median_pct,regret_iqr_pct,policy_compliant,policy_violations\n",
    );
    for s in summaries {
        summary_csv.push_str(&format!(
            "{},{},{},{},{},{},{:.4},{:.4},{:.2},{:.2},{:.0},{:.1},{:.4},{},{},{},{},{}\n",
            s.domain,
            s.profile_mode,
            s.trace_name,
            s.policy_label,
            s.total_bytes,
            s.trials,
            s.enc_median_ms,
            s.dec_median_ms,
            s.throughput_median_mb_s,
            s.throughput_iqr_mb_s,
            s.peak_rss_median_kib,
            s.switch_count_median,
            s.switch_overhead_median_ms,
            opt_fmt(s.regret_median_ms, 4),
            opt_fmt(s.regret_median_pct, 2),
            opt_fmt(s.regret_iqr_pct, 2),
            s.policy_compliant,
            s.policy_violations
        ));
    }
    fs::write(results_dir.join(format!("eval_{profile_label}.csv")), summary_csv)?;

    let mut tl_csv = String::from(
        "domain,profile_mode,trace,policy,step,file_count,file_size_bytes,min_security_bits,chosen_alg,switched,reason,enc_ns,dec_ns,switch_ns,oracle_ns\n",
    );
    for t in timeline {
        tl_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            t.domain,
            t.profile_mode,
            t.trace_name,
            t.policy_label,
            t.step,
            t.file_count,
            t.file_size_bytes,
            t.min_security_bits,
            t.chosen_alg,
            t.switched,
            t.reason,
            t.enc_ns,
            t.dec_ns,
            t.switch_ns,
            t.oracle_ns
        ));
    }
    fs::write(results_dir.join(format!("eval_{profile_label}_timeline.csv")), tl_csv)?;

    Ok(())
}
