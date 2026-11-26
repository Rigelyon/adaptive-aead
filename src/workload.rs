//! Deterministic mixed-workload and policy-shift trace evaluator.

use crate::crypto::{
    AeadCipher, Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy,
};
use crate::envelope::{open_envelope, seal_envelope};
use crate::profile::RuntimeProfile;
use crate::selector::{AdaptiveSelector, SelectionPolicy, SwitchReason};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceKind {
    MixedBurst,
    PolicyShift,
}

impl TraceKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::MixedBurst => "mixed_burst",
            Self::PolicyShift => "policy_shift",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TraceStep {
    pub step: usize,
    pub size_bytes: usize,
    pub policy: SecurityPolicy,
}

#[derive(Debug, Clone)]
pub struct PolicyEvalSummary {
    pub profile_mode: String,
    pub trace_name: String,
    pub policy_label: String,
    pub total_bytes: usize,
    pub enc_total_ms: f64,
    pub dec_total_ms: f64,
    pub throughput_mb_s: f64,
    pub peak_rss_kib: u64,
    pub switch_count: usize,
    pub switch_overhead_ms: f64,
    pub regret_ms: f64,
    pub regret_pct: f64,
    pub policy_compliant: bool,
    pub policy_violations: usize,
}

#[derive(Debug, Clone)]
pub struct TimelineRecord {
    pub profile_mode: String,
    pub trace_name: String,
    pub policy_label: String,
    pub step: usize,
    pub size_bytes: usize,
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

/// Deterministic 120-step mixed-size burst trace exercising boundary crossovers.
pub fn build_mixed_burst_trace() -> Vec<TraceStep> {
    let policy = SecurityPolicy::default();
    let pattern: &[usize] = &[
        128, 256, 384, 512, 192, 640, 1024, 3072, 4096, 512,
        128, 320, 4096, 16 * 1024, 64 * 1024, 128, 256, 512, 2048, 8192,
        256 * 1024, 1024 * 1024, 64, 512, 1024, 4096, 65_536, 256, 512, 4 * 1024 * 1024,
    ];
    (0..120)
        .map(|step| TraceStep {
            step,
            size_bytes: pattern[step % pattern.len()],
            policy,
        })
        .collect()
}

/// Deterministic 90-step trace with a mid-stream security upgrade (128 -> 256 -> 128 bits).
pub fn build_policy_shift_trace() -> Vec<TraceStep> {
    let sec_128 = SecurityPolicy::default();
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };
    let sizes: &[usize] = &[256, 512, 4096, 16 * 1024, 64 * 1024, 512 * 1024, 256, 1024, 32 * 1024];
    (0..90)
        .map(|step| TraceStep {
            step,
            size_bytes: sizes[step % sizes.len()],
            policy: if (30..60).contains(&step) { sec_256 } else { sec_128 },
        })
        .collect()
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

fn measure_oracle_steps(
    keys: &KeyRing,
    steps: &[TraceStep],
    input_paths: &[std::path::PathBuf],
    out_dir: &Path,
) -> Result<Vec<u64>, CryptoError> {
    let mut nonces = NonceGenerator::new();
    let mut oracle_ns = Vec::with_capacity(steps.len());

    for (idx, step) in steps.iter().enumerate() {
        let eligible = step.policy.eligible_algorithms();
        let mut best_ns = u64::MAX;

        for alg in eligible {
            let cipher = AeadCipher::new(alg, keys.key_for(alg))?;
            let mut nonce = vec![0u8; alg.nonce_len()];
            nonces.next_into(&mut nonce);

            let in_path = &input_paths[idx];
            let enc_path = out_dir.join(format!("oracle_{idx:04}_{}.aead", alg.id()));
            let mut buf = Vec::with_capacity(step.size_bytes + 64);

            let t0 = Instant::now();
            File::open(in_path).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
            seal_envelope(&cipher, &nonce, b"trace-aad", &mut buf)?;
            File::create(&enc_path).map_err(io_err)?.write_all(&buf).map_err(io_err)?;

            buf.clear();
            File::open(&enc_path).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
            open_envelope(keys, &step.policy, b"trace-aad", &mut buf)?;
            let elapsed = t0.elapsed().as_nanos() as u64;
            let _ = fs::remove_file(&enc_path);

            if elapsed < best_ns {
                best_ns = elapsed;
            }
        }
        oracle_ns.push(best_ns);
    }

    Ok(oracle_ns)
}

fn evaluated_policies() -> Vec<SelectionPolicy> {
    vec![
        SelectionPolicy::Static(Algorithm::Aes128Gcm),
        SelectionPolicy::Static(Algorithm::ChaCha20Poly1305),
        SelectionPolicy::Static(Algorithm::AsconAead128),
        SelectionPolicy::Adaptive,
        SelectionPolicy::AdaptiveHysteresis { delta: 0.05 },
        SelectionPolicy::AdaptiveHysteresis { delta: 0.10 },
        SelectionPolicy::AdaptiveHysteresis { delta: 0.15 },
        SelectionPolicy::AdaptiveHysteresis { delta: 0.25 },
        SelectionPolicy::AdaptiveHysteresis { delta: 0.35 },
    ]
}

/// Runs full disk-backed trace evaluations across all 9 policies and returns metrics + timeline.
pub fn run_evaluation(
    profile_label: &str,
    traces: &[(TraceKind, Vec<TraceStep>)],
    work_dir: &Path,
) -> Result<(Vec<PolicyEvalSummary>, Vec<TimelineRecord>), CryptoError> {
    let keys = KeyRing::deterministic_benchmark();
    let calibrated = RuntimeProfile::calibrate(&keys, 0.2)?;
    let policies = evaluated_policies();

    if work_dir.exists() {
        let _ = fs::remove_dir_all(work_dir);
    }
    fs::create_dir_all(work_dir).map_err(io_err)?;

    let mut summaries = Vec::new();
    let mut timeline = Vec::new();

    for (kind, steps) in traces {
        let trace_dir = work_dir.join(kind.name());
        let in_dir = trace_dir.join("in");
        let out_dir = trace_dir.join("out");
        fs::create_dir_all(&in_dir).map_err(io_err)?;
        fs::create_dir_all(&out_dir).map_err(io_err)?;

        let mut input_paths = Vec::with_capacity(steps.len());
        let mut total_bytes = 0usize;
        for step in steps {
            total_bytes += step.size_bytes;
            let payload = generate_payload(step.size_bytes, 0xA5A5_5A5A_0000_0000 ^ step.step as u64);
            let p = in_dir.join(format!("item_{:04}.bin", step.step));
            File::create(&p).map_err(io_err)?.write_all(&payload).map_err(io_err)?;
            input_paths.push(p);
        }

        let oracle_steps = measure_oracle_steps(&keys, steps, &input_paths, &out_dir)?;
        let oracle_total_ns: u64 = oracle_steps.iter().sum();

        for policy in &policies {
            let mut selector = AdaptiveSelector::new(*policy, calibrated.clone());
            let mut cache = CipherCache::new(&keys);
            let mut nonces = NonceGenerator::new();

            let mut enc_total_ns = 0u64;
            let mut dec_total_ns = 0u64;
            let mut switch_total_ns = 0u64;
            let mut switch_count = 0usize;
            let mut policy_violations = 0usize;

            for (idx, step) in steps.iter().enumerate() {
                let (chosen, switched, reason) = match selector.select_for(step.size_bytes, &step.policy) {
                    Ok(decision) => (decision.chosen, decision.switched, decision.reason),
                    Err(CryptoError::PolicyViolation(_)) => {
                        policy_violations += 1;
                        let fixed = match policy {
                            SelectionPolicy::Static(a) => *a,
                            _ => return Err(CryptoError::PolicyViolation("adaptive failed policy")),
                        };
                        (fixed, false, SwitchReason::StaticFixed)
                    }
                    Err(e) => return Err(e),
                };

                if switched {
                    switch_count += 1;
                }

                let (cipher, switch_ns) = cache.prepare(chosen)?;
                switch_total_ns += switch_ns;

                let mut nonce = vec![0u8; chosen.nonce_len()];
                nonces.next_into(&mut nonce);

                let enc_path = out_dir.join(format!("item_{idx:04}.aead"));
                let mut buf = Vec::with_capacity(step.size_bytes + 64);

                let t_enc = Instant::now();
                File::open(&input_paths[idx]).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
                seal_envelope(cipher, &nonce, b"trace-aad", &mut buf)?;
                File::create(&enc_path).map_err(io_err)?.write_all(&buf).map_err(io_err)?;
                let enc_ns = t_enc.elapsed().as_nanos() as u64;
                enc_total_ns += enc_ns;

                let t_dec = Instant::now();
                buf.clear();
                File::open(&enc_path).map_err(io_err)?.read_to_end(&mut buf).map_err(io_err)?;
                let verify_policy = if step.policy.validate(chosen).is_err() && matches!(policy, SelectionPolicy::Static(_)) {
                    SecurityPolicy::default()
                } else {
                    step.policy
                };
                open_envelope(&keys, &verify_policy, b"trace-aad", &mut buf)?;
                let dec_ns = t_dec.elapsed().as_nanos() as u64;
                dec_total_ns += dec_ns;
                let _ = fs::remove_file(&enc_path);

                selector.observe(chosen, step.size_bytes, (enc_ns + dec_ns) as f64);

                timeline.push(TimelineRecord {
                    profile_mode: profile_label.to_string(),
                    trace_name: kind.name().to_string(),
                    policy_label: policy.label(),
                    step: step.step,
                    size_bytes: step.size_bytes,
                    min_security_bits: step.policy.min_security_bits,
                    chosen_alg: chosen.name().to_string(),
                    switched,
                    reason: reason_str(reason),
                    enc_ns,
                    dec_ns,
                    switch_ns,
                    oracle_ns: oracle_steps[idx],
                });
            }

            let policy_total_ns = enc_total_ns + dec_total_ns + switch_total_ns;
            let total_sec = policy_total_ns as f64 / 1e9;
            let total_mb = total_bytes as f64 / (1024.0 * 1024.0);
            let throughput_mb_s = if total_sec > 0.0 { total_mb / total_sec } else { 0.0 };
            let regret_ns = policy_total_ns as f64 - oracle_total_ns as f64;
            let regret_pct = if oracle_total_ns > 0 {
                (regret_ns / oracle_total_ns as f64) * 100.0
            } else {
                0.0
            };

            summaries.push(PolicyEvalSummary {
                profile_mode: profile_label.to_string(),
                trace_name: kind.name().to_string(),
                policy_label: policy.label(),
                total_bytes,
                enc_total_ms: enc_total_ns as f64 / 1e6,
                dec_total_ms: dec_total_ns as f64 / 1e6,
                throughput_mb_s,
                peak_rss_kib: read_peak_rss_kib(),
                switch_count,
                switch_overhead_ms: switch_total_ns as f64 / 1e6,
                regret_ms: regret_ns / 1e6,
                regret_pct,
                policy_compliant: policy_violations == 0,
                policy_violations,
            });
        }

        let _ = fs::remove_dir_all(&trace_dir);
    }

    let _ = fs::remove_dir_all(work_dir);
    Ok((summaries, timeline))
}

pub fn write_evaluation_csvs(
    results_dir: &Path,
    profile_label: &str,
    summaries: &[PolicyEvalSummary],
    timeline: &[TimelineRecord],
) -> std::io::Result<()> {
    fs::create_dir_all(results_dir)?;

    let mut summary_csv = String::from(
        "profile_mode,trace,policy,total_bytes,enc_total_ms,dec_total_ms,throughput_mb_s,peak_rss_kib,switch_count,switch_overhead_ms,regret_ms,regret_pct,policy_compliant,policy_violations\n",
    );
    for s in summaries {
        summary_csv.push_str(&format!(
            "{},{},{},{},{:.4},{:.4},{:.2},{},{},{:.4},{:.4},{:.2},{},{}\n",
            s.profile_mode,
            s.trace_name,
            s.policy_label,
            s.total_bytes,
            s.enc_total_ms,
            s.dec_total_ms,
            s.throughput_mb_s,
            s.peak_rss_kib,
            s.switch_count,
            s.switch_overhead_ms,
            s.regret_ms,
            s.regret_pct,
            s.policy_compliant,
            s.policy_violations
        ));
    }
    fs::write(results_dir.join(format!("eval_{profile_label}.csv")), summary_csv)?;

    let mut tl_csv = String::from(
        "profile_mode,trace,policy,step,size_bytes,min_security_bits,chosen_alg,switched,reason,enc_ns,dec_ns,switch_ns,oracle_ns\n",
    );
    for t in timeline {
        tl_csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            t.profile_mode,
            t.trace_name,
            t.policy_label,
            t.step,
            t.size_bytes,
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
