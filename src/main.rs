//! Pilot benchmark profiling AES-128-GCM, ChaCha20-Poly1305, and Ascon-AEAD128
//! across initialization overhead, in-memory payload sizes, and disk file batches.

use adaptive_aead::profile::RuntimeProfile;
use adaptive_aead::selector::SelectionPolicy;
use adaptive_aead::workload::{
    DEFAULT_TRIALS, TraceKind, WorkloadDomain, build_trace, execute_single_policy,
    run_isolated_evaluation, serialize_worker_result, write_evaluation_csvs,
};
use adaptive_aead::{AeadCipher, Algorithm, KeyRing, NonceGenerator, SecurityPolicy};
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Generates reproducible pseudo-random payload bytes via SplitMix64.
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

/// Deterministic 32-byte master key material (for benchmark isolation only).
fn key_for(alg: Algorithm) -> Vec<u8> {
    (0..alg.key_len()).map(|i| (i as u8).wrapping_mul(17).wrapping_add(3)).collect()
}

/// Reads current process RSS and Peak RSS (VmHWM) in KiB on Linux.
fn read_proc_memory_kib() -> (Option<u64>, Option<u64>) {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return (None, None);
    };
    let mut rss = None;
    let mut hwm = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("VmHWM:") {
            hwm = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    (rss, hwm)
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

fn bench_init_overhead(alg: Algorithm, iterations: usize) -> f64 {
    let key = key_for(alg);
    // Warmup
    for _ in 0..1000 {
        let c = AeadCipher::new(black_box(alg), black_box(&key)).unwrap();
        black_box(c);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let c = AeadCipher::new(black_box(alg), black_box(&key)).unwrap();
        black_box(c);
    }
    let elapsed_ns = start.elapsed().as_nanos() as f64;
    elapsed_ns / iterations as f64
}

struct InMemResult {
    alg: Algorithm,
    size_bytes: usize,
    enc_ns_median: f64,
    dec_ns_median: f64,
    enc_mb_s: f64,
    dec_mb_s: f64,
}

fn bench_in_memory(alg: Algorithm, size_bytes: usize, trials: usize, reps_per_trial: usize) -> InMemResult {
    let key = key_for(alg);
    let cipher = AeadCipher::new(alg, &key).unwrap();
    let payload = generate_payload(size_bytes, 0x1234_5678_9ABC_DEF0);
    let aad = b"workload-pilot-aad";

    let mut nonces = NonceGenerator::new();
    let mut nonce = vec![0u8; alg.nonce_len()];
    let mut buf = Vec::with_capacity(size_bytes + alg.tag_len());

    // Warmup
    for _ in 0..3 {
        buf.clear();
        buf.extend_from_slice(&payload);
        nonces.next_into(&mut nonce);
        cipher.encrypt_in_place(&nonce, aad, &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, aad, &mut buf).unwrap();
        black_box(&buf);
    }

    let mut enc_samples = Vec::with_capacity(trials);
    let mut dec_samples = Vec::with_capacity(trials);

    for _ in 0..trials {
        // Measure encryption batch
        let mut enc_ns_total = 0.0_f64;
        let mut dec_ns_total = 0.0_f64;

        for _ in 0..reps_per_trial {
            buf.clear();
            buf.extend_from_slice(&payload);
            nonces.next_into(&mut nonce);

            let t0 = Instant::now();
            cipher
                .encrypt_in_place(black_box(&nonce), black_box(aad), black_box(&mut buf))
                .unwrap();
            enc_ns_total += t0.elapsed().as_nanos() as f64;

            let t1 = Instant::now();
            cipher
                .decrypt_in_place(black_box(&nonce), black_box(aad), black_box(&mut buf))
                .unwrap();
            dec_ns_total += t1.elapsed().as_nanos() as f64;
        }

        enc_samples.push(enc_ns_total / reps_per_trial as f64);
        dec_samples.push(dec_ns_total / reps_per_trial as f64);
    }

    let enc_med = median_f64(&mut enc_samples);
    let dec_med = median_f64(&mut dec_samples);
    let mb = size_bytes as f64 / (1024.0 * 1024.0);
    let enc_mb_s = if enc_med > 0.0 { mb / (enc_med / 1e9) } else { 0.0 };
    let dec_mb_s = if dec_med > 0.0 { mb / (dec_med / 1e9) } else { 0.0 };

    InMemResult {
        alg,
        size_bytes,
        enc_ns_median: enc_med,
        dec_ns_median: dec_med,
        enc_mb_s,
        dec_mb_s,
    }
}

struct FileBenchResult {
    enc_total_ms: f64,
    dec_total_ms: f64,
}

fn prepare_test_files(dir: &Path, count: usize, file_size: usize) -> std::io::Result<Vec<PathBuf>> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;
    let template = generate_payload(file_size, 0xCAFE_BABE_DEAD_BEEF);
    let mut paths = Vec::with_capacity(count);
    for idx in 0..count {
        let p = dir.join(format!("sample_{idx:04}.bin"));
        let mut f = File::create(&p)?;
        f.write_all(&template)?;
        paths.push(p);
    }
    Ok(paths)
}

fn bench_disk_scenario(
    _scenario: &'static str,
    alg: Algorithm,
    input_paths: &[PathBuf],
    out_dir: &Path,
    file_size_bytes: usize,
) -> std::io::Result<FileBenchResult> {
    if out_dir.exists() {
        fs::remove_dir_all(out_dir)?;
    }
    fs::create_dir_all(out_dir)?;

    let key = key_for(alg);
    let cipher = AeadCipher::new(alg, &key).unwrap();
    let mut nonces = NonceGenerator::new();
    let mut nonce = vec![0u8; alg.nonce_len()];
    let aad = b"file-header-aad";
    let mut buf = Vec::with_capacity(file_size_bytes + alg.tag_len());

    let mut encrypted_records: Vec<(PathBuf, Vec<u8>)> = Vec::with_capacity(input_paths.len());

    let t_enc = Instant::now();
    for (idx, in_path) in input_paths.iter().enumerate() {
        buf.clear();
        File::open(in_path)?.read_to_end(&mut buf)?;
        nonces.next_into(&mut nonce);
        cipher.encrypt_in_place(&nonce, aad, &mut buf).unwrap();

        let enc_path = out_dir.join(format!("enc_{idx:04}.aead"));
        File::create(&enc_path)?.write_all(&buf)?;
        encrypted_records.push((enc_path, nonce.clone()));
    }
    let enc_total_ms = t_enc.elapsed().as_secs_f64() * 1000.0;

    let t_dec = Instant::now();
    for (idx, (enc_path, n)) in encrypted_records.iter().enumerate() {
        buf.clear();
        File::open(enc_path)?.read_to_end(&mut buf)?;
        cipher.decrypt_in_place(n, aad, &mut buf).unwrap();

        let dec_path = out_dir.join(format!("dec_{idx:04}.bin"));
        File::create(&dec_path)?.write_all(&buf)?;
    }
    let dec_total_ms = t_dec.elapsed().as_secs_f64() * 1000.0;

    Ok(FileBenchResult {
        enc_total_ms,
        dec_total_ms,
    })
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{bytes} B")
    }
}

fn run_pilot_cli() -> std::io::Result<()> {
    let policy = SecurityPolicy::default();
    let candidates = policy.eligible_algorithms();
    println!("=== Adaptive AEAD Pilot Benchmark (Rust) ===");
    println!("Eligible algorithms (min {} bits):", policy.min_security_bits);
    for alg in &candidates {
        println!(
            "  - {} ({}, key={}B, nonce={}B, tag={}B)",
            alg.name(),
            alg.standard(),
            alg.key_len(),
            alg.nonce_len(),
            alg.tag_len()
        );
    }

    // 1. KeyInit / context initialization latency
    println!("\n[1] Cipher Initialization Overhead (KeyInit::new):");
    println!("{:<20} | {:>14}", "Algorithm", "Init Mean (ns)");
    println!("{:-<20}-+-{:-<14}", "", "");
    let mut init_csv_rows = Vec::new();
    for &alg in &candidates {
        let ns = bench_init_overhead(alg, 200_000);
        println!("{:<20} | {:>14.1}", alg.name(), ns);
        init_csv_rows.push(format!("init,{},0,1,{:.2},0,0,0", alg.name(), ns));
    }

    // 2. In-memory throughput across payload sizes
    let workloads: &[(usize, usize, usize)] = &[
        (64, 15, 2000),
        (1024, 15, 1000),
        (4 * 1024, 15, 500),
        (16 * 1024, 15, 250),
        (64 * 1024, 15, 100),
        (1024 * 1024, 11, 20),
        (16 * 1024 * 1024, 7, 3),
        (64 * 1024 * 1024, 5, 1),
    ];

    println!("\n[2] In-Memory AEAD Benchmark (Median across trials):");
    println!(
        "{:<10} | {:<18} | {:>11} | {:>11} | {:>11} | {:>11}",
        "Size", "Algorithm", "Enc (us)", "Dec (us)", "Enc (MB/s)", "Dec (MB/s)"
    );
    println!("{:-<10}-+-{:-<18}-+-{:-<11}-+-{:-<11}-+-{:-<11}-+-{:-<11}", "", "", "", "", "", "");

    let mut mem_csv_rows = Vec::new();
    for &(size, trials, reps) in workloads {
        for &alg in &candidates {
            let r = bench_in_memory(alg, size, trials, reps);
            println!(
                "{:<10} | {:<18} | {:>11.2} | {:>11.2} | {:>11.2} | {:>11.2}",
                format_size(r.size_bytes),
                r.alg.name(),
                r.enc_ns_median / 1000.0,
                r.dec_ns_median / 1000.0,
                r.enc_mb_s,
                r.dec_mb_s
            );
            mem_csv_rows.push(format!(
                "in_memory,{},{},1,{:.2},{:.2},{:.2},{:.2}",
                r.alg.name(),
                r.size_bytes,
                r.enc_ns_median,
                r.dec_ns_median,
                r.enc_mb_s,
                r.dec_mb_s
            ));
        }
    }

    // 3. Disk file I/O + AEAD benchmark (1 warmup + 5 rotated trials, median reported)
    let tmp_root = PathBuf::from("bench_tmp");
    let disk_scenarios: &[(&'static str, usize, usize)] = &[
        ("batch_small_200x4KB", 200, 4 * 1024),
        ("medium_8x2MB", 8, 2 * 1024 * 1024),
        ("large_1x64MB", 1, 64 * 1024 * 1024),
    ];

    println!("\n[3] Disk File Processing Benchmark (Median of 5 Rotated Trials, Read -> AEAD -> Write):");
    println!(
        "{:<22} | {:<18} | {:>11} | {:>11} | {:>11} | {:>11}",
        "Scenario", "Algorithm", "Enc (ms)", "Dec (ms)", "Enc (MB/s)", "Dec (MB/s)"
    );
    println!("{:-<22}-+-{:-<18}-+-{:-<11}-+-{:-<11}-+-{:-<11}-+-{:-<11}", "", "", "", "", "", "");

    let mut disk_csv_rows = Vec::new();
    for &(name, count, fsize) in disk_scenarios {
        let in_dir = tmp_root.join(format!("{name}_in"));
        let inputs = prepare_test_files(&in_dir, count, fsize)?;

        // Warmup pass on first algorithm so OS page cache is hot before timed trials
        if let Some(&first_alg) = candidates.first() {
            let warm_dir = tmp_root.join(format!("{name}_warm"));
            let _ = bench_disk_scenario(name, first_alg, &inputs, &warm_dir, fsize)?;
            let _ = fs::remove_dir_all(&warm_dir);
        }

        let num_trials = 5usize;
        let mut enc_by_alg: Vec<Vec<f64>> = vec![Vec::with_capacity(num_trials); candidates.len()];
        let mut dec_by_alg: Vec<Vec<f64>> = vec![Vec::with_capacity(num_trials); candidates.len()];

        for trial in 0..num_trials {
            for offset in 0..candidates.len() {
                let alg_idx = (trial + offset) % candidates.len();
                let alg = candidates[alg_idx];
                let out_dir = tmp_root.join(format!("{name}_out_{}_{trial}", alg.name()));
                let r = bench_disk_scenario(name, alg, &inputs, &out_dir, fsize)?;
                enc_by_alg[alg_idx].push(r.enc_total_ms);
                dec_by_alg[alg_idx].push(r.dec_total_ms);
                let _ = fs::remove_dir_all(&out_dir);
            }
        }

        let total_mb = (count * fsize) as f64 / (1024.0 * 1024.0);
        for (alg_idx, &alg) in candidates.iter().enumerate() {
            let enc_med = median_f64(&mut enc_by_alg[alg_idx]);
            let dec_med = median_f64(&mut dec_by_alg[alg_idx]);
            let enc_mb_s = total_mb / (enc_med / 1000.0);
            let dec_mb_s = total_mb / (dec_med / 1000.0);
            println!(
                "{:<22} | {:<18} | {:>11.2} | {:>11.2} | {:>11.2} | {:>11.2}",
                name, alg.name(), enc_med, dec_med, enc_mb_s, dec_mb_s
            );
            disk_csv_rows.push(format!(
                "disk_{},{},{},{},{:.2},{:.2},{:.2},{:.2}",
                name,
                alg.name(),
                fsize,
                count,
                enc_med * 1e6,
                dec_med * 1e6,
                enc_mb_s,
                dec_mb_s
            ));
        }
        let _ = fs::remove_dir_all(&in_dir);
    }
    let _ = fs::remove_dir_all(&tmp_root);

    let _ = KeyRing::deterministic_benchmark();
    let (rss_kib, hwm_kib) = read_proc_memory_kib();
    println!(
        "\nProcess Memory: VmRSS={:?} KiB, Peak VmHWM={:?} KiB",
        rss_kib, hwm_kib
    );

    fs::create_dir_all("results")?;
    let mut csv = String::from(
        "phase,algorithm,size_bytes,file_count,enc_ns,dec_ns,enc_mb_s,dec_mb_s\n",
    );
    for row in init_csv_rows.into_iter().chain(mem_csv_rows).chain(disk_csv_rows) {
        csv.push_str(&row);
        csv.push('\n');
    }
    fs::write("results/pilot_benchmark.csv", csv)?;
    println!("Saved raw measurements to results/pilot_benchmark.csv");

    Ok(())
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

fn run_eval_worker_cli(args: &[String]) -> std::io::Result<()> {
    let domain_name = arg_value(args, "--domain").ok_or_else(|| std::io::Error::other("missing --domain"))?;
    let domain = WorkloadDomain::from_name(domain_name)
        .ok_or_else(|| std::io::Error::other("invalid --domain"))?;
    let profile_mode = arg_value(args, "--profile").unwrap_or("native");
    let trace_name = arg_value(args, "--trace").ok_or_else(|| std::io::Error::other("missing --trace"))?;
    let trace_kind = TraceKind::from_name(trace_name)
        .ok_or_else(|| std::io::Error::other("invalid --trace"))?;
    let pol_key = arg_value(args, "--policy").ok_or_else(|| std::io::Error::other("missing --policy"))?;
    let policy = SelectionPolicy::from_key(pol_key)
        .ok_or_else(|| std::io::Error::other("invalid --policy"))?;
    let trial: usize = arg_value(args, "--trial")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let cal_path = arg_value(args, "--profile-cache")
        .ok_or_else(|| std::io::Error::other("missing --profile-cache"))?;
    let out_path = arg_value(args, "--out").ok_or_else(|| std::io::Error::other("missing --out"))?;
    let disk_root = arg_value(args, "--disk-root").map(PathBuf::from);

    let cal_txt = fs::read_to_string(cal_path)?;
    let calibrated = RuntimeProfile::deserialize(&cal_txt)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let steps = build_trace(domain, trace_kind);
    let res = execute_single_policy(
        domain,
        profile_mode,
        trace_kind,
        policy,
        calibrated,
        &steps,
        trial,
        disk_root.as_deref(),
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?;

    fs::write(out_path, serialize_worker_result(&res))
}

fn run_evaluate_cli(profile: &str, trials: usize) -> std::io::Result<()> {
    let work_dir = PathBuf::from(format!("bench_eval_tmp_{profile}"));
    let (summaries, timeline) = run_isolated_evaluation(profile, trials, &work_dir)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    println!("=== Adaptive AEAD Stage 2 Evaluation (profile={profile}, trials={trials}, isolated subprocesses) ===");
    println!(
        "{:<10} | {:<12} | {:<27} | {:>10} | {:>7} | {:>7} | {:>8} | {:>9} | {:>9}",
        "Domain", "Trace", "Policy", "Med(MB/s)", "IQR", "Sw(med)", "RSS(KiB)", "Regret(%)", "Compliant"
    );
    println!(
        "{:-<10}-+-{:-<12}-+-{:-<27}-+-{:-<10}-+-{:-<7}-+-{:-<7}-+-{:-<8}-+-{:-<9}-+-{:-<9}",
        "", "", "", "", "", "", "", "", ""
    );
    for s in &summaries {
        let reg = match s.regret_median_pct {
            Some(v) => format!("{v:.2}"),
            None => "N/A".to_string(),
        };
        println!(
            "{:<10} | {:<12} | {:<27} | {:>10.2} | {:>7.2} | {:>7.1} | {:>8.0} | {:>9} | {:>9}",
            s.domain,
            s.trace_name,
            s.policy_label,
            s.throughput_median_mb_s,
            s.throughput_iqr_mb_s,
            s.switch_count_median,
            s.peak_rss_median_kib,
            reg,
            s.policy_compliant
        );
    }

    write_evaluation_csvs(Path::new("results"), profile, &summaries, &timeline)?;
    println!(
        "Saved Stage 2 CSVs to results/eval_{profile}.csv and results/eval_{profile}_timeline.csv"
    );
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("evaluate") => {
            let profile = arg_value(&args, "--profile").unwrap_or("native");
            let trials = arg_value(&args, "--trials")
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_TRIALS);
            run_evaluate_cli(profile, trials)
        }
        Some("eval-worker") => run_eval_worker_cli(&args),
        _ => run_pilot_cli(),
    }
}
