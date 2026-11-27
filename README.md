# Adaptive AEAD (`adaptive-aead`)

Prototipe dan evaluasi empiris untuk **Security-Constrained Workload-Aware Adaptive Selection of AEAD Algorithms with Hysteresis for File Processing**.

Proyek ini membandingkan empat algoritma AEAD terstandar—**AES-128-GCM** (NIST SP 800-38D), **AES-256-GCM** (NIST SP 800-38D), **ChaCha20-Poly1305** (IETF RFC 8439), dan **Ascon-AEAD128** (NIST SP 800-232)—pada dua profil kompilasi nyata (`native` dengan AES-NI/AVX2 dan `soft` skalar murni) serta dua domain beban kerja (`memory` dan `disk_batch`).

## Struktur Proyek

```text
adaptive-aead/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Fasade publik library
│   ├── crypto.rs       # Primitif AEAD, SecurityPolicy, KeyRing terisolasi domain, CipherCache, NonceGenerator
│   ├── envelope.rs     # Format amplop biner self-describing (`AAED` v1) dengan AAD-authenticated header
│   ├── profile.rs      # Bucketing ukuran workload, kalibrasi model affine 2-titik, dan EMA decay
│   ├── selector.rs     # Kebijakan Static, Lookup, AdaptiveEMA, dan mesin Hysteresis + SecurityOverride
│   ├── workload.rs     # Trace deterministik, runner subproses terisolasi (n=11), agregasi Median+IQR, CSV writer
│   └── main.rs         # CLI (`pilot`, `evaluate`, `eval-worker`)
├── tests/
│   ├── test_vectors.rs # Known Answer Tests (NIST SP 800-38D, RFC 8439, NIST SP 800-232) & filter kebijakan
│   └── stage2_tests.rs # Pengujian amplop, hysteresis, security override, dan agregasi trial
├── scripts/
│   ├── plot_pilot.py       # Generator fig1 & fig2
│   └── plot_evaluation.py  # Generator fig3, fig4, & fig5
└── results/
    ├── pilot_benchmark.csv
    ├── eval_native.csv
    ├── eval_native_timeline.csv
    ├── eval_soft.csv
    ├── eval_soft_timeline.csv
    └── figures/            # fig1..fig5 (.png dan .pdf)
```

## Reproduksi Eksperimen

### 1. Pengujian Kebenaran & Kompilasi

```bash
# Profil native (AES-NI / AVX2 / VPCLMULQDQ aktif)
cargo test
cargo build --release

# Profil pure-software scalar (`soft`)
RUSTFLAGS='--cfg aes_backend="soft" --cfg polyval_backend="soft" --cfg chacha20_backend="soft" --cfg poly1305_backend="soft"' \
  cargo test --target-dir target-soft
RUSTFLAGS='--cfg aes_backend="soft" --cfg polyval_backend="soft" --cfg chacha20_backend="soft" --cfg poly1305_backend="soft"' \
  cargo build --release --target-dir target-soft
```

### 2. Menjalankan Benchmark & Menghasilkan Output Dataset + Grafik

```bash
# Stage 1: Pilot benchmark (init overhead, in-memory, disk batch 5 rotated trials)
./target/release/adaptive-aead
python3 scripts/plot_pilot.py

# Stage 2: Evaluasi multi-trial subproses terisolasi (11 trial per kebijakan)
./target/release/adaptive-aead evaluate --profile native --trials 11
./target-soft/release/adaptive-aead evaluate --profile soft --trials 11
python3 scripts/plot_evaluation.py
```

---

## Dokumentasi Output Dataset (`results/`)

Seluruh data uji dibangkitkan secara deterministik (*SplitMix64* dan pola ukuran terprogram) sehingga tidak memakai korpus eksternal; output eksperimen disimpan ke lima berkas CSV di `results/`:

### 1. `results/pilot_benchmark.csv` (48 baris data)
Hasil benchmark dasar pada profil `native` untuk fase `init`, `in_memory`, dan `disk_*`.

| Kolom | Tipe / Satuan | Deskripsi |
| :--- | :--- | :--- |
| `phase` | string | Fase pengukuran (`init`, `in_memory`, `disk_batch_small_200x4KB`, `disk_medium_8x2MB`, `disk_large_1x64MB`) |
| `algorithm` | string | Nama algoritma AEAD (`AES-128-GCM`, `AES-256-GCM`, `ChaCha20-Poly1305`, `Ascon-AEAD128`) |
| `size_bytes` | integer (byte) | Ukuran payload per operasi (`0` pada fase `init`) |
| `file_count` | integer | Jumlah file per skenario (`1` untuk `init`/`in_memory`/`large`, `200` untuk `batch_small`, `8` untuk `medium`) |
| `enc_ns` | float (ns) | Waktu rata-rata `init`, median latensi enkripsi in-memory, atau median total waktu enkripsi disk |
| `dec_ns` | float (ns) | Median latensi dekripsi in-memory atau median total waktu dekripsi disk (`0` pada `init`) |
| `enc_mb_s` | float (MB/s) | Throughput enkripsi dalam MiB/s (`1024²` byte/detik) |
| `dec_mb_s` | float (MB/s) | Throughput dekripsi dalam MiB/s (`1024²` byte/detik) |

### 2. `results/eval_native.csv` & `results/eval_soft.csv` (masing-masing 64 baris data)
Ringkasan metrik agregat dari **11 trial subproses terisolasi** untuk 16 kebijakan × 2 domain (`memory`, `disk_batch`) × 2 trace (`mixed_burst`, `policy_shift`).

| Kolom | Tipe / Satuan | Deskripsi |
| :--- | :--- | :--- |
| `domain` | string | Domain eksekusi: `memory` (720 langkah per trace) atau `disk_batch` (24 langkah `mixed_burst`, 18 langkah `policy_shift`) |
| `profile_mode` | string | Profil kompilasi: `native` atau `soft` |
| `trace` | string | Pola workload: `mixed_burst` (128-bit konstan) atau `policy_shift` (transisi `128 → 256 → 128` bit) |
| `policy` | string | Strategi seleksi (`Static(...)`, `Lookup(...)`, `Lookup+Hyst(d=...)`, `AdaptiveEMA(...)`, `AdaptiveEMA+Hyst(d=...)`) |
| `total_bytes` | integer (byte) | Total volume payload yang diproses dalam satu trial |
| `trials` | integer | Jumlah pengulangan trial terisolasi (`11`) |
| `enc_median_ms` | float (ms) | Median total waktu enkripsi (termasuk I/O pada `disk_batch`) |
| `dec_median_ms` | float (ms) | Median total waktu dekripsi (termasuk I/O pada `disk_batch`) |
| `throughput_median_mb_s` | float (MB/s) | Median throughput end-to-end (`total_bytes / (1024² × total_waktu)`) |
| `throughput_iqr_mb_s` | float (MB/s) | Interquartile Range (Q3 − Q1) throughput antar-trial |
| `peak_rss_median_kib` | integer (KiB) | Median Peak RSS (`VmHWM`) subproses pekerja |
| `switch_count_median` | float | Median frekuensi perpindahan algoritma per trace |
| `switch_overhead_median_ms` | float (ms) | Median akumulasi waktu transisi cipher (`CipherCache` enkripsi + dekripsi) |
| `regret_median_ms` | float (ms) / `N/A` | Median selisih waktu terhadap VBS Oracle per trial (`N/A` bila `policy_compliant = false`) |
| `regret_median_pct` | float (%) / `N/A` | Median persentase regret terhadap VBS Oracle (`N/A` bila non-compliant) |
| `regret_iqr_pct` | float (%) / `N/A` | IQR persentase regret antar-trial (`N/A` bila non-compliant) |
| `policy_compliant` | boolean | `true` jika seluruh langkah memenuhi `SecurityPolicy`, `false` jika ada pelanggaran |
| `policy_violations` | integer | Jumlah langkah yang melanggar `SecurityPolicy` |

### 3. `results/eval_native_timeline.csv` & `results/eval_soft_timeline.csv` (masing-masing 23.712 baris data)
Dataset *step-level* dari trial representatif (trial dengan throughput terdekat ke median) yang merekam keputusan algoritma pada setiap langkah trace.

| Kolom | Tipe / Satuan | Deskripsi |
| :--- | :--- | :--- |
| `domain`, `profile_mode`, `trace`, `policy` | string | Identitas skenario & kebijakan |
| `step` | integer | Indeks langkah berurutan dalam trace |
| `file_count` | integer | Jumlah file pada langkah tersebut (`1` untuk `memory`, `1–32` untuk `disk_batch`) |
| `file_size_bytes` | integer (byte) | Ukuran per file pada langkah tersebut |
| `min_security_bits` | integer (bit) | Constraint minimum kekuatan kunci aktif (`128` atau `256`) |
| `chosen_alg` | string | Algoritma yang dipilih pada langkah ini |
| `switched` | boolean | `true` jika algoritma berubah dari langkah sebelumnya |
| `reason` | string | Alasan keputusan: `initial`, `already_optimal`, `hysteresis_held`, `threshold_exceeded`, `security_override`, atau `static_fixed` |
| `enc_ns` | integer (ns) | Durasi langkah enkripsi |
| `dec_ns` | integer (ns) | Durasi langkah dekripsi |
| `switch_ns` | integer (ns) | Biaya transisi cipher pada langkah ini (`enc_sw_ns + dec_sw_ns`) |
| `oracle_ns` | integer (ns) | Latensi terbaik pada langkah ini di antara baseline `Static` yang patuh kebijakan (VBS Oracle) |

### 4. Grafik Evaluasi (`results/figures/`)
- `fig1_in_memory_profile.{png,pdf}` — Throughput dan latensi in-memory Stage 1 (`native`)
- `fig2_init_and_disk_profile.{png,pdf}` — Overhead `KeyInit::new` vs throughput disk multi-trial (`native`)
- `fig3_hysteresis_tradeoff.{png,pdf}` — Kurva trade-off *switching frequency* & *performance regret* terhadap `δ` (`Lookup` vs `EMA`, `Native` vs `Soft`)
- `fig4_policy_comparison.{png,pdf}` — Perbandingan throughput patuh kebijakan (`Native` & `Soft`, `Memory Policy-Shift` & `Disk-Batch Mixed-Burst`, ± IQR/2)
- `fig5_selection_timeline.{png,pdf}` — Timeline pemilihan algoritma per langkah & titik `SecurityOverride` pada `Memory Policy-Shift` (`Soft`)
