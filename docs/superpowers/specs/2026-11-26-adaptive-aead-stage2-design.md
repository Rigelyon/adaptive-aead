# Design Specification: Adaptive AEAD Selector, Hysteresis Engine, and Dual-Profile Evaluator (Stage 2)

**Date:** 2026-11-26  
**Project:** `adaptive-aead` (`/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead`)  
**Topic:** Security-Constrained Workload-Aware Adaptive Selection of AEAD Algorithms with Hysteresis for File Processing  
**Architecture Choice:** Option A — Single Modular Crate + Dual Real Build Profiles (`native` vs `soft`)

---

## 1. Goals and Scope

Stage 1 (`pilot_benchmark`) established baseline throughput and initialization metrics for `AES-128-GCM` (NIST SP 800-38D), `ChaCha20-Poly1305` (RFC 8439), and `Ascon-AEAD128` (NIST SP 800-232) on an AMD Ryzen 5 5600H (`AES-NI`, `VPCLMULQDQ`, `AVX2`). Stage 2 extends `adaptive-aead` from a static micro-benchmark into the complete adaptive prototype and evaluation suite required by the research methodology:

1. **Self-Describing Encrypted File Envelope:** An authenticated binary header format allowing decryption to identify the cipher and nonce automatically without external metadata, with header integrity bound via AEAD Associated Data (AAD).
2. **Workload-Aware Adaptive Selector with Security Gate:** Runtime cipher selection based on calibrated per-bucket performance profiles updated online with Exponential Moving Average (EMA) telemetry, constrained by `SecurityPolicy`.
3. **Hysteresis Engine:** Relative improvement threshold `δ` preventing oscillation (*flapping*) under workload fluctuations, overridden immediately if a security policy shift invalidates the active cipher.
4. **Dual-Profile Empirical Evaluation (`native` vs `soft`):** Real execution under both hardware-accelerated (`native`) and pure-software scalar (`soft`) builds, evaluating `Static`, `Adaptive (δ = 0%)`, and `Adaptive + Hysteresis (δ ∈ {5%, 10%, 15%, 25%, 35%})` across all seven proposal metrics.

Out of scope: designing new cryptographic primitives, network transport protocols, or multi-threaded async key servers.

---

## 2. Crate Module Layout

The single crate `adaptive-aead` is organized into focused modules under `src/`, keeping `src/lib.rs` as the clean public facade:

```text
adaptive-aead/
├── Cargo.toml
├── .gitignore                  # ignores /target/, /target-soft/, /bench_tmp/, /results/
├── docs/superpowers/specs/
│   └── 2026-11-26-adaptive-aead-stage2-design.md
├── src/
│   ├── lib.rs                  # public re-exports for library consumers & tests
│   ├── crypto.rs               # Algorithm, CryptoError, SecurityPolicy, KeyRing, AeadCipher, CipherCache, NonceGenerator
│   ├── envelope.rs             # Self-describing encrypted file format (seal_envelope / open_envelope)
│   ├── profile.rs              # WorkloadBucket, RuntimeProfile, calibration, and online EMA telemetry
│   ├── selector.rs             # SelectionPolicy, AdaptiveSelector, HysteresisConfig, SwitchDecision
│   ├── workload.rs             # Mixed/policy-shift trace generators, 7-metric evaluator, CSV exporter
│   └── main.rs                 # CLI entrypoint with `pilot` and `evaluate` subcommands
├── tests/
│   ├── test_vectors.rs         # Existing NIST/RFC KATs + policy tests
│   └── stage2_tests.rs         # Envelope, selector, hysteresis, and end-to-end trace tests
└── scripts/
    ├── plot_pilot.py           # Existing Stage 1 figures
    └── plot_evaluation.py      # Stage 2 trade-off, regret, and timeline figures
```

---

## 3. Component Design

### 3.1 Cryptographic Facade & Key Cache (`src/crypto.rs`)

- Preserves `Algorithm`, `SecurityPolicy`, `AeadCipher`, and `NonceGenerator` from Stage 1.
- Adds `KeyRing`: holds a 32-byte master key (`[u8; 32]`) and slices `&master[..alg.key_len()]` per candidate (`16 B` for `AES-128-GCM` and `Ascon-AEAD128`, `32 B` for `ChaCha20-Poly1305`).
- Adds `CipherCache`: maintains the currently active `AeadCipher` instance (or re-initializes on algorithm switch) and explicitly measures the wall-clock transition cost (`KeyInit::new` + `NonceGenerator` domain setup) whenever `active != next`, feeding directly into `switching_overhead_ns`.
- Extends `CryptoError` with envelope-specific variants (`InvalidMagic`, `UnsupportedVersion(u8)`, `UnknownAlgorithmId(u8)`, `TruncatedEnvelope`, `InvalidNonceField`).

### 3.2 Self-Describing Encrypted File Envelope (`src/envelope.rs`)

Every encrypted payload written to memory or disk uses a deterministic binary header followed by `ciphertext || tag`:

```text
+-------------------+-------------+------------+--------------+------------+-------------------+------------------------+
| Magic ("AAED")    | Version     | AlgID      | NonceLen     | Flags      | Nonce             | Ciphertext + Tag       |
| 4 bytes           | 1 byte      | 1 byte     | 1 byte       | 1 byte     | NonceLen bytes    | N + 16 bytes           |
+-------------------+-------------+------------+--------------+------------+-------------------+------------------------+
```

- **Field Definitions:**
  - `Magic`: `b"AAED"` (`[0x41, 0x41, 0x45, 0x44]`).
  - `Version`: `0x01`.
  - `AlgID`: `0x01` = `AES-128-GCM`, `0x02` = `ChaCha20-Poly1305`, `0x03` = `Ascon-AEAD128`.
  - `NonceLen`: `12` (`AES-128-GCM`, `ChaCha20-Poly1305`) or `16` (`Ascon-AEAD128`); validated to match `Algorithm::nonce_len()`.
  - `Flags`: `0x00` (must be zero in v1).
- **AAD Integrity Binding:**
  - Both encryption (`seal_envelope`) and decryption (`open_envelope`) construct `bound_aad = header_bytes (8 + NonceLen bytes) || user_aad`.
  - Any tampering with `Magic`, `Version`, `AlgID`, `NonceLen`, `Flags`, or `Nonce` invalidates the AEAD authentication tag and returns `Err(CryptoError::AeadFailure)` before plaintext is released.
- **Policy Enforcement on Decryption:**
  - `open_envelope` validates the parsed `Algorithm` against the caller's active `SecurityPolicy` before invoking decryption. If a file was encrypted with a cipher disallowed by current policy, decryption fails immediately with `Err(CryptoError::PolicyViolation(...))`.

### 3.3 Workload Profiling & Online EMA Telemetry (`src/profile.rs`)

File payloads are partitioned into five size buckets matching the empirical regimes observed in Stage 1:

| Bucket | Payload Size Range | Calibration Representative Size |
| :--- | :--- | :--- |
| `Tiny` | `0 ..= 512 B` | `256 B` |
| `Small` | `513 B ..= 8 KiB` | `4 KiB` |
| `Medium` | `8 KiB + 1 B ..= 128 KiB` | `64 KiB` |
| `Large` | `128 KiB + 1 B ..= 2 MiB` | `1 MiB` |
| `Bulk` | `> 2 MiB` | `8 MiB` |

- **Initial Calibration:** At startup (before trace execution), `RuntimeProfile::calibrate` runs short, reproducible warm-up + median measurements across all eligible algorithms at each bucket's representative size using the active build profile (`native` or `soft`). It records normalized cost in nanoseconds per byte (`ns_per_byte`, with a `max(1)` size guard) for each `(WorkloadBucket, Algorithm)` pair.
- **Cost Prediction:** For an incoming file of size `S` bytes, predicted latency for candidate `alg` is:
  `predicted_ns(alg, S) = profile.ns_per_byte(bucket(S), alg) * (S.max(1) as f64)`
- **Online EMA Update:** After processing each file in `observed_ns`, the profile updates the executed algorithm's entry in that bucket:
  `observed_rate = observed_ns / (S.max(1) as f64)`
  `new_rate = alpha * observed_rate + (1.0 - alpha) * old_rate`
  with smoothing factor `alpha = 0.2` (configurable). This allows the selector to adapt to real runtime I/O/cache conditions without erasing calibrated priors.

### 3.4 Adaptive Selector & Hysteresis Engine (`src/selector.rs`)

`AdaptiveSelector` implements three comparable decision modes over a `SecurityPolicy` and `RuntimeProfile`:

1. **`Static(Algorithm)`:** Always selects a fixed algorithm (baseline).
2. **`Adaptive` (`δ = 0.0`):** Selects the eligible algorithm with minimum `predicted_ns(alg, S)` on every file.
3. **`AdaptiveHysteresis { delta: f64 }` (`δ > 0.0`):**
   - Step 1 (**Security Gate**): Compute `eligible = policy.eligible_algorithms()`. If `eligible` is empty, return `CryptoError::PolicyViolation`.
   - Step 2 (**Mandatory Policy Override**): If no `active` algorithm exists yet, or if `policy.validate(active)` fails (e.g., policy tightened from 128-bit to 256-bit), immediately switch to `best = argmin_{a in eligible} predicted_ns(a, S)` with reason `SwitchReason::SecurityOverride`. Hysteresis never blocks a mandatory security upgrade.
   - Step 3 (**Best-Candidate Lookup**): Find `best = argmin_{a in eligible} predicted_ns(a, S)`. If `best == active`, keep `active` (`SwitchReason::AlreadyOptimal`).
   - Step 4 (**Relative Hysteresis Check**): Compute relative gain:
     `gain = (est(active) - est(best)) / est(active)`
     If `gain > delta`, switch to `best` (`SwitchReason::ThresholdExceeded`); otherwise keep `active` (`SwitchReason::HysteresisHeld`).

### 3.5 Dual-Profile Execution (`native` vs `soft`) & Trace Evaluator (`src/workload.rs`, `src/main.rs`)

- **Real Dual Build Profiles (Verified Crate Flags):**
  - **`native` profile:** Standard release build (`cargo build --release`) executing hardware `AES-NI`, `VPCLMULQDQ`, and `AVX2` instructions.
  - **`soft` profile:** Separate target directory build (`--target-dir target-soft`) compiled with:
    `RUSTFLAGS='--cfg aes_backend="soft" --cfg polyval_backend="soft" --cfg chacha20_backend="soft" --cfg poly1305_backend="soft"'`
    forcing pure-software scalar execution in `aes 0.9.4`, `polyval 0.7.3` (used by `ghash 0.6.0`), `chacha20 0.10.2`, and `poly1305 0.9.1`, alongside `ascon-aead128 0.1.1`.
  - The CLI `evaluate --profile <native|soft>` labels all output rows with the active build profile (`cfg!(...)` check / CLI tag) so CSVs and plots remain strictly attributable.

- **Evaluation Traces:**
  1. **`mixed_burst` (Workload Volatility Trace, `min_security_bits = 128`):** Deterministic sequence of 120 file operations cycling and jittering across size regimes—including boundary bursts near crossover points (`256 B – 1.5 KB` where `Ascon-AEAD128` vs `ChaCha20-Poly1305` cross in `soft`/`native`, and `4 KB – 1 MB` bursts)—performed on real temporary disk files (`Read -> Envelope Seal -> Write -> Read -> Envelope Open -> Verify`).
  2. **`policy_shift` (Security Constraint Trace):** 90-file mixed-size trace divided into three 30-file phases where `SecurityPolicy::min_security_bits` transitions `128 -> 256 -> 128`, testing immediate `SecurityOverride` switching to `ChaCha20-Poly1305` and post-relaxation hysteresis recovery.

- **Oracle Baseline & All 7 Proposal Metrics:**
  - For each trace, an oracle pass measures median encryption + decryption time of every eligible candidate per trace step `t` to establish `oracle_best_ns(t)` objectively.
  - Each policy (`Static(AES)`, `Static(ChaCha20)`, `Static(Ascon)`, `Adaptive(δ=0.00)`, `Adaptive(δ=0.05)`, `Adaptive(δ=0.10)`, `Adaptive(δ=0.15)`, `Adaptive(δ=0.25)`, `Adaptive(δ=0.35)`) is evaluated over the full trace, recording:
    1. `enc_total_ms` (Encryption time)
    2. `dec_total_ms` (Decryption time)
    3. `throughput_mb_s` (Total bytes / total crypto+envelope time)
    4. `peak_rss_kib` (Memory usage via Linux `/proc/self/status` `VmHWM`)
    5. `switch_count` (Switching frequency)
    6. `switch_overhead_ms` (Cumulative real context re-init / transition latency)
    7. `regret_ms` & `regret_pct` (`(policy_total_ns - oracle_total_ns) / oracle_total_ns * 100`)
  - Each summary row also records `policy_compliant` (`true`/`false`) and `policy_violations` count: during `policy_shift`'s 256-bit phase, `Static(AES-128-GCM)` and `Static(Ascon-AEAD128)` fail `SecurityPolicy::validate` and are marked `policy_compliant = false` (whereas `Static(ChaCha20-Poly1305)` and all `Adaptive*` policies remain `policy_compliant = true` via `SecurityOverride`).
  - Outputs saved to `results/eval_<profile>.csv` and `results/eval_<profile>_timeline.csv`.

---

## 4. Verification and Error Handling Strategy

- **Error Handling:** All library APIs return `Result<_, CryptoError>` with zero `unwrap()` in production paths (`crypto.rs`, `envelope.rs`, `profile.rs`, `selector.rs`). Invalid envelopes, truncated headers, wrong versions, tampered AAD/ciphertext, and security policy violations fail closed.
- **Automated Tests (`cargo test` under BOTH `native` and `soft` profiles):**
  - Existing NIST SP 800-38D, RFC 8439, and NIST SP 800-232 KATs (`tests/test_vectors.rs`).
  - Envelope roundtrip tests for all 3 ciphers (empty, small, large payloads; empty and non-empty user AAD).
  - Negative envelope tests: flipped magic, unsupported version, unknown `AlgID`, mismatched `NonceLen`, tampered `AlgID` in header (must trigger `AeadFailure`), and decryption blocked by `SecurityPolicy` (`PolicyViolation`).
  - Deterministic `AdaptiveSelector` unit tests: holding when `gain <= delta`, switching when `gain > delta`, forced immediate switch on `SecurityPolicy` upgrade regardless of `delta`, and EMA rate convergence.
  - Trace evaluator integration test verifying non-empty metrics, valid roundtrip recovery on every step, and monotonic/expected switching count trend (`switch_count(δ=0.35) <= switch_count(δ=0.0)`).
- **Visualizations (`scripts/plot_evaluation.py`):**
  - Generates publication-grade PNG (300 DPI) and vector PDF figures in `results/figures/` comparing `Static`, `Adaptive (δ=0)`, and `Adaptive + Hysteresis` across both `native` and `soft` profiles (Switching Frequency vs Performance Regret curve, Throughput & Latency comparison, and Per-Step Algorithm Selection Timeline).
