# Adaptive AEAD Stage 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the modular Stage 2 Adaptive AEAD prototype—authenticated file envelope, calibrated/EMA workload profiler, security-constrained hysteresis selector, dual-profile (`native` vs `soft`) trace evaluator, and evaluation figures—in `adaptive-aead`.

**Architecture:** Refactor `adaptive-aead` into single-responsibility modules (`crypto`, `envelope`, `profile`, `selector`, `workload`) behind `src/lib.rs` and a zero-dependency CLI (`pilot` and `evaluate`) in `src/main.rs`. Execute real empirical traces under both the default hardware-accelerated (`native`) build and a separate pure-software scalar (`soft`) build (`target-soft/`), writing CSV metrics and plotting publication-grade figures with Python `matplotlib`.

**Tech Stack:** Rust (`edition = "2024"`, `rustc 1.100.0`, crates `aead 0.6.1`, `aes-gcm 0.11.1`, `chacha20poly1305 0.11.0`, `ascon-aead128 0.1.1`), Python 3.15 (`matplotlib`, `numpy`) inside `distrobox enter my-distrobox`.

## Global Constraints

- Execute all `cargo`, `rustc`, and `python3` commands inside `distrobox enter my-distrobox -- ...` with working directory `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead`.
- No new Cargo dependencies beyond `aead 0.6.1`, `aes-gcm 0.11.1`, `ascon-aead128 0.1.1`, `chacha20poly1305 0.11.0` in `Cargo.toml`.
- Zero `unwrap()` or `expect()` in production library modules (`src/crypto.rs`, `src/envelope.rs`, `src/profile.rs`, `src/selector.rs`, `src/workload.rs`).
- Preserve all existing Stage 1 NIST SP 800-38D, RFC 8439, and NIST SP 800-232 KAT tests in `tests/test_vectors.rs`.
- Dual build profiles MUST use real RustCrypto cfg flags for `soft` (`--target-dir target-soft` with `RUSTFLAGS='--cfg aes_backend="soft" --cfg polyval_backend="soft" --cfg chacha20_backend="soft" --cfg poly1305_backend="soft"'`) — never synthetic delays.
- Ignore `/target/`, `/target-soft/`, `/bench_tmp/`, `/results/` in `.gitignore`.

---

## File Map

- Modify: `.gitignore` — add `/target-soft/`
- Create: `src/crypto.rs` — core AEAD primitives, `KeyRing`, `CipherCache`, extended `CryptoError`, `Algorithm::id`/`from_id`
- Create: `src/envelope.rs` — self-describing binary file header (`AAED` v1) with AAD binding & `SecurityPolicy` check
- Create: `src/profile.rs` — 5-bucket `WorkloadBucket`, `RuntimeProfile` calibration + online `EMA` (`alpha = 0.2`)
- Create: `src/selector.rs` — `SelectionPolicy`, `SwitchReason`, `SelectionDecision`, `AdaptiveSelector`
- Create: `src/workload.rs` — `mixed_burst` & `policy_shift` deterministic traces, oracle pass, 7-metric + compliance evaluator, CSV export
- Modify: `src/lib.rs` — clean module declarations and public re-exports
- Modify: `src/main.rs` — CLI subcommands `pilot` and `evaluate --profile <native|soft>`
- Create: `tests/stage2_tests.rs` — comprehensive envelope, selector, hysteresis, and evaluator integration tests
- Create: `scripts/plot_evaluation.py` — Stage 2 figures (`fig3_hysteresis_tradeoff`, `fig4_policy_comparison`, `fig5_selection_timeline`)

---

### Task 1: Extract `src/crypto.rs`, Add `KeyRing` & `CipherCache`, and Update `.gitignore`

**Files:**
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/.gitignore`
- Create: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/crypto.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/lib.rs`
- Test: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/tests/test_vectors.rs` (must stay passing) + unit tests in `src/crypto.rs`

**Interfaces:**
- Produces: `Algorithm::id(self) -> u8`, `Algorithm::from_id(id: u8) -> Result<Algorithm, CryptoError>`, `CryptoError::{InvalidMagic, UnsupportedVersion(u8), UnknownAlgorithmId(u8), TruncatedEnvelope, InvalidNonceField}`, `KeyRing::new([u8; 32])`, `KeyRing::deterministic_benchmark()`, `KeyRing::key_for(&self, Algorithm) -> &[u8]`, `CipherCache::new(&KeyRing)`, `CipherCache::prepare(&mut self, Algorithm) -> Result<(&AeadCipher, u64), CryptoError>` (returns `(cipher_ref, switch_overhead_ns)`).

- [ ] **Step 1: Update `.gitignore` and write failing unit tests in `src/crypto.rs` (via initial module skeleton)**

Update `.gitignore`:
```text
/target/
/target-soft/
/bench_tmp/
/results/
```

Create `src/crypto.rs` containing the existing Stage 1 primitives (`Algorithm`, `CryptoError`, `SecurityPolicy`, `AeadCipher`, `NonceGenerator`) plus failing tests for the new `Algorithm::id`/`from_id`, `KeyRing`, and `CipherCache` APIs (stubbing `KeyRing` and `CipherCache` with `unimplemented!()` or missing behavior so `cargo test` fails first):

```rust
// At bottom of src/crypto.rs:
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_id_roundtrip() {
        for alg in Algorithm::ALL {
            assert_eq!(Algorithm::from_id(alg.id()), Ok(alg));
        }
        assert_eq!(Algorithm::from_id(0), Err(CryptoError::UnknownAlgorithmId(0)));
        assert_eq!(Algorithm::from_id(99), Err(CryptoError::UnknownAlgorithmId(99)));
    }

    #[test]
    fn keyring_slices_exact_lengths() {
        let ring = KeyRing::deterministic_benchmark();
        assert_eq!(ring.key_for(Algorithm::Aes128Gcm).len(), 16);
        assert_eq!(ring.key_for(Algorithm::ChaCha20Poly1305).len(), 32);
        assert_eq!(ring.key_for(Algorithm::AsconAead128).len(), 16);
    }

    #[test]
    fn cipher_cache_reports_zero_switch_cost_when_reused() {
        let ring = KeyRing::deterministic_benchmark();
        let mut cache = CipherCache::new(&ring);
        let (c1, cost1) = cache.prepare(Algorithm::Aes128Gcm).unwrap();
        assert_eq!(c1.algorithm(), Algorithm::Aes128Gcm);
        assert!(cost1 > 0 || cost1 == 0); // initial creation timed
        let (c2, cost2) = cache.prepare(Algorithm::Aes128Gcm).unwrap();
        assert_eq!(c2.algorithm(), Algorithm::Aes128Gcm);
        assert_eq!(cost2, 0);
        let (c3, _) = cache.prepare(Algorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(c3.algorithm(), Algorithm::ChaCha20Poly1305);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test --lib crypto::tests"
```
Expected: FAIL (compile error because `Algorithm::id`, `KeyRing`, `CipherCache` are not implemented yet).

- [ ] **Step 3: Implement `src/crypto.rs` and re-export from `src/lib.rs`**

Write `src/crypto.rs`:
```rust
//! Core AEAD engine, security policy, key ring, and cipher cache primitives.

use aead::{AeadInOut, KeyInit, array::Array};
use aes_gcm::Aes128Gcm;
use ascon_aead128::AsconAead128;
use chacha20poly1305::ChaCha20Poly1305;
use std::fmt;
use std::time::Instant;

/// Supported authenticated encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Aes128Gcm,
    ChaCha20Poly1305,
    AsconAead128,
}

impl Algorithm {
    /// All candidate algorithms evaluated in this study.
    pub const ALL: [Algorithm; 3] = [
        Algorithm::Aes128Gcm,
        Algorithm::ChaCha20Poly1305,
        Algorithm::AsconAead128,
    ];

    /// Canonical wire identifier used in the self-describing file envelope.
    pub const fn id(self) -> u8 {
        match self {
            Algorithm::Aes128Gcm => 1,
            Algorithm::ChaCha20Poly1305 => 2,
            Algorithm::AsconAead128 => 3,
        }
    }

    /// Parses an algorithm from its wire identifier.
    pub const fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(Algorithm::Aes128Gcm),
            2 => Ok(Algorithm::ChaCha20Poly1305),
            3 => Ok(Algorithm::AsconAead128),
            _ => Err(CryptoError::UnknownAlgorithmId(id)),
        }
    }

    /// Human-readable canonical algorithm name.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Aes128Gcm => "AES-128-GCM",
            Algorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Algorithm::AsconAead128 => "Ascon-AEAD128",
        }
    }

    /// Governing cryptographic standard identifier.
    pub const fn standard(self) -> &'static str {
        match self {
            Algorithm::Aes128Gcm => "NIST SP 800-38D",
            Algorithm::ChaCha20Poly1305 => "IETF RFC 8439",
            Algorithm::AsconAead128 => "NIST SP 800-232",
        }
    }

    /// Required secret key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::ChaCha20Poly1305 => 32,
            Algorithm::AsconAead128 => 16,
        }
    }

    /// Required nonce/IV length in bytes.
    pub const fn nonce_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 12,
            Algorithm::AsconAead128 => 16,
        }
    }

    /// Authentication tag length in bytes.
    pub const fn tag_len(self) -> usize {
        16
    }

    /// Effective symmetric security strength in bits.
    pub const fn security_bits(self) -> u16 {
        match self {
            Algorithm::Aes128Gcm => 128,
            Algorithm::ChaCha20Poly1305 => 256,
            Algorithm::AsconAead128 => 128,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Errors produced by security constraint validation, envelope parsing, or AEAD operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    PolicyViolation(&'static str),
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidNonceLength { expected: usize, actual: usize },
    AeadFailure,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnknownAlgorithmId(u8),
    TruncatedEnvelope,
    InvalidNonceField,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::PolicyViolation(reason) => write!(f, "security policy violation: {reason}"),
            CryptoError::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected} bytes, got {actual}")
            }
            CryptoError::InvalidNonceLength { expected, actual } => {
                write!(f, "invalid nonce length: expected {expected} bytes, got {actual}")
            }
            CryptoError::AeadFailure => write!(f, "AEAD encryption/authentication failure"),
            CryptoError::InvalidMagic => write!(f, "invalid envelope magic header"),
            CryptoError::UnsupportedVersion(v) => write!(f, "unsupported envelope version: {v}"),
            CryptoError::UnknownAlgorithmId(id) => write!(f, "unknown algorithm identifier: {id}"),
            CryptoError::TruncatedEnvelope => write!(f, "envelope shorter than minimum header/tag"),
            CryptoError::InvalidNonceField => write!(f, "envelope nonce length mismatch"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Security eligibility constraint enforced prior to algorithm selection and decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub min_security_bits: u16,
    pub min_tag_len_bytes: usize,
    pub require_standard_compliance: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            min_security_bits: 128,
            min_tag_len_bytes: 16,
            require_standard_compliance: true,
        }
    }
}

impl SecurityPolicy {
    /// Checks whether a candidate algorithm satisfies all security requirements.
    pub fn validate(&self, alg: Algorithm) -> Result<(), CryptoError> {
        if alg.security_bits() < self.min_security_bits {
            return Err(CryptoError::PolicyViolation("security strength below minimum"));
        }
        if alg.tag_len() < self.min_tag_len_bytes {
            return Err(CryptoError::PolicyViolation("authentication tag shorter than policy"));
        }
        if self.require_standard_compliance && alg.standard().is_empty() {
            return Err(CryptoError::PolicyViolation("missing standard specification"));
        }
        Ok(())
    }

    /// Returns all algorithms eligible under this security policy.
    pub fn eligible_algorithms(&self) -> Vec<Algorithm> {
        Algorithm::ALL
            .into_iter()
            .filter(|&alg| self.validate(alg).is_ok())
            .collect()
    }
}

/// 256-bit key material provider sliced uniformly per AEAD candidate.
#[derive(Debug, Clone)]
pub struct KeyRing {
    master: [u8; 32],
}

impl KeyRing {
    /// Wraps an explicit 32-byte key buffer.
    pub const fn new(master: [u8; 32]) -> Self {
        Self { master }
    }

    /// Deterministic key material used exclusively for reproducible benchmark evaluation.
    pub fn deterministic_benchmark() -> Self {
        let mut master = [0u8; 32];
        for (i, b) in master.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        Self { master }
    }

    /// Returns the exact key slice required by `alg`.
    pub fn key_for(&self, alg: Algorithm) -> &[u8] {
        &self.master[..alg.key_len()]
    }
}

/// Uniform runtime AEAD cipher wrapper supporting dynamic algorithm switching.
pub enum AeadCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
    AsconAead128(Box<AsconAead128>),
}

impl AeadCipher {
    /// Initializes an AEAD cipher instance from raw key bytes.
    pub fn new(alg: Algorithm, key: &[u8]) -> Result<Self, CryptoError> {
        let expected = alg.key_len();
        if key.len() != expected {
            return Err(CryptoError::InvalidKeyLength {
                expected,
                actual: key.len(),
            });
        }

        Ok(match alg {
            Algorithm::Aes128Gcm => {
                let k = Array::try_from(key).map_err(|_| CryptoError::InvalidKeyLength {
                    expected,
                    actual: key.len(),
                })?;
                Self::Aes128Gcm(Box::new(Aes128Gcm::new(&k)))
            }
            Algorithm::ChaCha20Poly1305 => {
                let k = Array::try_from(key).map_err(|_| CryptoError::InvalidKeyLength {
                    expected,
                    actual: key.len(),
                })?;
                Self::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new(&k)))
            }
            Algorithm::AsconAead128 => {
                let k = Array::try_from(key).map_err(|_| CryptoError::InvalidKeyLength {
                    expected,
                    actual: key.len(),
                })?;
                Self::AsconAead128(Box::new(AsconAead128::new(&k)))
            }
        })
    }

    /// Returns the algorithm corresponding to this initialized instance.
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Aes128Gcm(_) => Algorithm::Aes128Gcm,
            Self::ChaCha20Poly1305(_) => Algorithm::ChaCha20Poly1305,
            Self::AsconAead128(_) => Algorithm::AsconAead128,
        }
    }

    /// Encrypts `buffer` in-place, appending the 16-byte authentication tag.
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let expected = self.algorithm().nonce_len();
        if nonce.len() != expected {
            return Err(CryptoError::InvalidNonceLength {
                expected,
                actual: nonce.len(),
            });
        }

        match self {
            Self::Aes128Gcm(c) => {
                let n = Array::try_from(nonce).map_err(|_| CryptoError::AeadFailure)?;
                c.encrypt_in_place(&n, aad, buffer)
                    .map_err(|_| CryptoError::AeadFailure)
            }
            Self::ChaCha20Poly1305(c) => {
                let n = Array::try_from(nonce).map_err(|_| CryptoError::AeadFailure)?;
                c.encrypt_in_place(&n, aad, buffer)
                    .map_err(|_| CryptoError::AeadFailure)
            }
            Self::AsconAead128(c) => {
                let n = Array::try_from(nonce).map_err(|_| CryptoError::AeadFailure)?;
                c.encrypt_in_place(&n, aad, buffer)
                    .map_err(|_| CryptoError::AeadFailure)
            }
        }
    }

    /// Decrypts and authenticates `buffer` in-place, truncating the trailing 16-byte tag.
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let expected = self.algorithm().nonce_len();
        if nonce.len() != expected {
            return Err(CryptoError::InvalidNonceLength {
                expected,
                actual: nonce.len(),
            });
        }

        match self {
            Self::Aes128Gcm(c) => {
                let n = Array::try_from(nonce).map_err(|_| CryptoError::AeadFailure)?;
                c.decrypt_in_place(&n, aad, buffer)
                    .map_err(|_| CryptoError::AeadFailure)
            }
            Self::ChaCha20Poly1305(c) => {
                let n = Array::try_from(nonce).map_err(|_| CryptoError::AeadFailure)?;
                c.decrypt_in_place(&n, aad, buffer)
                    .map_err(|_| CryptoError::AeadFailure)
            }
            Self::AsconAead128(c) => {
                let n = Array::try_from(nonce).map_err(|_| CryptoError::AeadFailure)?;
                c.decrypt_in_place(&n, aad, buffer)
                    .map_err(|_| CryptoError::AeadFailure)
            }
        }
    }
}

/// Active-cipher cache that re-initializes only on algorithm transitions and times switch cost.
pub struct CipherCache {
    keys: KeyRing,
    active: Option<AeadCipher>,
}

impl CipherCache {
    pub fn new(keys: &KeyRing) -> Self {
        Self {
            keys: keys.clone(),
            active: None,
        }
    }

    /// Ensures `alg` is active, returning the cipher reference and real switch overhead in ns.
    pub fn prepare(&mut self, alg: Algorithm) -> Result<(&AeadCipher, u64), CryptoError> {
        let needs_init = match &self.active {
            Some(cipher) => cipher.algorithm() != alg,
            None => true,
        };

        let mut switch_ns = 0u64;
        if needs_init {
            let t0 = Instant::now();
            let cipher = AeadCipher::new(alg, self.keys.key_for(alg))?;
            switch_ns = t0.elapsed().as_nanos() as u64;
            self.active = Some(cipher);
        }

        let cipher = self
            .active
            .as_ref()
            .ok_or(CryptoError::AeadFailure)?;
        Ok((cipher, switch_ns))
    }
}

/// Deterministic counter-based nonce builder ensuring uniqueness per encryption under a fixed key.
#[derive(Debug, Default)]
pub struct NonceGenerator {
    counter: u64,
}

impl NonceGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Fills a caller-provided slice with a unique domain-separated nonce and advances the counter.
    pub fn next_into(&mut self, dst: &mut [u8]) {
        dst.fill(0);
        let bytes = self.counter.to_le_bytes();
        let copy_len = dst.len().min(bytes.len());
        dst[..copy_len].copy_from_slice(&bytes[..copy_len]);
        self.counter = self.counter.wrapping_add(1);
    }
}
```

Update `src/lib.rs`:
```rust
//! Adaptive AEAD library: cryptographic facade, self-describing envelope,
//! workload profiler, hysteresis selector, and trace evaluator.

pub mod crypto;

pub use crypto::{
    AeadCipher, Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy,
};
```

- [ ] **Step 4: Run tests to verify `crypto` unit tests and existing `test_vectors` pass**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test"
```
Expected: All unit tests in `crypto::tests` and all 4 integration tests in `tests/test_vectors.rs` PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead add .gitignore src/crypto.rs src/lib.rs
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead commit -m "refactor: extract crypto primitives and add KeyRing and CipherCache"
```

---

### Task 2: Self-Describing Encrypted File Envelope (`src/envelope.rs`)

**Files:**
- Create: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/envelope.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/lib.rs`
- Create: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/tests/stage2_tests.rs`

**Interfaces:**
- Consumes: `AeadCipher`, `Algorithm`, `CryptoError`, `KeyRing`, `SecurityPolicy`.
- Produces:
  - `pub const ENVELOPE_MAGIC: [u8; 4] = *b"AAED";`
  - `pub const ENVELOPE_VERSION: u8 = 1;`
  - `pub const FIXED_HEADER_LEN: usize = 8;`
  - `pub struct EnvelopeHeader { pub version: u8, pub alg: Algorithm, pub flags: u8, pub nonce: Vec<u8> }`
  - `pub fn seal_envelope(cipher: &AeadCipher, nonce: &[u8], user_aad: &[u8], payload_in_out: &mut Vec<u8>) -> Result<(), CryptoError>` (encrypts `payload_in_out` and prepends the `8 + nonce.len()` header in-place or via buffer swap, binding `header_bytes || user_aad` as AAD)
  - `pub fn parse_header(data: &[u8]) -> Result<(EnvelopeHeader, usize), CryptoError>`
  - `pub fn open_envelope(keys: &KeyRing, policy: &SecurityPolicy, user_aad: &[u8], envelope_in_out: &mut Vec<u8>) -> Result<Algorithm, CryptoError>`

- [ ] **Step 1: Write failing envelope tests in `tests/stage2_tests.rs`**

Create `tests/stage2_tests.rs`:
```rust
use adaptive_aead::envelope::{
    ENVELOPE_MAGIC, ENVELOPE_VERSION, FIXED_HEADER_LEN, open_envelope, parse_header,
    seal_envelope,
};
use adaptive_aead::{AeadCipher, Algorithm, CryptoError, KeyRing, NonceGenerator, SecurityPolicy};

#[test]
fn envelope_roundtrip_all_algorithms() {
    let keys = KeyRing::deterministic_benchmark();
    let policy = SecurityPolicy::default();
    let mut nonces = NonceGenerator::new();

    for alg in Algorithm::ALL {
        for size in [0usize, 1, 64, 4096] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut nonce = vec![0u8; alg.nonce_len()];
            nonces.next_into(&mut nonce);

            let cipher = AeadCipher::new(alg, keys.key_for(alg)).unwrap();
            let mut buf = plaintext.clone();
            seal_envelope(&cipher, &nonce, b"file-meta", &mut buf).unwrap();

            let (hdr, hdr_len) = parse_header(&buf).unwrap();
            assert_eq!(hdr.version, ENVELOPE_VERSION);
            assert_eq!(hdr.alg, alg);
            assert_eq!(hdr.nonce, nonce);
            assert_eq!(hdr_len, FIXED_HEADER_LEN + alg.nonce_len());
            assert_eq!(buf.len(), hdr_len + size + alg.tag_len());

            let used_alg = open_envelope(&keys, &policy, b"file-meta", &mut buf).unwrap();
            assert_eq!(used_alg, alg);
            assert_eq!(buf, plaintext);
        }
    }
}

#[test]
fn envelope_rejects_header_tampering_and_policy_violation() {
    let keys = KeyRing::deterministic_benchmark();
    let policy_128 = SecurityPolicy::default();
    let policy_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };

    let cipher = AeadCipher::new(Algorithm::Aes128Gcm, keys.key_for(Algorithm::Aes128Gcm)).unwrap();
    let nonce = [0x11u8; 12];
    let original = b"sensitive payload".to_vec();

    let mut sealed = original.clone();
    seal_envelope(&cipher, &nonce, b"aad", &mut sealed).unwrap();
    assert_eq!(&sealed[0..4], &ENVELOPE_MAGIC);

    // 1. Policy violation must fail closed before decryption
    let mut for_policy = sealed.clone();
    assert_eq!(
        open_envelope(&keys, &policy_256, b"aad", &mut for_policy),
        Err(CryptoError::PolicyViolation("security strength below minimum"))
    );

    // 2. Tampering flags byte in header must trigger AeadFailure via bound AAD
    let mut tampered_flags = sealed.clone();
    tampered_flags[7] ^= 0x01;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut tampered_flags),
        Err(CryptoError::AeadFailure)
    );

    // 3. Invalid magic
    let mut bad_magic = sealed.clone();
    bad_magic[0] = b'X';
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut bad_magic),
        Err(CryptoError::InvalidMagic)
    );

    // 4. Unsupported version
    let mut bad_ver = sealed.clone();
    bad_ver[4] = 99;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut bad_ver),
        Err(CryptoError::UnsupportedVersion(99))
    );

    // 5. Unknown algorithm ID
    let mut bad_alg = sealed.clone();
    bad_alg[5] = 42;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut bad_alg),
        Err(CryptoError::UnknownAlgorithmId(42))
    );

    // 6. Wrong user AAD
    let mut wrong_aad = sealed;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"wrong", &mut wrong_aad),
        Err(CryptoError::AeadFailure)
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test --test stage2_tests"
```
Expected: FAIL because `envelope` module does not exist yet.

- [ ] **Step 3: Implement `src/envelope.rs` and expose it in `src/lib.rs`**

Write `src/envelope.rs`:
```rust
//! Self-describing encrypted file envelope with AAD-authenticated header binding.

use crate::crypto::{AeadCipher, Algorithm, CryptoError, KeyRing, SecurityPolicy};

pub const ENVELOPE_MAGIC: [u8; 4] = *b"AAED";
pub const ENVELOPE_VERSION: u8 = 1;
pub const FIXED_HEADER_LEN: usize = 8;

/// Parsed header from a self-describing encrypted envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub version: u8,
    pub alg: Algorithm,
    pub flags: u8,
    pub nonce: Vec<u8>,
}

fn build_bound_aad(header_bytes: &[u8], user_aad: &[u8]) -> Vec<u8> {
    let mut bound = Vec::with_capacity(header_bytes.len() + user_aad.len());
    bound.extend_from_slice(header_bytes);
    bound.extend_from_slice(user_aad);
    bound
}

/// Encrypts `buffer` in-place and prepends the self-describing header.
/// The entire header (`FIXED_HEADER_LEN + nonce.len()`) is bound into AEAD AAD.
pub fn seal_envelope(
    cipher: &AeadCipher,
    nonce: &[u8],
    user_aad: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    let alg = cipher.algorithm();
    let expected_nonce_len = alg.nonce_len();
    if nonce.len() != expected_nonce_len {
        return Err(CryptoError::InvalidNonceLength {
            expected: expected_nonce_len,
            actual: nonce.len(),
        });
    }

    let header_len = FIXED_HEADER_LEN + nonce.len();
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(&ENVELOPE_MAGIC);
    header.push(ENVELOPE_VERSION);
    header.push(alg.id());
    header.push(nonce.len() as u8);
    header.push(0x00); // flags reserved
    header.extend_from_slice(nonce);

    let bound_aad = build_bound_aad(&header, user_aad);
    cipher.encrypt_in_place(nonce, &bound_aad, buffer)?;

    let ct_len = buffer.len();
    buffer.resize(ct_len + header_len, 0);
    buffer.copy_within(0..ct_len, header_len);
    buffer[..header_len].copy_from_slice(&header);
    Ok(())
}

/// Parses and validates an envelope header without decrypting the payload.
pub fn parse_header(data: &[u8]) -> Result<(EnvelopeHeader, usize), CryptoError> {
    if data.len() < FIXED_HEADER_LEN {
        return Err(CryptoError::TruncatedEnvelope);
    }
    if data[0..4] != ENVELOPE_MAGIC {
        return Err(CryptoError::InvalidMagic);
    }
    let version = data[4];
    if version != ENVELOPE_VERSION {
        return Err(CryptoError::UnsupportedVersion(version));
    }
    let alg = Algorithm::from_id(data[5])?;
    let nonce_len = data[6] as usize;
    if nonce_len != alg.nonce_len() {
        return Err(CryptoError::InvalidNonceField);
    }
    let flags = data[7];
    let header_len = FIXED_HEADER_LEN + nonce_len;
    if data.len() < header_len + alg.tag_len() {
        return Err(CryptoError::TruncatedEnvelope);
    }

    let nonce = data[FIXED_HEADER_LEN..header_len].to_vec();
    Ok((
        EnvelopeHeader {
            version,
            alg,
            flags,
            nonce,
        },
        header_len,
    ))
}

/// Validates security policy, verifies header + payload authenticity, and decrypts in-place.
pub fn open_envelope(
    keys: &KeyRing,
    policy: &SecurityPolicy,
    user_aad: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<Algorithm, CryptoError> {
    let (header, header_len) = parse_header(buffer)?;
    policy.validate(header.alg)?;

    let bound_aad = build_bound_aad(&buffer[..header_len], user_aad);
    let cipher = AeadCipher::new(header.alg, keys.key_for(header.alg))?;

    let ct_len = buffer.len() - header_len;
    buffer.copy_within(header_len.., 0);
    buffer.truncate(ct_len);

    cipher.decrypt_in_place(&header.nonce, &bound_aad, buffer)?;
    Ok(header.alg)
}
```

Add `pub mod envelope;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test"
```
Expected: All tests in `crypto::tests`, `tests/test_vectors.rs`, and `tests/stage2_tests.rs` PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead add src/envelope.rs src/lib.rs tests/stage2_tests.rs
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead commit -m "feat: add self-describing AEAD file envelope with AAD binding"
```

---

### Task 3: Workload Buckets, Calibration & Online EMA Telemetry (`src/profile.rs`)

**Files:**
- Create: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/profile.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/lib.rs`

**Interfaces:**
- Consumes: `AeadCipher`, `Algorithm`, `CryptoError`, `KeyRing`, `NonceGenerator`.
- Produces:
  - `pub enum WorkloadBucket { Tiny, Small, Medium, Large, Bulk }` (`WorkloadBucket::from_size(usize)`, `WorkloadBucket::ALL`, `WorkloadBucket::rep_size_bytes(self) -> usize`, `WorkloadBucket::name(self) -> &'static str`)
  - `pub struct RuntimeProfile`
  - `RuntimeProfile::from_rates(alpha: f64, rates: [[f64; 3]; 5]) -> Self`
  - `RuntimeProfile::calibrate(keys: &KeyRing, alpha: f64) -> Result<Self, CryptoError>`
  - `RuntimeProfile::ns_per_byte(&self, bucket: WorkloadBucket, alg: Algorithm) -> f64`
  - `RuntimeProfile::predicted_ns(&self, alg: Algorithm, size_bytes: usize) -> f64`
  - `RuntimeProfile::observe(&mut self, alg: Algorithm, size_bytes: usize, observed_ns: f64)`

- [ ] **Step 1: Write failing unit tests in `src/profile.rs`**

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test --lib profile::tests"
```
Expected: FAIL (`profile` module missing).

- [ ] **Step 3: Implement `src/profile.rs` and expose it in `src/lib.rs`**

Write `src/profile.rs`:
```rust
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
```

Add `pub mod profile;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test"
```
Expected: All tests pass.

- [ ] **Step 5: Commit Task 3**

```bash
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead add src/profile.rs src/lib.rs
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead commit -m "feat: add workload buckets, startup calibration, and online EMA profiler"
```

---

### Task 4: Adaptive Selector & Hysteresis Engine (`src/selector.rs`)

**Files:**
- Create: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/selector.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/lib.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/tests/stage2_tests.rs`

**Interfaces:**
- Consumes: `Algorithm`, `CryptoError`, `SecurityPolicy`, `RuntimeProfile`.
- Produces:
  - `pub enum SelectionPolicy { Static(Algorithm), Adaptive, AdaptiveHysteresis { delta: f64 } }`
  - `SelectionPolicy::label(&self) -> String`
  - `pub enum SwitchReason { Initial, AlreadyOptimal, HysteresisHeld, ThresholdExceeded, SecurityOverride, StaticFixed }`
  - `pub struct SelectionDecision { pub chosen: Algorithm, pub switched: bool, pub reason: SwitchReason, pub relative_gain: f64 }`
  - `pub struct AdaptiveSelector`
  - `AdaptiveSelector::new(SelectionPolicy, RuntimeProfile)`
  - `AdaptiveSelector::select_for(&mut self, size_bytes: usize, security: &SecurityPolicy) -> Result<SelectionDecision, CryptoError>`
  - `AdaptiveSelector::observe(&mut self, alg: Algorithm, size_bytes: usize, observed_ns: f64)`
  - `AdaptiveSelector::active(&self) -> Option<Algorithm>`

- [ ] **Step 1: Write failing selector & hysteresis tests in `tests/stage2_tests.rs`**

Append to `tests/stage2_tests.rs`:
```rust
use adaptive_aead::profile::RuntimeProfile;
use adaptive_aead::selector::{AdaptiveSelector, SelectionPolicy, SwitchReason};

fn synthetic_profile() -> RuntimeProfile {
    // Rates (ns/byte) per bucket [AES-128-GCM, ChaCha20-Poly1305, Ascon-AEAD128]
    // Tiny: Ascon fastest (2.0), AES (3.0), ChaCha20 (10.0)
    // Small: AES fastest (2.0), ChaCha20 (2.2), Ascon (5.0)
    // Medium: ChaCha20 fastest (1.0), AES (1.15 -> 13% slower than ChaCha20), Ascon (4.0)
    let rates = [
        [3.0, 10.0, 2.0], // Tiny
        [2.0, 2.2, 5.0],  // Small
        [1.15, 1.0, 4.0], // Medium
        [1.0, 1.2, 4.0],  // Large
        [1.0, 1.2, 4.0],  // Bulk
    ];
    RuntimeProfile::from_rates(0.2, rates)
}

#[test]
fn hysteresis_holds_below_delta_and_switches_above_delta() {
    let sec = SecurityPolicy::default();

    // Delta = 0.20 (20%)
    let mut sel = AdaptiveSelector::new(
        SelectionPolicy::AdaptiveHysteresis { delta: 0.20 },
        synthetic_profile(),
    );

    // 1. First file (Small, 4096 B) -> picks AES-128-GCM (2.0 vs 2.2)
    let d1 = sel.select_for(4096, &sec).unwrap();
    assert_eq!(d1.chosen, Algorithm::Aes128Gcm);
    assert_eq!(d1.reason, SwitchReason::Initial);

    // 2. Medium (65536 B): ChaCha20 is 1.0 vs AES 1.15 -> gain = (1.15 - 1.0) / 1.15 ≈ 0.1304 <= 0.20 -> HOLD
    let d2 = sel.select_for(65_536, &sec).unwrap();
    assert_eq!(d2.chosen, Algorithm::Aes128Gcm);
    assert!(!d2.switched);
    assert_eq!(d2.reason, SwitchReason::HysteresisHeld);

    // 3. Tiny (256 B): Ascon is 2.0 vs AES 3.0 -> gain = (3.0 - 2.0) / 3.0 ≈ 0.3333 > 0.20 -> SWITCH
    let d3 = sel.select_for(256, &sec).unwrap();
    assert_eq!(d3.chosen, Algorithm::AsconAead128);
    assert!(d3.switched);
    assert_eq!(d3.reason, SwitchReason::ThresholdExceeded);
}

#[test]
fn security_policy_upgrade_overrides_hysteresis_immediately() {
    let sec_128 = SecurityPolicy::default();
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };

    // High delta (0.95) that would normally block any performance switch
    let mut sel = AdaptiveSelector::new(
        SelectionPolicy::AdaptiveHysteresis { delta: 0.95 },
        synthetic_profile(),
    );

    let d1 = sel.select_for(256, &sec_128).unwrap();
    assert_eq!(d1.chosen, Algorithm::AsconAead128);

    // Policy tightens to 256-bit -> Ascon invalid -> must force switch to ChaCha20-Poly1305
    let d2 = sel.select_for(256, &sec_256).unwrap();
    assert_eq!(d2.chosen, Algorithm::ChaCha20Poly1305);
    assert!(d2.switched);
    assert_eq!(d2.reason, SwitchReason::SecurityOverride);
}

#[test]
fn static_policy_rejects_ineligible_security_constraint() {
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };
    let mut sel = AdaptiveSelector::new(
        SelectionPolicy::Static(Algorithm::Aes128Gcm),
        synthetic_profile(),
    );
    assert_eq!(
        sel.select_for(1024, &sec_256),
        Err(CryptoError::PolicyViolation("security strength below minimum"))
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test --test stage2_tests"
```
Expected: FAIL (`selector` module missing).

- [ ] **Step 3: Implement `src/selector.rs` and expose it in `src/lib.rs`**

Write `src/selector.rs`:
```rust
//! Security-constrained adaptive AEAD selector with relative hysteresis.

use crate::crypto::{Algorithm, CryptoError, SecurityPolicy};
use crate::profile::RuntimeProfile;

/// Selection strategy evaluated in experiments.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SelectionPolicy {
    Static(Algorithm),
    Adaptive,
    AdaptiveHysteresis { delta: f64 },
}

impl SelectionPolicy {
    pub fn label(&self) -> String {
        match self {
            Self::Static(alg) => format!("Static({})", alg.name()),
            Self::Adaptive => "Adaptive(d=0.00)".to_string(),
            Self::AdaptiveHysteresis { delta } => format!("Adaptive+Hyst(d={delta:.2})"),
        }
    }

    pub const fn delta(&self) -> f64 {
        match self {
            Self::Static(_) | Self::Adaptive => 0.0,
            Self::AdaptiveHysteresis { delta } => *delta,
        }
    }
}

/// Explanation for why the selector kept or switched the active algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    Initial,
    AlreadyOptimal,
    HysteresisHeld,
    ThresholdExceeded,
    SecurityOverride,
    StaticFixed,
}

/// Result of a per-file selection step.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectionDecision {
    pub chosen: Algorithm,
    pub switched: bool,
    pub reason: SwitchReason,
    pub relative_gain: f64,
}

/// Stateful selector combining calibrated/EMA profiling, security gate, and hysteresis.
#[derive(Debug, Clone)]
pub struct AdaptiveSelector {
    policy: SelectionPolicy,
    profile: RuntimeProfile,
    active: Option<Algorithm>,
}

impl AdaptiveSelector {
    pub fn new(policy: SelectionPolicy, profile: RuntimeProfile) -> Self {
        Self {
            policy,
            profile,
            active: None,
        }
    }

    pub const fn active(&self) -> Option<Algorithm> {
        self.active
    }

    pub const fn policy(&self) -> SelectionPolicy {
        self.policy
    }

    /// Selects the algorithm for an upcoming file of `size_bytes` under `security`.
    pub fn select_for(
        &mut self,
        size_bytes: usize,
        security: &SecurityPolicy,
    ) -> Result<SelectionDecision, CryptoError> {
        if let SelectionPolicy::Static(fixed) = self.policy {
            security.validate(fixed)?;
            let switched = matches!(self.active, Some(prev) if prev != fixed);
            self.active = Some(fixed);
            return Ok(SelectionDecision {
                chosen: fixed,
                switched,
                reason: SwitchReason::StaticFixed,
                relative_gain: 0.0,
            });
        }

        let eligible = security.eligible_algorithms();
        if eligible.is_empty() {
            return Err(CryptoError::PolicyViolation("no eligible algorithms satisfy policy"));
        }

        let (best, best_cost) = eligible
            .iter()
            .copied()
            .map(|alg| (alg, self.profile.predicted_ns(alg, size_bytes)))
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .ok_or(CryptoError::PolicyViolation("no eligible algorithms satisfy policy"))?;

        let Some(current) = self.active else {
            self.active = Some(best);
            return Ok(SelectionDecision {
                chosen: best,
                switched: false,
                reason: SwitchReason::Initial,
                relative_gain: 0.0,
            });
        };

        if security.validate(current).is_err() {
            self.active = Some(best);
            return Ok(SelectionDecision {
                chosen: best,
                switched: current != best,
                reason: SwitchReason::SecurityOverride,
                relative_gain: 1.0,
            });
        }

        if best == current {
            return Ok(SelectionDecision {
                chosen: current,
                switched: false,
                reason: SwitchReason::AlreadyOptimal,
                relative_gain: 0.0,
            });
        }

        let current_cost = self.profile.predicted_ns(current, size_bytes);
        let relative_gain = if current_cost > 0.0 {
            (current_cost - best_cost) / current_cost
        } else {
            0.0
        };

        let delta = self.policy.delta();
        if relative_gain > delta {
            self.active = Some(best);
            Ok(SelectionDecision {
                chosen: best,
                switched: true,
                reason: SwitchReason::ThresholdExceeded,
                relative_gain,
            })
        } else {
            Ok(SelectionDecision {
                chosen: current,
                switched: false,
                reason: SwitchReason::HysteresisHeld,
                relative_gain,
            })
        }
    }

    /// Feeds real observed latency back into the online EMA profile.
    pub fn observe(&mut self, alg: Algorithm, size_bytes: usize, observed_ns: f64) {
        self.profile.observe(alg, size_bytes, observed_ns);
    }
}
```

Add `pub mod selector;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test"
```
Expected: All tests in `crypto::tests`, `profile::tests`, `tests/test_vectors.rs`, and `tests/stage2_tests.rs` PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead add src/selector.rs src/lib.rs tests/stage2_tests.rs
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead commit -m "feat: add security-constrained adaptive selector and hysteresis engine"
```

---

### Task 5: Mixed-Workload & Policy-Shift Trace Evaluator + CLI (`src/workload.rs`, `src/main.rs`)

**Files:**
- Create: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/workload.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/lib.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/src/main.rs`
- Modify: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/tests/stage2_tests.rs`

**Interfaces:**
- Consumes: `crypto::{Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy}`, `envelope::{open_envelope, seal_envelope}`, `profile::RuntimeProfile`, `selector::{AdaptiveSelector, SelectionPolicy, SwitchReason}`.
- Produces:
  - `pub enum TraceKind { MixedBurst, PolicyShift }` (`name(&self) -> &'static str`)
  - `pub struct TraceStep { pub step: usize, pub size_bytes: usize, pub policy: SecurityPolicy }`
  - `pub struct PolicyEvalSummary` (all 7 metrics + `policy_compliant`, `policy_violations`, `total_bytes`)
  - `pub struct TimelineRecord` (per-step `trace`, `profile_mode`, `policy_label`, `step`, `size_bytes`, `min_security_bits`, `chosen_alg`, `switched`, `reason`, `enc_ns`, `dec_ns`, `switch_ns`, `oracle_ns`)
  - `pub fn build_mixed_burst_trace() -> Vec<TraceStep>` (120 steps)
  - `pub fn build_policy_shift_trace() -> Vec<TraceStep>` (90 steps)
  - `pub fn run_evaluation(profile_label: &str, traces: &[(TraceKind, Vec<TraceStep>)], work_dir: &Path) -> Result<(Vec<PolicyEvalSummary>, Vec<TimelineRecord>), CryptoError>`
  - `pub fn write_evaluation_csvs(results_dir: &Path, profile_label: &str, summaries: &[PolicyEvalSummary], timeline: &[TimelineRecord]) -> std::io::Result<()>`
  - `src/main.rs` CLI supporting `pilot` (runs Stage 1 benchmark unchanged) and `evaluate --profile <native|soft>` (runs Stage 2 evaluation and writes `results/eval_<profile>.csv` and `results/eval_<profile>_timeline.csv`).

- [ ] **Step 1: Write failing trace & evaluator integration test in `tests/stage2_tests.rs`**

Append to `tests/stage2_tests.rs`:
```rust
use adaptive_aead::workload::{
    TraceKind, TraceStep, build_mixed_burst_trace, build_policy_shift_trace, run_evaluation,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn evaluator_runs_mini_trace_and_respects_policy_shift() {
    let mixed = build_mixed_burst_trace();
    let shifted = build_policy_shift_trace();
    assert_eq!(mixed.len(), 120);
    assert_eq!(shifted.len(), 90);

    // Mini 12-step policy-shift trace for fast integration verification
    let sec_128 = SecurityPolicy::default();
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };
    let mini_trace: Vec<TraceStep> = (0..12)
        .map(|i| TraceStep {
            step: i,
            size_bytes: if i % 2 == 0 { 256 } else { 16 * 1024 },
            policy: if (4..8).contains(&i) { sec_256 } else { sec_128 },
        })
        .collect();

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let tmp = std::env::temp_dir().join(format!("adaptive_aead_test_{stamp}"));
    let (summaries, timeline) =
        run_evaluation("test", &[(TraceKind::PolicyShift, mini_trace)], &tmp).unwrap();
    let _ = std::fs::remove_dir_all(&tmp);

    // 3 Static + 1 Adaptive(d=0) + 5 Hysteresis(0.05..0.35) = 9 policies
    assert_eq!(summaries.len(), 9);
    assert!(!timeline.is_empty());

    let static_aes = summaries
        .iter()
        .find(|s| s.policy_label == "Static(AES-128-GCM)")
        .unwrap();
    assert!(!static_aes.policy_compliant);
    assert_eq!(static_aes.policy_violations, 4);

    let adaptive_zero = summaries
        .iter()
        .find(|s| s.policy_label == "Adaptive(d=0.00)")
        .unwrap();
    let adaptive_max_hyst = summaries
        .iter()
        .find(|s| s.policy_label == "Adaptive+Hyst(d=0.35)")
        .unwrap();
    assert!(adaptive_zero.policy_compliant);
    assert!(adaptive_max_hyst.policy_compliant);
    assert!(adaptive_max_hyst.switch_count <= adaptive_zero.switch_count);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test --test stage2_tests"
```
Expected: FAIL (`workload` module missing).

- [ ] **Step 3: Implement `src/workload.rs`, export in `src/lib.rs`, and update `src/main.rs` CLI**

Write `src/workload.rs`:
```rust
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
                // Verify envelope integrity using step policy when compliant, or permissive policy on flagged static baselines
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
```

Add `pub mod workload;` to `src/lib.rs`, and update `src/main.rs` so `pilot` preserves the Stage 1 `main()` body inside `run_pilot_cli()` and `evaluate --profile <native|soft>` runs Stage 2 evaluation:
```rust
use adaptive_aead::workload::{
    TraceKind, build_mixed_burst_trace, build_policy_shift_trace, run_evaluation,
    write_evaluation_csvs,
};

fn run_evaluate_cli(profile: &str) -> std::io::Result<()> {
    let traces = vec![
        (TraceKind::MixedBurst, build_mixed_burst_trace()),
        (TraceKind::PolicyShift, build_policy_shift_trace()),
    ];
    let work_dir = PathBuf::from(format!("bench_eval_tmp_{profile}"));
    let (summaries, timeline) = run_evaluation(profile, &traces, &work_dir)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    println!("=== Adaptive AEAD Stage 2 Evaluation (profile={profile}) ===");
    println!(
        "{:<13} | {:<24} | {:>9} | {:>8} | {:>8} | {:>8} | {:>9}",
        "Trace", "Policy", "Thru(MB/s)", "Switches", "SwOv(ms)", "Regret(%)", "Compliant"
    );
    println!("{:-<13}-+-{:-<24}-+-{:-<9}-+-{:-<8}-+-{:-<8}-+-{:-<9}-+-{:-<9}", "", "", "", "", "", "", "");
    for s in &summaries {
        println!(
            "{:<13} | {:<24} | {:>9.2} | {:>8} | {:>8.3} | {:>9.2} | {:>9}",
            s.trace_name,
            s.policy_label,
            s.throughput_mb_s,
            s.switch_count,
            s.switch_overhead_ms,
            s.regret_pct,
            s.policy_compliant
        );
    }

    write_evaluation_csvs(Path::new("results"), profile, &summaries, &timeline)?;
    println!("Saved Stage 2 CSVs to results/eval_{profile}.csv and results/eval_{profile}_timeline.csv");
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("evaluate") => {
            let profile = args
                .windows(2)
                .find(|w| w[0] == "--profile")
                .map(|w| w[1].as_str())
                .unwrap_or("native");
            run_evaluate_cli(profile)
        }
        _ => run_pilot_cli(),
    }
}
```

- [ ] **Step 4: Run tests to verify all Stage 1 and Stage 2 tests pass**

Run:
```bash
distrobox enter my-distrobox -- sh -c "cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test"
```
Expected: All tests PASS.

- [ ] **Step 5: Commit Task 5**

```bash
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead add src/workload.rs src/lib.rs src/main.rs tests/stage2_tests.rs
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead commit -m "feat: add mixed-workload and policy-shift evaluator with CLI subcommands"
```

---

### Task 6: Dual-Profile Verification (`native` & `soft`), Empirical Evaluation Runs, and Stage 2 Figures

**Files:**
- Create: `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/scripts/plot_evaluation.py`
- Generated outputs (gitignored in `results/`):
  - `results/eval_native.csv`, `results/eval_native_timeline.csv`
  - `results/eval_soft.csv`, `results/eval_soft_timeline.csv`
  - `results/figures/fig3_hysteresis_tradeoff.{png,pdf}`
  - `results/figures/fig4_policy_comparison.{png,pdf}`
  - `results/figures/fig5_selection_timeline.{png,pdf}`

- [ ] **Step 1: Run `cargo test` under BOTH `native` and `soft` profiles**

Run:
```bash
distrobox enter my-distrobox -- sh -c 'cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo test --release && RUSTFLAGS="--cfg aes_backend=\"soft\" --cfg polyval_backend=\"soft\" --cfg chacha20_backend=\"soft\" --cfg poly1305_backend=\"soft\"" cargo test --release --target-dir target-soft'
```
Expected: Both `native` and `soft` builds compile cleanly and pass 100% of unit, KAT, and Stage 2 integration tests.

- [ ] **Step 2: Build release binaries and run `evaluate` for both `native` and `soft` profiles**

Run:
```bash
distrobox enter my-distrobox -- sh -c 'cd /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead && cargo run --release -- evaluate --profile native && RUSTFLAGS="--cfg aes_backend=\"soft\" --cfg polyval_backend=\"soft\" --cfg chacha20_backend=\"soft\" --cfg poly1305_backend=\"soft\"" cargo run --release --target-dir target-soft -- evaluate --profile soft'
```
Expected: Both commands exit 0 and generate `results/eval_native.csv`, `results/eval_native_timeline.csv`, `results/eval_soft.csv`, and `results/eval_soft_timeline.csv`.

- [ ] **Step 3: Write `scripts/plot_evaluation.py` and generate Stage 2 figures**

Write `/home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/scripts/plot_evaluation.py`:
```python
"""Generate publication-quality Stage 2 evaluation figures from eval_<profile>.csv."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

PROFILE_STYLES = {
    "native": {"color": "#0072B2", "marker": "o", "linestyle": "-", "label": "Native (AES-NI + AVX2)"},
    "soft": {"color": "#D55E00", "marker": "s", "linestyle": "--", "label": "Software-Only (Scalar)"},
}

ALG_MAP = {
    "AES-128-GCM": 0,
    "ChaCha20-Poly1305": 1,
    "Ascon-AEAD128": 2,
}


def configure_rcparams() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "font.family": "sans-serif",
            "font.sans-serif": ["DejaVu Sans", "Liberation Sans", "Arial"],
            "font.size": 9.5,
            "axes.titlesize": 10.5,
            "axes.titleweight": "bold",
            "axes.labelsize": 9.5,
            "xtick.labelsize": 8.5,
            "ytick.labelsize": 8.5,
            "legend.fontsize": 8.5,
            "legend.frameon": True,
            "legend.framealpha": 0.95,
            "legend.edgecolor": "#CCCCCC",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.edgecolor": "#333333",
            "axes.linewidth": 0.9,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def save_figure(fig: mpl.figure.Figure, stem: Path) -> None:
    stem.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(stem.with_suffix(".png"), dpi=300, facecolor="white")
    fig.savefig(stem.with_suffix(".pdf"), facecolor="white")


def parse_delta(policy_label: str) -> float | None:
    if policy_label == "Adaptive(d=0.00)":
        return 0.0
    if policy_label.startswith("Adaptive+Hyst(d="):
        return float(policy_label.split("d=")[1].rstrip(")"))
    return None


def plot_hysteresis_tradeoff(
    native_rows: list[dict[str, str]],
    soft_rows: list[dict[str, str]],
    out_stem: Path,
) -> None:
    fig, (ax_sw, ax_reg) = plt.subplots(1, 2, figsize=(11.5, 4.5), layout="constrained")

    for profile, rows in [("native", native_rows), ("soft", soft_rows)]:
        st = PROFILE_STYLES[profile]
        mb = [r for r in rows if r["trace"] == "mixed_burst"]
        pts = []
        for r in mb:
            d = parse_delta(r["policy"])
            if d is not None:
                pts.append((d * 100.0, int(r["switch_count"]), float(r["regret_pct"])))
        pts.sort(key=lambda x: x[0])
        xs = [p[0] for p in pts]
        sw = [p[1] for p in pts]
        reg = [p[2] for p in pts]

        ax_sw.plot(xs, sw, label=st["label"], color=st["color"], marker=st["marker"], linestyle=st["linestyle"], lw=2.0)
        ax_reg.plot(xs, reg, label=st["label"], color=st["color"], marker=st["marker"], linestyle=st["linestyle"], lw=2.0)

    ax_sw.set_title("A. Switching Frequency vs Hysteresis Threshold")
    ax_sw.set_xlabel("Hysteresis Threshold δ (%)")
    ax_sw.set_ylabel("Algorithm Switches (count)")
    ax_sw.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
    ax_sw.legend(loc="upper right")

    ax_reg.set_title("B. Performance Regret vs Hysteresis Threshold")
    ax_reg.set_xlabel("Hysteresis Threshold δ (%)")
    ax_reg.set_ylabel("Performance Regret vs Oracle (%)")
    ax_reg.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
    ax_reg.legend(loc="upper left")

    fig.suptitle("Hysteresis Stability–Performance Trade-Off (Mixed Burst Trace)", fontsize=11.5, fontweight="bold")
    save_figure(fig, out_stem)
    plt.close(fig)


def plot_policy_comparison(
    native_rows: list[dict[str, str]],
    soft_rows: list[dict[str, str]],
    out_stem: Path,
) -> None:
    selected_policies = [
        "Static(AES-128-GCM)",
        "Static(ChaCha20-Poly1305)",
        "Static(Ascon-AEAD128)",
        "Adaptive(d=0.00)",
        "Adaptive+Hyst(d=0.15)",
    ]
    short_labels = ["Static\nAES-GCM", "Static\nChaCha20", "Static\nAscon", "Adaptive\n(δ=0%)", "Adaptive+Hyst\n(δ=15%)"]

    fig, (ax_nat, ax_soft) = plt.subplots(1, 2, figsize=(12.0, 4.6), layout="constrained")
    x = np.arange(len(selected_policies))

    for ax, title, rows in [
        (ax_nat, "A. Native Hardware Profile (AES-NI + AVX2)", native_rows),
        (ax_soft, "B. Pure-Software Scalar Profile", soft_rows),
    ]:
        mb = {r["policy"]: float(r["throughput_mb_s"]) for r in rows if r["trace"] == "mixed_burst"}
        vals = [mb[p] for p in selected_policies]
        colors = ["#666666", "#888888", "#AAAAAA", "#D55E00", "#0072B2"]
        bars = ax.bar(x, vals, width=0.58, color=colors, edgecolor="#222222", lw=0.8)
        ax.set_title(title)
        ax.set_ylabel("End-to-End Throughput (MB/s)")
        ax.set_xticks(x, short_labels)
        ax.set_ylim(0, max(vals) * 1.22 if vals else 1.0)
        ax.grid(axis="y", linestyle=":", lw=0.7, color="#CCCCCC")
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2.0, v + max(vals) * 0.02, f"{v:.1f}", ha="center", va="bottom", fontsize=8.0)

    fig.suptitle("Policy Throughput Comparison on Mixed Burst Workload", fontsize=11.5, fontweight="bold")
    save_figure(fig, out_stem)
    plt.close(fig)


def plot_selection_timeline(soft_tl: list[dict[str, str]], out_stem: Path) -> None:
    fig, (ax0, ax1) = plt.subplots(2, 1, figsize=(11.5, 5.4), sharex=True, layout="constrained")

    for ax, pol, title in [
        (ax0, "Adaptive(d=0.00)", "A. Adaptive without Hysteresis (δ = 0%) — Software Profile"),
        (ax1, "Adaptive+Hyst(d=0.15)", "B. Adaptive with Hysteresis (δ = 15%) — Software Profile"),
    ]:
        rows = [r for r in soft_tl if r["trace"] == "policy_shift" and r["policy"] == pol]
        steps = [int(r["step"]) for r in rows]
        algs = [ALG_MAP[r["chosen_alg"]] for r in rows]
        ax.axvspan(30, 59, color="#F0E442", alpha=0.25, label="256-bit Security Phase")
        ax.step(steps, algs, where="post", color="#0072B2", lw=1.8)
        ax.set_yticks([0, 1, 2], ["AES-128-GCM", "ChaCha20-Poly1305", "Ascon-AEAD128"])
        ax.set_ylim(-0.35, 2.35)
        ax.set_title(title)
        ax.grid(axis="x", linestyle=":", lw=0.6, color="#CCCCCC")
        ax.legend(loc="lower right")

    ax1.set_xlabel("Trace Step Index (0–89)")
    fig.suptitle("Per-Step Algorithm Selection & Security Override Timeline (Policy Shift Trace)", fontsize=11.5, fontweight="bold")
    save_figure(fig, out_stem)
    plt.close(fig)


def main() -> None:
    configure_rcparams()
    base = Path(__file__).resolve().parent.parent
    res = base / "results"
    figs = res / "figures"

    native_rows = load_csv(res / "eval_native.csv")
    soft_rows = load_csv(res / "eval_soft.csv")
    soft_tl = load_csv(res / "eval_soft_timeline.csv")

    plot_hysteresis_tradeoff(native_rows, soft_rows, figs / "fig3_hysteresis_tradeoff")
    plot_policy_comparison(native_rows, soft_rows, figs / "fig4_policy_comparison")
    plot_selection_timeline(soft_tl, figs / "fig5_selection_timeline")
    print(f"Generated Stage 2 evaluation figures in {figs}")


if __name__ == "__main__":
    main()
```

Run:
```bash
distrobox enter my-distrobox -- python3 /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead/scripts/plot_evaluation.py
```

- [ ] **Step 4: Visually inspect all 3 rendered PNG figures with `read_file`**

Read `fig3_hysteresis_tradeoff.png`, `fig4_policy_comparison.png`, and `fig5_selection_timeline.png` to verify no overlapping labels, cut-off axes, or legend collisions. Fix and regenerate if any layout issue appears.

- [ ] **Step 5: Commit `scripts/plot_evaluation.py`**

```bash
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead add scripts/plot_evaluation.py
git -C /home/rigelyon/Workspaces/UAS_Cryptography/adaptive-aead commit -m "feat: add Stage 2 evaluation visualization script"
```
