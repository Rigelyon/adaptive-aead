//! Core AEAD engine, security policy, domain-separated key ring, and cipher cache primitives.

use aead::{AeadInOut, KeyInit, array::Array};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use ascon_aead128::AsconAead128;
use chacha20poly1305::ChaCha20Poly1305;
use std::fmt;
use std::time::Instant;

/// Supported authenticated encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    AsconAead128,
}

impl Algorithm {
    /// All candidate algorithms evaluated in this study.
    pub const ALL: [Algorithm; 4] = [
        Algorithm::Aes128Gcm,
        Algorithm::Aes256Gcm,
        Algorithm::ChaCha20Poly1305,
        Algorithm::AsconAead128,
    ];

    /// Compact zero-based array index (`0..4`).
    pub const fn index(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 0,
            Algorithm::Aes256Gcm => 1,
            Algorithm::ChaCha20Poly1305 => 2,
            Algorithm::AsconAead128 => 3,
        }
    }

    /// Canonical wire identifier used in the self-describing file envelope.
    pub const fn id(self) -> u8 {
        match self {
            Algorithm::Aes128Gcm => 1,
            Algorithm::ChaCha20Poly1305 => 2,
            Algorithm::AsconAead128 => 3,
            Algorithm::Aes256Gcm => 4,
        }
    }

    /// Parses an algorithm from its wire identifier.
    pub const fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(Algorithm::Aes128Gcm),
            2 => Ok(Algorithm::ChaCha20Poly1305),
            3 => Ok(Algorithm::AsconAead128),
            4 => Ok(Algorithm::Aes256Gcm),
            _ => Err(CryptoError::UnknownAlgorithmId(id)),
        }
    }

    /// Human-readable canonical algorithm name.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Aes128Gcm => "AES-128-GCM",
            Algorithm::Aes256Gcm => "AES-256-GCM",
            Algorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Algorithm::AsconAead128 => "Ascon-AEAD128",
        }
    }

    /// Governing cryptographic standard identifier.
    pub const fn standard(self) -> &'static str {
        match self {
            Algorithm::Aes128Gcm | Algorithm::Aes256Gcm => "NIST SP 800-38D",
            Algorithm::ChaCha20Poly1305 => "IETF RFC 8439",
            Algorithm::AsconAead128 => "NIST SP 800-232",
        }
    }

    /// Required secret key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm | Algorithm::AsconAead128 => 16,
            Algorithm::Aes256Gcm | Algorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Required nonce/IV length in bytes.
    pub const fn nonce_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm | Algorithm::Aes256Gcm | Algorithm::ChaCha20Poly1305 => 12,
            Algorithm::AsconAead128 => 16,
        }
    }

    /// Authentication tag length in bytes (128-bit tag for all four AEADs).
    pub const fn tag_len(self) -> usize {
        16
    }

    /// Cipher key strength in bits (`128` or `256`; authentication tags remain 128-bit).
    pub const fn security_bits(self) -> u16 {
        match self {
            Algorithm::Aes128Gcm | Algorithm::AsconAead128 => 128,
            Algorithm::Aes256Gcm | Algorithm::ChaCha20Poly1305 => 256,
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

fn derive_domain_key(master: &[u8; 32], alg_id: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state = 0xD6E8_FEB8_6659_FD93_u64 ^ ((alg_id as u64) << 56);
    for chunk_idx in 0..4 {
        let base = chunk_idx * 8;
        let word = u64::from_le_bytes([
            master[base],
            master[base + 1],
            master[base + 2],
            master[base + 3],
            master[base + 4],
            master[base + 5],
            master[base + 6],
            master[base + 7],
        ]);
        state = state
            .wrapping_add(word)
            .wrapping_add(0x9E37_79B9_7F4A_7C15)
            .rotate_left(19);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out[base..base + 8].copy_from_slice(&z.to_le_bytes());
    }
    out
}

/// Per-algorithm isolated key provider derived with domain separation from a 256-bit master secret.
/// Note: in production deployments, replace with a standardized KDF (e.g., HKDF-SHA256).
#[derive(Debug, Clone)]
pub struct KeyRing {
    per_alg: [[u8; 32]; 4],
}

impl KeyRing {
    /// Derives independent per-algorithm keys from a 32-byte master secret.
    pub fn new(master: [u8; 32]) -> Self {
        let mut per_alg = [[0u8; 32]; 4];
        for alg in Algorithm::ALL {
            per_alg[alg.index()] = derive_domain_key(&master, alg.id());
        }
        Self { per_alg }
    }

    /// Deterministic key material used exclusively for reproducible benchmark evaluation.
    pub fn deterministic_benchmark() -> Self {
        let mut master = [0u8; 32];
        for (i, b) in master.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        Self::new(master)
    }

    /// Returns the isolated key slice assigned exclusively to `alg`.
    pub fn key_for(&self, alg: Algorithm) -> &[u8] {
        &self.per_alg[alg.index()][..alg.key_len()]
    }
}

/// Uniform runtime AEAD cipher wrapper supporting dynamic algorithm switching.
pub enum AeadCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
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
            Algorithm::Aes256Gcm => {
                let k = Array::try_from(key).map_err(|_| CryptoError::InvalidKeyLength {
                    expected,
                    actual: key.len(),
                })?;
                Self::Aes256Gcm(Box::new(Aes256Gcm::new(&k)))
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
            Self::Aes256Gcm(_) => Algorithm::Aes256Gcm,
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
            Self::Aes256Gcm(c) => {
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
            Self::Aes256Gcm(c) => {
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
/// Initial cold setup (`active == None`) reports `switch_ns == 0` so non-switching policies pay zero switch cost.
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

    /// Ensures `alg` is active, returning the cipher reference and real transition overhead in ns.
    pub fn prepare(&mut self, alg: Algorithm) -> Result<(&AeadCipher, u64), CryptoError> {
        match &self.active {
            Some(cipher) if cipher.algorithm() == alg => {
                let c = self.active.as_ref().ok_or(CryptoError::AeadFailure)?;
                Ok((c, 0))
            }
            Some(_) => {
                let t0 = Instant::now();
                let cipher = AeadCipher::new(alg, self.keys.key_for(alg))?;
                let switch_ns = t0.elapsed().as_nanos() as u64;
                self.active = Some(cipher);
                let c = self.active.as_ref().ok_or(CryptoError::AeadFailure)?;
                Ok((c, switch_ns))
            }
            None => {
                let cipher = AeadCipher::new(alg, self.keys.key_for(alg))?;
                self.active = Some(cipher);
                let c = self.active.as_ref().ok_or(CryptoError::AeadFailure)?;
                Ok((c, 0))
            }
        }
    }
}

/// Deterministic counter-based nonce builder ensuring domain separation and uniqueness per encryption.
#[derive(Debug, Default)]
pub struct NonceGenerator {
    counter: u64,
}

impl NonceGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Fills a caller-provided slice with a unique counter nonce and advances the counter.
    pub fn next_into(&mut self, dst: &mut [u8]) {
        dst.fill(0);
        let bytes = self.counter.to_le_bytes();
        let copy_len = dst.len().min(bytes.len());
        dst[..copy_len].copy_from_slice(&bytes[..copy_len]);
        self.counter = self.counter.wrapping_add(1);
    }

    /// Fills `dst` with a counter nonce domain-separated by `alg.id()` in the final byte.
    pub fn next_for(&mut self, alg: Algorithm, dst: &mut [u8]) {
        self.next_into(dst);
        if let Some(last) = dst.last_mut() {
            *last = alg.id();
        }
    }
}

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
    fn keyring_isolates_and_slices_exact_lengths() {
        let ring = KeyRing::deterministic_benchmark();
        assert_eq!(ring.key_for(Algorithm::Aes128Gcm).len(), 16);
        assert_eq!(ring.key_for(Algorithm::Aes256Gcm).len(), 32);
        assert_eq!(ring.key_for(Algorithm::ChaCha20Poly1305).len(), 32);
        assert_eq!(ring.key_for(Algorithm::AsconAead128).len(), 16);

        // Domain separation: 16-byte keys must not share prefixes with each other or 32-byte keys
        assert_ne!(ring.key_for(Algorithm::Aes128Gcm), ring.key_for(Algorithm::AsconAead128));
        assert_ne!(ring.key_for(Algorithm::Aes128Gcm), &ring.key_for(Algorithm::Aes256Gcm)[..16]);
        assert_ne!(
            ring.key_for(Algorithm::Aes256Gcm),
            ring.key_for(Algorithm::ChaCha20Poly1305)
        );
    }

    #[test]
    fn cipher_cache_reports_zero_on_cold_init_and_reuse() {
        let ring = KeyRing::deterministic_benchmark();
        let mut cache = CipherCache::new(&ring);
        let (c1, cost1) = cache.prepare(Algorithm::Aes128Gcm).unwrap();
        assert_eq!(c1.algorithm(), Algorithm::Aes128Gcm);
        assert_eq!(cost1, 0);
        let (c2, cost2) = cache.prepare(Algorithm::Aes128Gcm).unwrap();
        assert_eq!(c2.algorithm(), Algorithm::Aes128Gcm);
        assert_eq!(cost2, 0);
        let (c3, _) = cache.prepare(Algorithm::Aes256Gcm).unwrap();
        assert_eq!(c3.algorithm(), Algorithm::Aes256Gcm);
    }
}
