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

    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Aes128Gcm => "AES-128-GCM",
            Algorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Algorithm::AsconAead128 => "Ascon-AEAD128",
        }
    }

    pub const fn standard(self) -> &'static str {
        match self {
            Algorithm::Aes128Gcm => "NIST SP 800-38D",
            Algorithm::ChaCha20Poly1305 => "IETF RFC 8439",
            Algorithm::AsconAead128 => "NIST SP 800-232",
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::ChaCha20Poly1305 => 32,
            Algorithm::AsconAead128 => 16,
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 12,
            Algorithm::AsconAead128 => 16,
        }
    }

    pub const fn tag_len(self) -> usize {
        16
    }

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

pub enum AeadCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
    AsconAead128(Box<AsconAead128>),
}

impl AeadCipher {
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

    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Aes128Gcm(_) => Algorithm::Aes128Gcm,
            Self::ChaCha20Poly1305(_) => Algorithm::ChaCha20Poly1305,
            Self::AsconAead128(_) => Algorithm::AsconAead128,
        }
    }

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

#[derive(Debug, Default)]
pub struct NonceGenerator {
    counter: u64,
}

impl NonceGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn next_into(&mut self, dst: &mut [u8]) {
        dst.fill(0);
        let bytes = self.counter.to_le_bytes();
        let copy_len = dst.len().min(bytes.len());
        dst[..copy_len].copy_from_slice(&bytes[..copy_len]);
        self.counter = self.counter.wrapping_add(1);
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
        let (c1, _) = cache.prepare(Algorithm::Aes128Gcm).unwrap();
        assert_eq!(c1.algorithm(), Algorithm::Aes128Gcm);
        let (c2, cost2) = cache.prepare(Algorithm::Aes128Gcm).unwrap();
        assert_eq!(c2.algorithm(), Algorithm::Aes128Gcm);
        assert_eq!(cost2, 0);
        let (c3, _) = cache.prepare(Algorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(c3.algorithm(), Algorithm::ChaCha20Poly1305);
    }
}
