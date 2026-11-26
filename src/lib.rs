//! Adaptive AEAD library: cryptographic facade, self-describing envelope,
//! workload profiler, hysteresis selector, and trace evaluator.

pub mod crypto;
pub mod envelope;

pub use crypto::{
    AeadCipher, Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy,
};
