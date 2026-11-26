//! Adaptive AEAD library: cryptographic facade, self-describing envelope,
//! workload profiler, hysteresis selector, and trace evaluator.

pub mod crypto;
pub mod envelope;
pub mod profile;
pub mod selector;
pub mod workload;

pub use crypto::{
    AeadCipher, Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy,
};
