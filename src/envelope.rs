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
