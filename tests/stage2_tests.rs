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
