//! Official standard compliance tests (NIST SP 800-38D, RFC 8439, NIST SP 800-232)
//! and security constraint checks.

use adaptive_aead::{AeadCipher, Algorithm, CryptoError, SecurityPolicy};

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn verify_kat(alg: Algorithm, key_hex: &str, nonce_hex: &str, aad_hex: &str, pt_hex: &str, ct_and_tag_hex: &str) {
    let key = decode_hex(key_hex);
    let nonce = decode_hex(nonce_hex);
    let aad = decode_hex(aad_hex);
    let pt = decode_hex(pt_hex);
    let expected_ct = decode_hex(ct_and_tag_hex);

    let cipher = AeadCipher::new(alg, &key).expect("cipher init succeeds");

    // 1. Encryption must match exact KAT ciphertext + tag
    let mut buf = pt.clone();
    cipher.encrypt_in_place(&nonce, &aad, &mut buf).expect("encrypt succeeds");
    assert_eq!(buf, expected_ct, "ciphertext+tag mismatch for {alg}");

    // 2. Decryption must recover exact plaintext
    cipher.decrypt_in_place(&nonce, &aad, &mut buf).expect("decrypt succeeds");
    assert_eq!(buf, pt, "recovered plaintext mismatch for {alg}");

    // 3. Tampering a ciphertext byte must fail authentication
    let mut tampered = expected_ct.clone();
    tampered[0] ^= 0x01;
    assert_eq!(
        cipher.decrypt_in_place(&nonce, &aad, &mut tampered),
        Err(CryptoError::AeadFailure),
        "tampered ciphertext was not rejected for {alg}"
    );

    // 4. Tampering AAD must fail authentication
    let mut wrong_aad = aad.clone();
    if let Some(first) = wrong_aad.first_mut() {
        *first ^= 0x80;
    } else {
        wrong_aad.push(0x01);
    }
    let mut valid_ct = expected_ct;
    assert_eq!(
        cipher.decrypt_in_place(&nonce, &wrong_aad, &mut valid_ct),
        Err(CryptoError::AeadFailure),
        "tampered AAD was not rejected for {alg}"
    );
}

#[test]
fn test_aes_128_gcm_nist_sp800_38d_kat() {
    // NIST CAVS gcmEncryptExtIV128.rsp vector (non-empty PT and non-empty AAD)
    verify_kat(
        Algorithm::Aes128Gcm,
        "c939cc13397c1d37de6ae0e1cb7c423c",
        "b3d8cc017cbb89b39e0f67e2",
        "24825602bd12a984e0092d3e448eda5f",
        "c3b3c41f113a31b73d9a5cd432103069",
        "93fe7d9e9bfd10348a5606e5cafa73540032a1dc85f1c9786925a2e71d8272dd",
    );
}

#[test]
fn test_chacha20_poly1305_rfc8439_kat() {
    // RFC 8439 Section 2.8.2 test vector
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let pt_hex: String = plaintext.iter().map(|b| format!("{b:02x}")).collect();

    verify_kat(
        Algorithm::ChaCha20Poly1305,
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "070000004041424344454647",
        "50515253c0c1c2c3c4c5c6c7",
        &pt_hex,
        concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691"
        ),
    );
}

#[test]
fn test_ascon_aead128_nist_sp800_232_kats() {
    // Reference KAT Count 1 (empty PT, empty AD) from ascon/ascon-c LWC_AEAD_KAT_128_128.txt
    verify_kat(
        Algorithm::AsconAead128,
        "000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F",
        "",
        "",
        "4F9C278211BEC9316BF68F46EE8B2EC6",
    );

    // Reference KAT Count 350 (10-byte PT, 19-byte AD)
    verify_kat(
        Algorithm::AsconAead128,
        "000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F",
        "303132333435363738393A3B3C3D3E3F404142",
        "20212223242526272829",
        "A967C136D389E007BA4288F5AA823357D40CF629CBB136E67852",
    );
}

#[test]
fn test_security_policy_filtering() {
    let policy_128 = SecurityPolicy::default();
    assert_eq!(policy_128.eligible_algorithms().len(), 3);

    // Requiring 256-bit key strength excludes 128-bit AEADs
    let policy_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };
    assert_eq!(
        policy_256.eligible_algorithms(),
        vec![Algorithm::ChaCha20Poly1305]
    );
}
