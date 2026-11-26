use adaptive_aead::envelope::{
    ENVELOPE_MAGIC, ENVELOPE_VERSION, FIXED_HEADER_LEN, open_envelope, parse_header,
    seal_envelope,
};
use adaptive_aead::profile::RuntimeProfile;
use adaptive_aead::selector::{AdaptiveSelector, SelectionPolicy, SwitchReason};
use adaptive_aead::workload::{
    TraceKind, TraceStep, build_mixed_burst_trace, build_policy_shift_trace, run_evaluation,
};
use adaptive_aead::{AeadCipher, Algorithm, CryptoError, KeyRing, NonceGenerator, SecurityPolicy};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn synthetic_profile() -> RuntimeProfile {
    // Rates (ns/byte) per bucket [AES-128-GCM, ChaCha20-Poly1305, Ascon-AEAD128]
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

    let mut sel = AdaptiveSelector::new(
        SelectionPolicy::AdaptiveHysteresis { delta: 0.20 },
        synthetic_profile(),
    );

    // 1. First file (Small, 4096 B) -> picks AES-128-GCM (2.0 vs 2.2)
    let d1 = sel.select_for(4096, &sec).unwrap();
    assert_eq!(d1.chosen, Algorithm::Aes128Gcm);
    assert_eq!(d1.reason, SwitchReason::Initial);

    // 2. Medium (65536 B): ChaCha20 is 1.0 vs AES 1.15 -> gain ≈ 0.1304 <= 0.20 -> HOLD
    let d2 = sel.select_for(65_536, &sec).unwrap();
    assert_eq!(d2.chosen, Algorithm::Aes128Gcm);
    assert!(!d2.switched);
    assert_eq!(d2.reason, SwitchReason::HysteresisHeld);

    // 3. Tiny (256 B): Ascon is 2.0 vs AES 3.0 -> gain ≈ 0.3333 > 0.20 -> SWITCH
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

#[test]
fn evaluator_runs_mini_trace_and_respects_policy_shift() {
    let mixed = build_mixed_burst_trace();
    let shifted = build_policy_shift_trace();
    assert_eq!(mixed.len(), 120);
    assert_eq!(shifted.len(), 90);

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
