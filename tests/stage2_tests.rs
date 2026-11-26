use adaptive_aead::envelope::{
    ENVELOPE_MAGIC, ENVELOPE_VERSION, FIXED_HEADER_LEN, open_envelope, open_envelope_cached,
    parse_header, seal_envelope,
};
use adaptive_aead::profile::RuntimeProfile;
use adaptive_aead::selector::{AdaptiveSelector, SelectionPolicy, SwitchReason};
use adaptive_aead::workload::{
    TraceKind, TraceStep, WorkloadDomain, aggregate_trials, all_policies, build_mixed_burst_trace,
    build_policy_shift_trace, deserialize_worker_result, execute_single_policy,
    serialize_worker_result,
};
use adaptive_aead::{
    AeadCipher, Algorithm, CipherCache, CryptoError, KeyRing, NonceGenerator, SecurityPolicy,
};

#[test]
fn envelope_roundtrip_all_four_algorithms_cached_and_uncached() {
    let keys = KeyRing::deterministic_benchmark();
    let policy = SecurityPolicy::default();
    let mut nonces = NonceGenerator::new();
    let mut dec_cache = CipherCache::new(&keys);

    for alg in Algorithm::ALL {
        for size in [0usize, 1, 64, 4096] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut nonce = vec![0u8; alg.nonce_len()];
            nonces.next_for(alg, &mut nonce);

            let cipher = AeadCipher::new(alg, keys.key_for(alg)).unwrap();
            let mut buf = plaintext.clone();
            seal_envelope(&cipher, &nonce, b"file-meta", &mut buf).unwrap();

            let (hdr, hdr_len) = parse_header(&buf).unwrap();
            assert_eq!(hdr.version, ENVELOPE_VERSION);
            assert_eq!(hdr.alg, alg);
            assert_eq!(hdr.nonce, nonce);
            assert_eq!(hdr_len, FIXED_HEADER_LEN + alg.nonce_len());
            assert_eq!(buf.len(), hdr_len + size + alg.tag_len());

            let mut buf_cached = buf.clone();
            let (used_alg_cached, _) =
                open_envelope_cached(&mut dec_cache, &policy, b"file-meta", &mut buf_cached).unwrap();
            assert_eq!(used_alg_cached, alg);
            assert_eq!(buf_cached, plaintext);

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

    let mut sealed = original;
    seal_envelope(&cipher, &nonce, b"aad", &mut sealed).unwrap();
    assert_eq!(&sealed[0..4], &ENVELOPE_MAGIC);

    let mut for_policy = sealed.clone();
    assert_eq!(
        open_envelope(&keys, &policy_256, b"aad", &mut for_policy),
        Err(CryptoError::PolicyViolation("security strength below minimum"))
    );

    let mut tampered_flags = sealed.clone();
    tampered_flags[7] ^= 0x01;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut tampered_flags),
        Err(CryptoError::AeadFailure)
    );

    let mut bad_magic = sealed.clone();
    bad_magic[0] = b'X';
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut bad_magic),
        Err(CryptoError::InvalidMagic)
    );

    let mut bad_ver = sealed.clone();
    bad_ver[4] = 99;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut bad_ver),
        Err(CryptoError::UnsupportedVersion(99))
    );

    let mut bad_alg = sealed.clone();
    bad_alg[5] = 42;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"aad", &mut bad_alg),
        Err(CryptoError::UnknownAlgorithmId(42))
    );

    let mut wrong_aad = sealed;
    assert_eq!(
        open_envelope(&keys, &policy_128, b"wrong", &mut wrong_aad),
        Err(CryptoError::AeadFailure)
    );
}

fn synthetic_profile() -> RuntimeProfile {
    // [Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, AsconAead128]
    let rates = [
        [3.0, 3.8, 10.0, 2.0],  // Tiny: Ascon fastest (2.0)
        [2.0, 2.5, 2.2, 5.0],   // Small: AES-128 fastest (2.0)
        [1.15, 1.3, 1.0, 4.0],  // Medium: ChaCha20 fastest (1.0), 13% faster than AES-128
        [1.0, 1.15, 1.4, 4.0],  // Large: AES-128 fastest (1.0), AES-256 fastest 256-bit (1.15)
        [1.0, 1.15, 1.4, 4.0],  // Bulk
    ];
    RuntimeProfile::from_rates(0.2, rates)
}

#[test]
fn hysteresis_holds_below_delta_and_switches_above_delta() {
    let sec = SecurityPolicy::default();

    for pol in [
        SelectionPolicy::LookupHysteresis { delta: 0.20 },
        SelectionPolicy::AdaptiveEmaHysteresis { delta: 0.20 },
    ] {
        let mut sel = AdaptiveSelector::new(pol, synthetic_profile());

        let d1 = sel.select_for(4096, &sec).unwrap();
        assert_eq!(d1.chosen, Algorithm::Aes128Gcm);
        assert_eq!(d1.reason, SwitchReason::Initial);

        // Medium: ChaCha20 1.0 vs AES-128 1.15 -> gain ≈ 0.1304 <= 0.20 -> HOLD
        let d2 = sel.select_for(65_536, &sec).unwrap();
        assert_eq!(d2.chosen, Algorithm::Aes128Gcm);
        assert!(!d2.switched);
        assert_eq!(d2.reason, SwitchReason::HysteresisHeld);

        // Tiny: Ascon 2.0 vs AES-128 3.0 -> gain ≈ 0.3333 > 0.20 -> SWITCH
        let d3 = sel.select_for(256, &sec).unwrap();
        assert_eq!(d3.chosen, Algorithm::AsconAead128);
        assert!(d3.switched);
        assert_eq!(d3.reason, SwitchReason::ThresholdExceeded);
    }
}

#[test]
fn security_policy_upgrade_overrides_hysteresis_and_picks_fastest_256bit() {
    let sec_128 = SecurityPolicy::default();
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };

    let mut sel = AdaptiveSelector::new(
        SelectionPolicy::LookupHysteresis { delta: 0.95 },
        synthetic_profile(),
    );

    let d1 = sel.select_for(256, &sec_128).unwrap();
    assert_eq!(d1.chosen, Algorithm::AsconAead128);

    // At 256 B under 256-bit constraint: AES-256-GCM (3.8) beats ChaCha20-Poly1305 (10.0)
    let d2 = sel.select_for(256, &sec_256).unwrap();
    assert_eq!(d2.chosen, Algorithm::Aes256Gcm);
    assert!(d2.switched);
    assert_eq!(d2.reason, SwitchReason::SecurityOverride);

    // At 65536 B under 256-bit constraint: ChaCha20 (1.0) vs AES-256 (1.3) -> gain 0.23 < 0.95 -> HOLD
    let d3 = sel.select_for(65_536, &sec_256).unwrap();
    assert_eq!(d3.chosen, Algorithm::Aes256Gcm);
    assert!(!d3.switched);
    assert_eq!(d3.reason, SwitchReason::HysteresisHeld);
}

#[test]
fn worker_execution_and_trial_aggregation_handle_non_compliant_regret_as_none() {
    let mixed = build_mixed_burst_trace();
    let shifted = build_policy_shift_trace();
    assert_eq!(mixed.len(), 120);
    assert_eq!(shifted.len(), 90);
    assert_eq!(shifted[29].file_size_bytes, 128);
    assert_eq!(shifted[30].policy.min_security_bits, 256);

    let sec_128 = SecurityPolicy::default();
    let sec_256 = SecurityPolicy {
        min_security_bits: 256,
        ..SecurityPolicy::default()
    };
    let mini_trace: Vec<TraceStep> = (0..12)
        .map(|i| TraceStep {
            step: i,
            file_count: 1,
            file_size_bytes: if i % 2 == 0 { 256 } else { 16 * 1024 },
            policy: if (4..8).contains(&i) { sec_256 } else { sec_128 },
        })
        .collect();

    let mut trial_runs = Vec::new();
    for trial in 0..3 {
        let mut runs = Vec::new();
        for pol in all_policies() {
            let res = execute_single_policy(
                WorkloadDomain::Memory,
                "test",
                TraceKind::PolicyShift,
                pol,
                synthetic_profile(),
                &mini_trace,
                trial,
                None,
            )
            .unwrap();
            let roundtrip = deserialize_worker_result(&serialize_worker_result(&res)).unwrap();
            assert_eq!(roundtrip.policy_label, res.policy_label);
            assert_eq!(roundtrip.step_total_ns.len(), mini_trace.len());
            runs.push(roundtrip);
        }
        trial_runs.push(runs);
    }

    let (summaries, timelines) = aggregate_trials(
        WorkloadDomain::Memory,
        "test",
        TraceKind::PolicyShift,
        &mini_trace,
        &trial_runs,
    );
    assert_eq!(summaries.len(), 16);
    assert_eq!(timelines.len(), 16 * mini_trace.len());

    let static_aes128 = summaries
        .iter()
        .find(|s| s.policy_label == "Static(AES-128-GCM)")
        .unwrap();
    assert!(!static_aes128.policy_compliant);
    assert_eq!(static_aes128.policy_violations, 4);
    assert!(static_aes128.regret_median_pct.is_none());

    let static_aes256 = summaries
        .iter()
        .find(|s| s.policy_label == "Static(AES-256-GCM)")
        .unwrap();
    assert!(static_aes256.policy_compliant);
    assert!(static_aes256.regret_median_pct.unwrap() >= 0.0);

    let lookup_0 = summaries
        .iter()
        .find(|s| s.policy_label == "Lookup(d=0.00)")
        .unwrap();
    let lookup_35 = summaries
        .iter()
        .find(|s| s.policy_label == "Lookup+Hyst(d=0.35)")
        .unwrap();
    assert!(lookup_0.policy_compliant);
    assert!(lookup_35.policy_compliant);
    assert!(lookup_35.switch_count_median <= lookup_0.switch_count_median);
}
