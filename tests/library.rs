//! Library-level round trips that do not depend on the shared vectors:
//! encodings, the attestation and rotation builders, and the did:nostr view.

use did_nostr::*;

#[test]
fn identity_generation_and_derivation_agree() {
    let id = generate_identity();
    assert_eq!(id.pubkey.len(), 64);
    assert!(id
        .pubkey
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(public_key_from_secret(&id.secret_hex).unwrap(), id.pubkey);
}

#[test]
fn npub_nsec_did_round_trips() {
    let id = generate_identity();
    assert_eq!(
        npub_to_hex(&hex_to_npub(&id.pubkey).unwrap()).unwrap(),
        id.pubkey
    );
    assert_eq!(
        nsec_to_secret(&secret_to_nsec(&id.secret_hex).unwrap()).unwrap(),
        id.secret_hex
    );
    assert_eq!(
        did_to_hex(&hex_to_did(&id.pubkey).unwrap()).unwrap(),
        id.pubkey
    );
    assert_eq!(
        normalize_pubkey(&hex_to_npub(&id.pubkey).unwrap()).unwrap(),
        id.pubkey
    );
    assert_eq!(
        normalize_pubkey(&id.pubkey.to_uppercase()).unwrap(),
        id.pubkey
    );
}

#[test]
fn npub_to_hex_rejects_an_nsec() {
    let id = generate_identity();
    assert!(npub_to_hex(&secret_to_nsec(&id.secret_hex).unwrap()).is_err());
}

#[test]
fn attestation_builds_verifies_and_parses() {
    let attester = generate_identity();
    let subject = generate_identity();
    let ev = create_attestation(
        &AttestationInput {
            subject: subject.pubkey.clone(),
            claims: vec![
                Claim::new("name", "alice"),
                Claim::new("nip05", "alice@example.com"),
            ],
            method: "in-person".into(),
            ..Default::default()
        },
        &attester.secret_hex,
    )
    .unwrap();
    assert!(verify_event(&ev).ok);
    let p = parse_attestation(&ev).unwrap();
    assert_eq!(p.attester, attester.pubkey);
    assert_eq!(p.subject, subject.pubkey);
    assert_eq!(p.method.as_deref(), Some("in-person"));
    assert_eq!(p.claims.len(), 2);
}

#[test]
fn revocation_verifies_and_carries_no_claims() {
    let attester = generate_identity();
    let subject = generate_identity();
    let ev =
        revoke_attestation(&subject.pubkey, "key rotated", &attester.secret_hex, None).unwrap();
    assert!(verify_event(&ev).ok);
    let p = parse_attestation(&ev).unwrap();
    assert_eq!(p.revoked.as_deref(), Some("key rotated"));
    assert_eq!(p.claims.len(), 0);
}

#[test]
fn attestation_needs_at_least_one_claim() {
    let a = generate_identity();
    assert!(create_attestation(
        &AttestationInput {
            subject: a.pubkey.clone(),
            method: "asserted".into(),
            ..Default::default()
        },
        &a.secret_hex,
    )
    .is_err());
}

#[test]
fn guardian_rotation_happy_path_accepts_past_the_cooldown() {
    let old = generate_identity();
    let next = generate_identity();
    let g1 = generate_identity();
    let g2 = generate_identity();
    let g3 = generate_identity();

    let t0 = 1_700_000_000;
    let claim_at = t0 + DEFAULT_COOLDOWN_SECONDS + 3600;

    let events = vec![
        create_guardian_set(
            &GuardianSetInput {
                guardians: vec![g1.pubkey.clone(), g2.pubkey.clone(), g3.pubkey.clone()],
                threshold: 2,
                created_at: Some(t0),
            },
            &old.secret_hex,
        )
        .unwrap(),
        create_rotation_claim(
            &RotationClaimInput {
                old_pubkey: old.pubkey.clone(),
                reason: "lost".into(),
                created_at: Some(claim_at),
                ..Default::default()
            },
            &next.secret_hex,
        )
        .unwrap(),
        create_rotation_attestation(
            &RotationAttestationInput {
                old_pubkey: old.pubkey.clone(),
                new_pubkey: next.pubkey.clone(),
                method: "in-person".into(),
                created_at: Some(claim_at + 60),
            },
            &g1.secret_hex,
        )
        .unwrap(),
        create_rotation_attestation(
            &RotationAttestationInput {
                old_pubkey: old.pubkey.clone(),
                new_pubkey: next.pubkey.clone(),
                method: "existing-channel".into(),
                created_at: Some(claim_at + 120),
            },
            &g2.secret_hex,
        )
        .unwrap(),
    ];
    for ev in &events {
        assert!(verify_event(ev).ok, "{:?}", verify_event(ev).reason);
    }
    let verdict = evaluate_rotation(&events, &EvaluateOptions::default());
    assert!(verdict.accepted, "{}", verdict.reason);
    assert_eq!(verdict.new.as_deref(), Some(next.pubkey.as_str()));
    assert_eq!(verdict.old.as_deref(), Some(old.pubkey.as_str()));
}

#[test]
fn fresh_guardian_set_inside_cooldown_does_not_count() {
    let old = generate_identity();
    let next = generate_identity();
    let g1 = generate_identity();
    let g2 = generate_identity();
    let claim_at = 1_800_000_000;
    let events = vec![
        create_guardian_set(
            &GuardianSetInput {
                guardians: vec![g1.pubkey.clone(), g2.pubkey.clone()],
                threshold: 2,
                created_at: Some(claim_at - 3600),
            },
            &old.secret_hex,
        )
        .unwrap(),
        create_rotation_claim(
            &RotationClaimInput {
                old_pubkey: old.pubkey.clone(),
                reason: "compromised".into(),
                created_at: Some(claim_at),
                ..Default::default()
            },
            &next.secret_hex,
        )
        .unwrap(),
        create_rotation_attestation(
            &RotationAttestationInput {
                old_pubkey: old.pubkey.clone(),
                new_pubkey: next.pubkey.clone(),
                method: "existing-channel".into(),
                created_at: Some(claim_at + 60),
            },
            &g1.secret_hex,
        )
        .unwrap(),
        create_rotation_attestation(
            &RotationAttestationInput {
                old_pubkey: old.pubkey.clone(),
                new_pubkey: next.pubkey.clone(),
                method: "existing-channel".into(),
                created_at: Some(claim_at + 90),
            },
            &g2.secret_hex,
        )
        .unwrap(),
    ];
    assert!(!evaluate_rotation(&events, &EvaluateOptions::default()).accepted);
}

#[test]
fn self_authorised_rotation_via_prev_sig_needs_no_guardians() {
    let old = generate_identity();
    let next = generate_identity();
    let claim = create_rotation_claim(
        &RotationClaimInput {
            old_pubkey: old.pubkey.clone(),
            reason: "planned".into(),
            old_secret_hex_for_prev_sig: Some(old.secret_hex.clone()),
            created_at: None,
        },
        &next.secret_hex,
    )
    .unwrap();
    assert!(verify_event(&claim).ok);
    let verdict = evaluate_rotation(&[claim], &EvaluateOptions::default());
    assert!(verdict.accepted, "{}", verdict.reason);
    assert_eq!(verdict.new.as_deref(), Some(next.pubkey.as_str()));
}

#[test]
fn did_nostr_document_and_multikey_round_trip() {
    let id = generate_identity();
    let doc = did_document(&id.pubkey, &["wss://relay.example".to_string()]).unwrap();
    assert_eq!(doc.id, format!("did:nostr:{}", id.pubkey));
    assert_eq!(doc.type_, "DIDNostr");
    assert_eq!(
        doc.verification_method[0].public_key_multibase,
        format!("fe70102{}", id.pubkey)
    );
    assert_eq!(
        multikey_to_xonly(&xonly_to_multikey(&id.pubkey).unwrap()).unwrap(),
        id.pubkey
    );
    assert_eq!(doc.authentication[0], format!("did:nostr:{}#0", id.pubkey));
    assert_eq!(doc.service.as_ref().unwrap().len(), 1);
}
