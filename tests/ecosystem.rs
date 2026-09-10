//! Ecosystem check (`DESIGN.md` §10): an event produced by did-rust MUST validate
//! in an unmodified third-party Nostr library. Here that library is `nostr`
//! (rust-nostr).
//!
//! This is what "Nostr-compatible" has to mean in practice — software that has
//! never heard of Resolving Architecture can still check the signature.

use did_nostr::{
    create_attestation, create_guardian_set, create_rotation_claim, generate_identity,
    sign_event_with_aux, AttestationInput, Claim, GuardianSetInput, NostrEvent, RotationClaimInput,
    UnsignedEvent,
};
use nostr::event::Event;
use serde_json::Value;

fn parse(json: &str) -> Event {
    serde_json::from_str(json).expect("rust-nostr deserialises the event")
}

fn cross_verify(ev: &NostrEvent) {
    let parsed = parse(&serde_json::to_string(ev).unwrap());
    parsed
        .verify()
        .unwrap_or_else(|e| panic!("rust-nostr rejected a did-rust kind {} event: {e}", ev.kind));
}

#[test]
fn did_rust_events_verify_under_rust_nostr() {
    let alice = generate_identity();
    let bob = generate_identity();

    let note = sign_event_with_aux(
        &UnsignedEvent {
            kind: 1,
            content: "móving to a new 🔑".into(),
            tags: vec![vec!["t".into(), "did".into()]],
            ..Default::default()
        },
        &alice.secret_hex,
        &[0u8; 32],
    )
    .unwrap();
    let attestation = create_attestation(
        &AttestationInput {
            subject: alice.pubkey.clone(),
            claims: vec![Claim::new("name", "alice")],
            method: "in-person".into(),
            ..Default::default()
        },
        &bob.secret_hex,
    )
    .unwrap();
    let gset = create_guardian_set(
        &GuardianSetInput {
            guardians: vec![generate_identity().pubkey, generate_identity().pubkey],
            threshold: 2,
            created_at: None,
        },
        &alice.secret_hex,
    )
    .unwrap();
    let claim = create_rotation_claim(
        &RotationClaimInput {
            old_pubkey: alice.pubkey.clone(),
            reason: "planned".into(),
            ..Default::default()
        },
        &generate_identity().secret_hex,
    )
    .unwrap();

    for ev in [&note, &attestation, &gset, &claim] {
        cross_verify(ev);
    }
}

#[test]
fn shared_valid_events_verify_under_rust_nostr() {
    let v: Value = serde_json::from_str(include_str!("vectors/events.json")).unwrap();
    for c in v["valid_events"].as_array().unwrap() {
        let parsed = parse(&serde_json::to_string(&c["event"]).unwrap());
        assert!(
            parsed.verify().is_ok(),
            "rust-nostr rejected vector {}",
            c["name"].as_str().unwrap()
        );
    }
}

#[test]
fn rust_nostr_also_rejects_the_any_invalid_events() {
    let v: Value = serde_json::from_str(include_str!("vectors/events.json")).unwrap();
    for c in v["invalid_events"].as_array().unwrap() {
        if c["rejected_by"].as_str() != Some("any") {
            continue; // 'did'-only cases: a permissive verifier accepts them
        }
        let json = serde_json::to_string(&c["event"]).unwrap();
        let accepted = serde_json::from_str::<Event>(&json)
            .map(|e| e.verify().is_ok())
            .unwrap_or(false);
        assert!(
            !accepted,
            "rust-nostr accepted {}",
            c["name"].as_str().unwrap()
        );
    }
}
