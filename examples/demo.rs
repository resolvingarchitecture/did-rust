//! End-to-end walkthrough of did-rust. Run with:
//!
//!     cargo run --example demo
//!
//! It creates identities, has one vouch for another, produces the did:nostr view,
//! then loses a key and recovers it through guardians — printing each signed
//! event so you can see exactly what goes on the wire.

use did_nostr::*;

fn rule(s: &str) {
    println!("\n---- {s} {}", "-".repeat(40usize.saturating_sub(s.len())));
}

fn show(label: &str, ev: &NostrEvent) {
    let v = verify_event(ev);
    let status = if v.ok {
        "ok".to_string()
    } else {
        format!("FAIL step {:?} ({:?})", v.step, v.reason)
    };
    println!("{label}  [kind {}]  verify: {status}", ev.kind);
    println!("{}", serde_json::to_string(ev).unwrap());
}

fn main() {
    // 1. Identities
    rule("identities");
    let alice = generate_identity();
    let bob = generate_identity();
    println!("alice  hex  {}", alice.pubkey);
    println!("       npub {}", hex_to_npub(&alice.pubkey).unwrap());
    println!("       did  {}", hex_to_did(&alice.pubkey).unwrap());
    println!("bob    hex  {}", bob.pubkey);

    // 2. Attestation: bob vouches for alice's name, in person
    rule("attestation (bob -> alice)");
    let attestation = create_attestation(
        &AttestationInput {
            subject: alice.pubkey.clone(),
            claims: vec![
                Claim::new("name", "Alice"),
                Claim::new("nip05", "alice@example.com"),
            ],
            method: "in-person".into(),
            ..Default::default()
        },
        &bob.secret_hex,
    )
    .unwrap();
    show("bob's attestation", &attestation);
    println!("parsed: {:?}", parse_attestation(&attestation).unwrap());

    // 3. The did:nostr view of alice
    rule("did:nostr document for alice");
    println!(
        "{}",
        serde_json::to_string_pretty(
            &did_document(&alice.pubkey, &["wss://relay.example.com".to_string()]).unwrap()
        )
        .unwrap()
    );

    // 4. Alice designates guardians
    rule("guardian set");
    let (g1, g2, g3) = (
        generate_identity(),
        generate_identity(),
        generate_identity(),
    );
    let t0 = 1_700_000_000; // pretend the set has been in place a long time
    let guardian_set = create_guardian_set(
        &GuardianSetInput {
            guardians: vec![g1.pubkey.clone(), g2.pubkey.clone(), g3.pubkey.clone()],
            threshold: 2,
            created_at: Some(t0),
        },
        &alice.secret_hex,
    )
    .unwrap();
    show("alice's guardian set (M=2 of 3)", &guardian_set);

    // 5. Alice loses her key. A new key claims succession, two guardians endorse.
    rule("recovery");
    let alice_new = generate_identity();
    let claim_at = t0 + DEFAULT_COOLDOWN_SECONDS + 86_400; // well past the cool-down
    let claim = create_rotation_claim(
        &RotationClaimInput {
            old_pubkey: alice.pubkey.clone(),
            reason: "lost".into(),
            created_at: Some(claim_at),
            ..Default::default()
        },
        &alice_new.secret_hex,
    )
    .unwrap();
    let endorse1 = create_rotation_attestation(
        &RotationAttestationInput {
            old_pubkey: alice.pubkey.clone(),
            new_pubkey: alice_new.pubkey.clone(),
            method: "in-person".into(),
            created_at: Some(claim_at + 3600),
        },
        &g1.secret_hex,
    )
    .unwrap();
    let endorse2 = create_rotation_attestation(
        &RotationAttestationInput {
            old_pubkey: alice.pubkey.clone(),
            new_pubkey: alice_new.pubkey.clone(),
            method: "existing-channel".into(),
            created_at: Some(claim_at + 7200),
        },
        &g2.secret_hex,
    )
    .unwrap();
    show("rotation claim (signed by the new key)", &claim);
    show("guardian 1 endorses", &endorse1);
    show("guardian 2 endorses", &endorse2);

    let verdict = evaluate_rotation(
        &[guardian_set, claim, endorse1, endorse2],
        &EvaluateOptions::default(),
    );
    rule("verdict");
    println!("{verdict:#?}");
    if verdict.accepted {
        println!(
            "\nalice's identity is now {}\n(a client migrates follows, contacts and prior attestations, and shows the identity as rotated)",
            hex_to_npub(verdict.new.as_ref().unwrap()).unwrap()
        );
    } else {
        println!("\nrotation NOT accepted");
    }
}
