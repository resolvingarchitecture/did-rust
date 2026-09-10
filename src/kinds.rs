//! The four DID event kinds and their kind-specific validation (`DESIGN.md`
//! §3–§4, verification step 4).
//!
//! The kind numbers are PROVISIONAL (`DESIGN.md` §8). They live here, in one
//! place, so that a reassignment through the NIP process is a one-line change.

use crate::event::NostrEvent;
use crate::keys::hex64_ok;

pub const KIND_IDENTITY_ATTESTATION: u32 = 30100;
pub const KIND_GUARDIAN_SET: u32 = 30101;
pub const KIND_ROTATION_ATTESTATION: u32 = 30102;
pub const KIND_ROTATION_CLAIM: u32 = 30103;

pub const DID_KINDS: [u32; 4] = [
    KIND_IDENTITY_ATTESTATION,
    KIND_GUARDIAN_SET,
    KIND_ROTATION_ATTESTATION,
    KIND_ROTATION_CLAIM,
];

/// §3.2 verification methods. Unknown methods are treated as no stronger than `asserted`.
pub const METHODS: [&str; 5] = [
    "in-person",
    "qr",
    "existing-channel",
    "guardian",
    "asserted",
];

/// §3.3 reserved claim attributes. `claim` attributes are otherwise open.
pub const CLAIM_ATTRIBUTES: [&str; 4] = ["name", "same-as", "nip05", "not"];

/// §4.2 rotation reasons.
pub const ROTATION_REASONS: [&str; 3] = ["lost", "compromised", "planned"];

type Check = Result<(), String>;

/// Step 4: kind-specific validation. An event whose `kind` is not one of the DID
/// kinds passes here unconditionally — this library does not police generic
/// Nostr events.
pub fn validate_kind(ev: &NostrEvent) -> Check {
    match ev.kind {
        KIND_IDENTITY_ATTESTATION => validate_attestation(ev),
        KIND_GUARDIAN_SET => validate_guardian_set(ev),
        KIND_ROTATION_ATTESTATION => validate_rotation_attestation(ev),
        KIND_ROTATION_CLAIM => validate_rotation_claim(ev),
        _ => Ok(()),
    }
}

fn validate_attestation(ev: &NostrEvent) -> Check {
    let d = ev.tag("d");
    let p = ev.tag("p");
    match d {
        Some(v) if hex64_ok(v) => {}
        _ => return Err("kind 30100: `d` MUST be the subject pubkey (64 lowercase hex)".into()),
    }
    match p {
        Some(v) if hex64_ok(v) => {}
        _ => return Err("kind 30100: `p` MUST be the subject pubkey (64 lowercase hex)".into()),
    }
    if d != p {
        return Err("kind 30100: `d` and `p` MUST both be the subject pubkey".into());
    }

    let revoked = ev.has_tag("revoked");
    let claims: Vec<&Vec<String>> = ev
        .tags
        .iter()
        .filter(|t| t.first().map(String::as_str) == Some("claim"))
        .collect();

    if revoked {
        if !claims.is_empty() {
            return Err("kind 30100: a revocation MUST carry no `claim` tags".into());
        }
        return Ok(());
    }
    if claims.is_empty() {
        return Err("kind 30100: requires >=1 `claim` tag".into());
    }
    for c in &claims {
        if c.len() < 3 {
            return Err("kind 30100: each `claim` tag is [\"claim\", <attribute>, <value>]".into());
        }
    }
    if !ev.has_tag("method") {
        return Err("kind 30100: requires a `method` tag".into());
    }
    Ok(())
}

fn validate_guardian_set(ev: &NostrEvent) -> Check {
    if ev.tag("d") != Some("guardians") {
        return Err("kind 30101: `d` MUST be the literal \"guardians\"".into());
    }
    let guardians = ev.tag_values("p");
    if guardians.is_empty() {
        return Err("kind 30101: requires >=1 `p` (guardian) tag".into());
    }
    if guardians.iter().any(|g| !hex64_ok(g)) {
        return Err("kind 30101: guardian pubkeys MUST be 64 lowercase hex".into());
    }
    let mut uniq = guardians.clone();
    uniq.sort_unstable();
    uniq.dedup();
    if uniq.len() != guardians.len() {
        return Err("kind 30101: duplicate guardian pubkey".into());
    }
    let m = match ev.tag("threshold") {
        Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s
            .parse::<u64>()
            .map_err(|_| "kind 30101: `threshold` out of range".to_string())?,
        _ => return Err("kind 30101: requires an integer `threshold`".into()),
    };
    if m < 1 || m > guardians.len() as u64 {
        return Err("kind 30101: requires 1 <= M <= N".into());
    }
    Ok(())
}

fn validate_rotation_attestation(ev: &NostrEvent) -> Check {
    for (name, label) in [
        ("d", "old pubkey"),
        ("p", "old pubkey"),
        ("new", "endorsed pubkey"),
    ] {
        match ev.tag(name) {
            Some(v) if hex64_ok(v) => {}
            _ => {
                return Err(format!(
                    "kind 30102: `{name}` MUST be the {label} (64 lowercase hex)"
                ))
            }
        }
    }
    if !ev.has_tag("method") {
        return Err("kind 30102: requires a `method` tag".into());
    }
    Ok(())
}

fn validate_rotation_claim(ev: &NostrEvent) -> Check {
    for name in ["d", "p"] {
        match ev.tag(name) {
            Some(v) if hex64_ok(v) => {}
            _ => {
                return Err(format!(
                    "kind 30103: `{name}` MUST be the old pubkey (64 lowercase hex)"
                ))
            }
        }
    }
    match ev.tag("reason") {
        Some(r) if ROTATION_REASONS.contains(&r) => Ok(()),
        _ => Err("kind 30103: `reason` MUST be lost|compromised|planned".into()),
    }
}
