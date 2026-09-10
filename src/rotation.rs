//! Guardians, rotation and recovery (`DESIGN.md` §4, drafts/social-recovery.md).
//!
//!   - kind 30101 Guardian Set         — signed by the root identity
//!   - kind 30103 Rotation Claim       — signed by the new key
//!   - kind 30102 Rotation Attestation — signed by a guardian, one per guardian
//!
//! Plus [`evaluate_rotation`], the normative acceptance rule (§4.3). This is a
//! direct port of `did-vectors/acceptance.py`; the two are kept in step.

use std::collections::{HashMap, HashSet};

use crate::error::{Error, Result};
use crate::event::{
    schnorr_sign_raw, schnorr_verify_raw, sign_event_with_aux, NostrEvent, UnsignedEvent,
};
use crate::keys::{normalize_pubkey, public_key_from_secret};
use crate::kinds::{KIND_GUARDIAN_SET, KIND_ROTATION_ATTESTATION, KIND_ROTATION_CLAIM};

/// Default guardian-set cool-down: 7 days, in seconds (§4.3 clause 5).
pub const DEFAULT_COOLDOWN_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Small allowance for a Rotation Claim dated slightly ahead of the verifier's clock.
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

// --- builders ----------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct GuardianSetInput {
    pub guardians: Vec<String>, // hex or npub
    pub threshold: u32,
    pub created_at: Option<i64>,
}

/// Build and sign a kind 30101 Guardian Set.
pub fn create_guardian_set(input: &GuardianSetInput, root_secret_hex: &str) -> Result<NostrEvent> {
    let guardians: Vec<String> = input
        .guardians
        .iter()
        .map(|g| normalize_pubkey(g))
        .collect::<Result<_>>()?;
    if guardians.is_empty() {
        return Err(Error::Input(
            "a guardian set needs at least one guardian".into(),
        ));
    }
    let mut uniq: Vec<&String> = guardians.iter().collect();
    uniq.sort();
    uniq.dedup();
    if uniq.len() != guardians.len() {
        return Err(Error::Input("duplicate guardian".into()));
    }
    if input.threshold < 1 || input.threshold as usize > guardians.len() {
        return Err(Error::Input("threshold must be an integer in 1..N".into()));
    }
    let mut tags: Vec<Vec<String>> = vec![vec!["d".into(), "guardians".into()]];
    for g in guardians {
        tags.push(vec!["p".into(), g]);
    }
    tags.push(vec!["threshold".into(), input.threshold.to_string()]);
    sign_event_with_aux(
        &UnsignedEvent {
            created_at: input.created_at,
            kind: KIND_GUARDIAN_SET,
            tags,
            content: String::new(),
        },
        root_secret_hex,
        &[0u8; 32],
    )
}

#[derive(Debug, Clone, Default)]
pub struct RotationClaimInput {
    pub old_pubkey: String, // hex or npub
    pub reason: String,
    /// Include a `prev-sig` when the old key is still held (self-authorised, §4.3).
    pub old_secret_hex_for_prev_sig: Option<String>,
    pub created_at: Option<i64>,
}

/// Build and sign a kind 30103 Rotation Claim (signed by the NEW key).
pub fn create_rotation_claim(
    input: &RotationClaimInput,
    new_secret_hex: &str,
) -> Result<NostrEvent> {
    let old = normalize_pubkey(&input.old_pubkey)?;
    let mut tags: Vec<Vec<String>> = vec![
        vec!["d".into(), old.clone()],
        vec!["p".into(), old.clone()],
        vec!["reason".into(), input.reason.clone()],
    ];
    if let Some(old_secret) = &input.old_secret_hex_for_prev_sig {
        let new_pubkey = public_key_from_secret(new_secret_hex)?;
        tags.push(vec![
            "prev-sig".into(),
            schnorr_sign_raw(&new_pubkey, old_secret)?,
        ]);
    }
    sign_event_with_aux(
        &UnsignedEvent {
            created_at: input.created_at,
            kind: KIND_ROTATION_CLAIM,
            tags,
            content: String::new(),
        },
        new_secret_hex,
        &[0u8; 32],
    )
}

#[derive(Debug, Clone, Default)]
pub struct RotationAttestationInput {
    pub old_pubkey: String, // hex or npub
    pub new_pubkey: String, // hex or npub
    pub method: String,
    pub created_at: Option<i64>,
}

/// Build and sign a kind 30102 Rotation Attestation (signed by a GUARDIAN).
pub fn create_rotation_attestation(
    input: &RotationAttestationInput,
    guardian_secret_hex: &str,
) -> Result<NostrEvent> {
    let old = normalize_pubkey(&input.old_pubkey)?;
    let new = normalize_pubkey(&input.new_pubkey)?;
    sign_event_with_aux(
        &UnsignedEvent {
            created_at: input.created_at,
            kind: KIND_ROTATION_ATTESTATION,
            tags: vec![
                vec!["d".into(), old.clone()],
                vec!["p".into(), old],
                vec!["new".into(), new],
                vec!["method".into(), input.method.clone()],
            ],
            content: String::new(),
        },
        guardian_secret_hex,
        &[0u8; 32],
    )
}

/// Compute a `prev-sig`: BIP-340 by the old key over the 32 raw new-pubkey bytes.
pub fn prev_sig(new_pubkey_hex: &str, old_secret_hex: &str) -> Result<String> {
    schnorr_sign_raw(&normalize_pubkey(new_pubkey_hex)?, old_secret_hex)
}

// --- the acceptance rule (§4.3) --------------------------------------

/// The verdict [`evaluate_rotation`] reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationVerdict {
    pub accepted: bool,
    pub reason: String,
    /// On acceptance: the successor key a client should migrate to.
    pub new: Option<String>,
    /// On acceptance: the key being rotated away from.
    pub old: Option<String>,
}

impl RotationVerdict {
    fn reject(reason: impl Into<String>) -> Self {
        Self {
            accepted: false,
            reason: reason.into(),
            new: None,
            old: None,
        }
    }
    fn accept(reason: impl Into<String>, new: String, old: String) -> Self {
        Self {
            accepted: true,
            reason: reason.into(),
            new: Some(new),
            old: Some(old),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvaluateOptions {
    pub cooldown_seconds: i64,
    /// Verifier's notion of "now"; a claim dated beyond this + skew is rejected.
    pub now: Option<i64>,
    pub clock_skew_seconds: i64,
}

impl Default for EvaluateOptions {
    fn default() -> Self {
        Self {
            cooldown_seconds: DEFAULT_COOLDOWN_SECONDS,
            now: None,
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }
}

/// Decide whether some `new` key is the accepted successor of some `old` key,
/// given a bag of events. Assumes every event is already well-formed and its
/// signature and id verified — run [`crate::verify_event`] on each first.
///
/// Mirrors `did-vectors/acceptance.py`.
pub fn evaluate_rotation(events: &[NostrEvent], opts: &EvaluateOptions) -> RotationVerdict {
    let cooldown = opts.cooldown_seconds;
    let skew = opts.clock_skew_seconds;

    // clause 4: a Rotation Claim (kind 30103). Take the earliest.
    let mut claims: Vec<&NostrEvent> = events
        .iter()
        .filter(|e| e.kind == KIND_ROTATION_CLAIM)
        .collect();
    claims.sort_by_key(|e| e.created_at);
    let Some(claim) = claims.first() else {
        return RotationVerdict::reject("clause 4: no kind 30103 Rotation Claim");
    };
    let Some(old) = claim.tag("d") else {
        return RotationVerdict::reject("clause 4: Rotation Claim has no `d` (old pubkey)");
    };
    let old = old.to_string();
    let next = claim.pubkey.clone();
    let ct = claim.created_at;
    if next == old {
        return RotationVerdict::reject(
            "clause 4: Rotation Claim does not name a distinct successor key",
        );
    }
    if let Some(n) = opts.now {
        if ct > n + skew {
            return RotationVerdict::reject("clause 5: Rotation Claim is dated in the future");
        }
    }

    // clause 4 (self-authorised): a valid prev-sig by old over the new pubkey.
    if let Some(ps) = claim.tag("prev-sig") {
        if schnorr_verify_raw(ps, &next, &old) {
            return RotationVerdict::accept(
                "self-authorised: valid prev-sig by old over new",
                next,
                old,
            );
        }
        // invalid prev-sig -> ignored; fall through to the guardian path
    }

    // clause 1: a Guardian Set (kind 30101, d=guardians) signed by old.
    let gsets: Vec<&NostrEvent> = events
        .iter()
        .filter(|e| {
            e.kind == KIND_GUARDIAN_SET && e.pubkey == old && e.tag("d") == Some("guardians")
        })
        .collect();
    if gsets.is_empty() {
        return RotationVerdict::reject("clause 1: no Guardian Set signed by old");
    }

    // clause 5: use the most recent set that is both current at the claim and past its cool-down.
    let eligible: Vec<&&NostrEvent> = gsets
        .iter()
        .filter(|g| g.created_at + cooldown <= ct)
        .collect();
    let Some(gset) = eligible.iter().max_by_key(|g| g.created_at) else {
        return RotationVerdict::reject(
            "clause 5: no Guardian Set is both current at the claim and past its cool-down",
        );
    };
    let guardians: HashSet<&str> = gset.tag_values("p").into_iter().collect();
    let threshold = match gset.tag("threshold").and_then(|s| {
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse::<i64>().ok()
        } else {
            None
        }
    }) {
        Some(t) => t,
        None => return RotationVerdict::reject("clause 1: Guardian Set has no valid threshold"),
    };
    if !(threshold >= 1 && threshold <= guardians.len() as i64) {
        return RotationVerdict::reject("clause 1: Guardian Set threshold out of range 1..N");
    }

    // clauses 2 + 3: >= M distinct guardians, each signing their own kind 30102
    //                for this old, all naming an identical new.
    let mut endorsers: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut ignored_non_guardian = 0usize;
    for a in events {
        if a.kind != KIND_ROTATION_ATTESTATION || a.tag("d") != Some(old.as_str()) {
            continue;
        }
        if !guardians.contains(a.pubkey.as_str()) {
            ignored_non_guardian += 1;
            continue;
        }
        let Some(n) = a.tag("new") else { continue };
        endorsers.entry(n).or_default().insert(a.pubkey.as_str());
    }

    let have = endorsers.get(next.as_str()).map(HashSet::len).unwrap_or(0) as i64;
    if have >= threshold {
        return RotationVerdict::accept(
            format!("guardian path: {have} of {threshold} distinct guardians endorsed new"),
            next,
            old,
        );
    }
    let note = if ignored_non_guardian > 0 {
        format!(" ({ignored_non_guardian} endorsement(s) ignored: not in guardian set)")
    } else {
        String::new()
    };
    RotationVerdict::reject(format!(
        "clause 2: {have} distinct guardians endorsed the claimed new key, need {threshold}{note}"
    ))
}
