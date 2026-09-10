//! Identity attestations — the `vouch` primitive (`DESIGN.md` §3,
//! drafts/attestations.md).
//!
//! Kind 30100, signed by the attester, addressable on the subject's pubkey so an
//! attester holds exactly one current attestation per subject.

use crate::error::{Error, Result};
use crate::event::{sign_event_with_aux, NostrEvent, UnsignedEvent};
use crate::keys::normalize_pubkey;
use crate::kinds::KIND_IDENTITY_ATTESTATION;

/// One asserted attribute of the subject. The attribute list is open (§3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub attribute: String,
    pub value: String,
}

impl Claim {
    pub fn new(attribute: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            attribute: attribute.into(),
            value: value.into(),
        }
    }
}

/// What a caller supplies to build a kind 30100 Identity Attestation.
#[derive(Debug, Clone, Default)]
pub struct AttestationInput {
    /// The key being vouched for (hex or npub).
    pub subject: String,
    /// At least one claim.
    pub claims: Vec<Claim>,
    /// How the attester verified (§3.2).
    pub method: String,
    /// Optional NIP-40 expiration, unix seconds.
    pub expiration: Option<i64>,
    pub created_at: Option<i64>,
}

/// Build and sign a kind 30100 Identity Attestation.
pub fn create_attestation(
    input: &AttestationInput,
    attester_secret_hex: &str,
) -> Result<NostrEvent> {
    create_attestation_with_aux(input, attester_secret_hex, &[0u8; 32])
}

pub fn create_attestation_with_aux(
    input: &AttestationInput,
    attester_secret_hex: &str,
    aux_rand: &[u8; 32],
) -> Result<NostrEvent> {
    if input.claims.is_empty() {
        return Err(Error::Input(
            "an attestation needs at least one claim".into(),
        ));
    }
    let subject = normalize_pubkey(&input.subject)?;
    let mut tags: Vec<Vec<String>> =
        vec![vec!["d".into(), subject.clone()], vec!["p".into(), subject]];
    for c in &input.claims {
        tags.push(vec!["claim".into(), c.attribute.clone(), c.value.clone()]);
    }
    tags.push(vec!["method".into(), input.method.clone()]);
    if let Some(exp) = input.expiration {
        tags.push(vec!["expiration".into(), exp.to_string()]);
    }
    sign_event_with_aux(
        &UnsignedEvent {
            created_at: input.created_at,
            kind: KIND_IDENTITY_ATTESTATION,
            tags,
            content: String::new(),
        },
        attester_secret_hex,
        aux_rand,
    )
}

/// Build and sign a revocation: the addressable event is replaced with one that
/// carries `["revoked", <reason>]` and no `claim` tags (§3.4). A verifier MUST
/// treat this differently from a missing attestation.
pub fn revoke_attestation(
    subject: &str,
    reason: &str,
    attester_secret_hex: &str,
    created_at: Option<i64>,
) -> Result<NostrEvent> {
    let s = normalize_pubkey(subject)?;
    sign_event_with_aux(
        &UnsignedEvent {
            created_at,
            kind: KIND_IDENTITY_ATTESTATION,
            tags: vec![
                vec!["d".into(), s.clone()],
                vec!["p".into(), s],
                vec!["revoked".into(), reason.into()],
            ],
            content: String::new(),
        },
        attester_secret_hex,
        &[0u8; 32],
    )
}

// --- reading -----------------------------------------------------------

/// Structured view of a kind 30100 event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAttestation {
    pub attester: String,
    pub subject: String,
    pub claims: Vec<Claim>,
    pub method: Option<String>,
    pub expiration: Option<i64>,
    pub revoked: Option<String>,
}

/// Structured view of a kind 30100 event. Does not verify — call
/// [`crate::verify_event`] first.
pub fn parse_attestation(ev: &NostrEvent) -> Result<ParsedAttestation> {
    if ev.kind != KIND_IDENTITY_ATTESTATION {
        return Err(Error::Input(format!(
            "not a kind {KIND_IDENTITY_ATTESTATION} event"
        )));
    }
    Ok(ParsedAttestation {
        attester: ev.pubkey.clone(),
        subject: ev.tag("d").unwrap_or("").to_string(),
        claims: ev
            .tags
            .iter()
            .filter(|t| t.first().map(String::as_str) == Some("claim") && t.len() >= 3)
            .map(|t| Claim::new(t[1].clone(), t[2].clone()))
            .collect(),
        method: ev.tag("method").map(str::to_string),
        expiration: ev.tag("expiration").and_then(|s| s.parse().ok()),
        revoked: ev.tag("revoked").map(str::to_string),
    })
}

/// Is this attestation past its NIP-40 `expiration` at `at`?
pub fn is_expired(ev: &NostrEvent, at: i64) -> bool {
    ev.tag("expiration")
        .and_then(|s| s.parse::<i64>().ok())
        .map(|exp| exp <= at)
        .unwrap_or(false)
}
