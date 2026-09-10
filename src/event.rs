//! Signed records (`DESIGN.md` §2): Nostr events with a BIP-340 Schnorr
//! signature, and the normative four-step verification order.

use crate::error::{Error, Result};
use crate::keys::{hex64_ok, is_valid_pubkey, public_key_from_secret};
use crate::kinds::validate_kind;
use crate::serialize::{compute_id, EventTemplate};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A fully signed Nostr event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrEvent {
    pub(crate) fn template(&self) -> EventTemplate {
        EventTemplate {
            pubkey: self.pubkey.clone(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
        }
    }

    /// First value of the first tag named `name`.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(name))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    }

    /// Second value of every tag named `name`.
    pub fn tag_values(&self, name: &str) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|t| t.len() > 1 && t[0] == name)
            .map(|t| t[1].as_str())
            .collect()
    }

    /// Whether any tag is named `name`.
    pub fn has_tag(&self, name: &str) -> bool {
        self.tags
            .iter()
            .any(|t| t.first().map(String::as_str) == Some(name))
    }
}

/// Fields a caller supplies; `pubkey`, `id` and `sig` are filled in by [`sign_event`].
#[derive(Debug, Clone, Default)]
pub struct UnsignedEvent {
    pub created_at: Option<i64>,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// Current unix time in whole seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    if !hex64_ok(s) {
        return Err(Error::Format("expected 64 lowercase hex chars".into()));
    }
    let v = hex::decode(s).map_err(|e| Error::Format(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Sign an event with a 32-byte secret hex.
///
/// `aux_rand` defaults to 32 zero bytes, which makes signatures byte-for-byte
/// reproducible (this is how `did-vectors` is generated). Pass real randomness in
/// production if you prefer; verification never depends on how a signature was
/// produced.
pub fn sign_event(ev: &UnsignedEvent, secret_hex: &str) -> Result<NostrEvent> {
    sign_event_with_aux(ev, secret_hex, &[0u8; 32])
}

pub fn sign_event_with_aux(
    ev: &UnsignedEvent,
    secret_hex: &str,
    aux_rand: &[u8; 32],
) -> Result<NostrEvent> {
    let template = EventTemplate {
        pubkey: public_key_from_secret(secret_hex)?,
        created_at: ev.created_at.unwrap_or_else(now),
        kind: ev.kind,
        tags: ev.tags.clone(),
        content: ev.content.clone(),
    };
    let id = compute_id(&template);
    let sk = SecretKey::from_slice(&decode_hex32(secret_hex)?)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let kp = Keypair::from_secret_key(SECP256K1, &sk);
    let sig = SECP256K1.sign_schnorr_with_aux_rand(&decode_hex32(&id)?, &kp, aux_rand);
    Ok(NostrEvent {
        id,
        pubkey: template.pubkey,
        created_at: template.created_at,
        kind: template.kind,
        tags: template.tags,
        content: template.content,
        sig: hex::encode(sig.to_byte_array()),
    })
}

/// Which verification step failed, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub ok: bool,
    /// The verification step (1–4) that failed; `None` on success.
    pub step: Option<u8>,
    pub reason: Option<String>,
}

impl VerifyResult {
    fn pass() -> Self {
        Self {
            ok: true,
            step: None,
            reason: None,
        }
    }
    fn fail(step: u8, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            step: Some(step),
            reason: Some(reason.into()),
        }
    }
}

/// Verify an event against `DESIGN.md` §2.2. Steps run in order and the first
/// failure is returned:
///
///   1. `pubkey` is 64 lowercase hex over a valid x-only point
///   2. the recomputed `id` equals the stated `id` (and the stated `id` is
///      itself 64 lowercase hex)
///   3. the Schnorr signature verifies over the 32 raw `id` bytes
///   4. kind-specific validation (§3, §4)
///
/// Step 2 is not optional: an event whose `id` does not match its content is
/// malformed even if the signature verifies against the stated `id`.
pub fn verify_event(ev: &NostrEvent) -> VerifyResult {
    // Step 1
    if !hex64_ok(&ev.pubkey) {
        return VerifyResult::fail(1, "pubkey is not 64 lowercase hex chars");
    }
    if !is_valid_pubkey(&ev.pubkey) {
        return VerifyResult::fail(1, "pubkey is not a valid x-only point");
    }

    // Step 2
    if !hex64_ok(&ev.id) {
        return VerifyResult::fail(2, "id is not 64 lowercase hex chars");
    }
    let recomputed = compute_id(&ev.template());
    if recomputed != ev.id {
        return VerifyResult::fail(2, format!("id mismatch: computed {recomputed}"));
    }

    // Step 3
    if ev.sig.len() != 128
        || !ev
            .sig
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return VerifyResult::fail(3, "sig is not 128 lowercase hex chars");
    }
    if !schnorr_verify_raw(&ev.sig, &ev.id, &ev.pubkey) {
        return VerifyResult::fail(3, "Schnorr signature does not verify");
    }

    // Step 4
    if let Err(reason) = validate_kind(ev) {
        return VerifyResult::fail(4, reason);
    }

    VerifyResult::pass()
}

/// Convenience wrapper: `Err` with the failing step if verification fails.
pub fn assert_valid(ev: &NostrEvent) -> Result<()> {
    let r = verify_event(ev);
    if r.ok {
        Ok(())
    } else {
        Err(Error::Input(format!(
            "event verification failed at step {}: {}",
            r.step.unwrap_or(0),
            r.reason.unwrap_or_default()
        )))
    }
}

/// BIP-340 verify of an arbitrary 32-byte message (used by `prev-sig`, §4.2).
pub fn schnorr_verify_raw(sig_hex: &str, msg32_hex: &str, pubkey_hex: &str) -> bool {
    let (Ok(sig_bytes), Ok(msg), Ok(pk_bytes)) = (
        hex_decode_len(sig_hex, 64),
        decode_hex32(msg32_hex),
        decode_hex32(pubkey_hex),
    ) else {
        return false;
    };
    let (Ok(sig), Ok(pk)) = (
        Signature::from_slice(&sig_bytes),
        XOnlyPublicKey::from_slice(&pk_bytes),
    ) else {
        return false;
    };
    SECP256K1.verify_schnorr(&sig, &msg, &pk).is_ok()
}

/// BIP-340 sign of an arbitrary 32-byte message (used to build a `prev-sig`).
pub fn schnorr_sign_raw(msg32_hex: &str, secret_hex: &str) -> Result<String> {
    schnorr_sign_raw_with_aux(msg32_hex, secret_hex, &[0u8; 32])
}

pub fn schnorr_sign_raw_with_aux(
    msg32_hex: &str,
    secret_hex: &str,
    aux_rand: &[u8; 32],
) -> Result<String> {
    let msg = decode_hex32(msg32_hex)?;
    let sk = SecretKey::from_slice(&decode_hex32(secret_hex)?)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let kp = Keypair::from_secret_key(SECP256K1, &sk);
    let sig = SECP256K1.sign_schnorr_with_aux_rand(&msg, &kp, aux_rand);
    Ok(hex::encode(sig.to_byte_array()))
}

fn hex_decode_len(s: &str, n: usize) -> Result<Vec<u8>> {
    let v = hex::decode(s).map_err(|e| Error::Format(e.to_string()))?;
    if v.len() != n {
        return Err(Error::Format(format!("expected {n} bytes")));
    }
    Ok(v)
}

/// sha256, exposed for callers that need the raw digest.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
