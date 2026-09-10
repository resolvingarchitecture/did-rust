//! The identity primitive (`DESIGN.md` §1): one secp256k1 keypair, x-only public
//! key per BIP-340, and its encodings.
//!
//!   - lowercase hex (64 chars) — canonical; the only form used in preimages
//!   - `npub1…` / `nsec1…` — Bech32 (NIP-19), for display and export only
//!   - `did:nostr:<hex>` — the W3C view (§5)
//!
//! `secp256k1` (libsecp256k1, the same primitive rust-nostr builds on) provides
//! BIP-340 Schnorr; there is no hand-rolled elliptic-curve code here and there
//! must never be.

use crate::error::{Error, Result};
use bech32::{Bech32, Hrp};
use secp256k1::rand::thread_rng;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};

/// One identity: a 32-byte secret and its x-only public key, both lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// 32-byte secret scalar, lowercase hex. Treat as sensitive — see §6.3.
    pub secret_hex: String,
    /// 32-byte x-only public key, lowercase hex. The canonical identifier.
    pub pubkey: String,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    if !is_hex64(s) {
        return Err(Error::Format(format!(
            "{what} must be 64 lowercase hex chars"
        )));
    }
    let v = hex::decode(s).map_err(|e| Error::Format(format!("{what}: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// True if `s` is 64 lowercase hex chars over a valid x-only curve point.
pub fn is_valid_pubkey(s: &str) -> bool {
    match decode_hex32(s, "pubkey") {
        Ok(b) => XOnlyPublicKey::from_slice(&b).is_ok(),
        Err(_) => false,
    }
}

/// Generate a fresh identity from the platform CSPRNG.
pub fn generate_identity() -> Identity {
    let (sk, _) = SECP256K1.generate_keypair(&mut thread_rng());
    identity_from_secret_key(&sk)
}

fn identity_from_secret_key(sk: &SecretKey) -> Identity {
    let kp = Keypair::from_secret_key(SECP256K1, sk);
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&kp);
    Identity {
        secret_hex: hex::encode(sk.secret_bytes()),
        pubkey: hex::encode(xonly.serialize()),
    }
}

/// Derive the x-only public key (lowercase hex) from a 32-byte secret hex.
pub fn public_key_from_secret(secret_hex: &str) -> Result<String> {
    let bytes = decode_hex32(secret_hex, "secret key")?;
    let sk =
        SecretKey::from_slice(&bytes).map_err(|e| Error::Crypto(format!("secret key: {e}")))?;
    Ok(identity_from_secret_key(&sk).pubkey)
}

// --- encodings -----------------------------------------------------------

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("static hrp is valid");
    bech32::encode::<Bech32>(hrp, data).expect("32-byte payload encodes")
}

fn bech32_decode(s: &str, want: &str) -> Result<[u8; 32]> {
    let (hrp, data) = bech32::decode(s).map_err(|e| Error::Format(format!("bech32: {e}")))?;
    if hrp.as_str() != want {
        return Err(Error::Format(format!(
            "expected an {want}, got {}",
            hrp.as_str()
        )));
    }
    if data.len() != 32 {
        return Err(Error::Format(format!(
            "{want} does not decode to a 32-byte key"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Ok(out)
}

/// hex → `npub1…`
pub fn hex_to_npub(pubkey_hex: &str) -> Result<String> {
    let b = decode_hex32(pubkey_hex, "pubkey")?;
    Ok(bech32_encode("npub", &b))
}

/// `npub1…` → hex. Rejects any other prefix.
pub fn npub_to_hex(npub: &str) -> Result<String> {
    Ok(hex::encode(bech32_decode(npub, "npub")?))
}

/// secret hex → `nsec1…`.
///
/// Per §1.1 / §6.3 an implementation MUST NOT surface `nsec` incidentally. This
/// function exists so an export flow can call it deliberately; it is never used
/// by the library itself and callers MUST gate it behind explicit confirmation.
pub fn secret_to_nsec(secret_hex: &str) -> Result<String> {
    let b = decode_hex32(secret_hex, "secret key")?;
    Ok(bech32_encode("nsec", &b))
}

/// `nsec1…` → secret hex.
pub fn nsec_to_secret(nsec: &str) -> Result<String> {
    Ok(hex::encode(bech32_decode(nsec, "nsec")?))
}

/// hex or `npub1…` → canonical lowercase hex. Accepts what §1.1 says to accept.
pub fn normalize_pubkey(input: &str) -> Result<String> {
    let s = input.trim();
    if s.starts_with("npub1") {
        return npub_to_hex(s);
    }
    if let Some(rest) = s.strip_prefix("did:nostr:") {
        if is_hex64(rest) {
            return Ok(rest.to_string());
        }
    }
    let lower = s.to_ascii_lowercase();
    if !is_hex64(&lower) {
        return Err(Error::Format("expected 64 hex chars or an npub".into()));
    }
    Ok(lower)
}

/// hex → `did:nostr:<hex>` (§5.1 — hex, not npub).
pub fn hex_to_did(pubkey_hex: &str) -> Result<String> {
    if !is_hex64(pubkey_hex) {
        return Err(Error::Format(
            "pubkey must be 64 lowercase hex chars".into(),
        ));
    }
    Ok(format!("did:nostr:{pubkey_hex}"))
}

/// `did:nostr:<hex>` → hex.
pub fn did_to_hex(did: &str) -> Result<String> {
    match did.strip_prefix("did:nostr:") {
        Some(hex) if is_hex64(hex) => Ok(hex.to_string()),
        _ => Err(Error::Format(
            "expected did:nostr:<64 lowercase hex>".into(),
        )),
    }
}

pub(crate) fn hex64_ok(s: &str) -> bool {
    is_hex64(s)
}
