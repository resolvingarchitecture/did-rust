//! `did:nostr` compatibility (`DESIGN.md` §5).
//!
//! RA does not define a DID method. This produces the `did:nostr` *view* of a key
//! it already holds, offline, from the public key alone — the draft's "minimal
//! resolution". No HTTP `.well-known` tier (§5.3): that reintroduces a domain as
//! a trust anchor, which §3 exists to remove.
//!
//! The `did:nostr` method is an unratified community draft. Re-verify these
//! details against the current draft before relying on them.

use crate::error::{Error, Result};
use crate::keys::normalize_pubkey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
}

/// Multikey encoding of an x-only key (§5.2):
///
///   1. x-only (32 bytes) -> compressed secp256k1 (33 bytes) by prepending 0x02
///   2. prepend the multicodec varint for secp256k1-pub: 0xe7 0x01
///   3. multibase base16-lower: prefix `f`, then lowercase hex
///
/// i.e. `publicKeyMultibase` = `f` + `e701` + `02` + `<x-only hex>`.
pub fn xonly_to_multikey(pubkey_hex: &str) -> Result<String> {
    let hex = normalize_pubkey(pubkey_hex)?;
    Ok(format!("fe70102{hex}"))
}

/// Decode a Multikey string back to x-only hex, or error if it is not the expected shape.
pub fn multikey_to_xonly(multikey: &str) -> Result<String> {
    match multikey.strip_prefix("fe70102") {
        Some(hex)
            if hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Ok(hex.to_string())
        }
        _ => Err(Error::Format(
            "not an x-only secp256k1 Multikey (f e701 02 <hex>)".into(),
        )),
    }
}

/// Produce the `did:nostr` document for a public key, offline. `relays`, when
/// non-empty, adds an OPTIONAL `service` entry ("enhanced resolution").
pub fn did_document(pubkey: &str, relays: &[String]) -> Result<DidDocument> {
    let hex = normalize_pubkey(pubkey)?;
    let did = format!("did:nostr:{hex}");
    let vm_id = format!("{did}#0");
    let mut doc = DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/multikey/v1".into(),
        ],
        id: did.clone(),
        type_: "DIDNostr".into(),
        verification_method: vec![VerificationMethod {
            id: vm_id.clone(),
            type_: "Multikey".into(),
            controller: did.clone(),
            public_key_multibase: xonly_to_multikey(&hex)?,
        }],
        authentication: vec![vm_id.clone()],
        assertion_method: vec![vm_id],
        service: None,
    };
    if !relays.is_empty() {
        doc.service = Some(vec![Service {
            id: format!("{did}#relays"),
            type_: "NostrRelays".into(),
            service_endpoint: relays.to_vec(),
        }]);
    }
    Ok(doc)
}
