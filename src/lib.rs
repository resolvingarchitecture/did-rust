//! `did-rust` — a small, dependency-light reference implementation of Resolving
//! Architecture's DID design: secp256k1 / BIP-340 identities, Nostr-compatible
//! signed records, attestations as a decentralised replacement for NIP-05, and
//! guardian-based key recovery and rotation.
//!
//! Spec: `../DESIGN.md`. Conformance suite: `did-vectors` (vendored in
//! `tests/vectors`). Public domain (CC0 1.0).

pub mod attestation;
pub mod diddoc;
pub mod error;
pub mod event;
pub mod keys;
pub mod kinds;
pub mod rotation;
pub mod serialize;

pub use error::{Error, Result};

pub use serialize::{compute_id, preimage_bytes, serialize_event, serialize_string, EventTemplate};

pub use keys::{
    did_to_hex, generate_identity, hex_to_did, hex_to_npub, is_valid_pubkey, normalize_pubkey,
    npub_to_hex, nsec_to_secret, public_key_from_secret, secret_to_nsec, Identity,
};

pub use event::{
    assert_valid, now, schnorr_sign_raw, schnorr_sign_raw_with_aux, schnorr_verify_raw, sha256,
    sign_event, sign_event_with_aux, verify_event, NostrEvent, UnsignedEvent, VerifyResult,
};

pub use kinds::{
    validate_kind, CLAIM_ATTRIBUTES, DID_KINDS, KIND_GUARDIAN_SET, KIND_IDENTITY_ATTESTATION,
    KIND_ROTATION_ATTESTATION, KIND_ROTATION_CLAIM, METHODS, ROTATION_REASONS,
};

pub use attestation::{
    create_attestation, create_attestation_with_aux, is_expired, parse_attestation,
    revoke_attestation, AttestationInput, Claim, ParsedAttestation,
};

pub use rotation::{
    create_guardian_set, create_rotation_attestation, create_rotation_claim, evaluate_rotation,
    prev_sig, EvaluateOptions, GuardianSetInput, RotationAttestationInput, RotationClaimInput,
    RotationVerdict, DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_COOLDOWN_SECONDS,
};

pub use diddoc::{
    did_document, multikey_to_xonly, xonly_to_multikey, DidDocument, Service, VerificationMethod,
};
