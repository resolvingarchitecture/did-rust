# did-rust

A small, dependency-light implementation of [Resolving
Architecture](https://resolvingarchitecture.io)'s DID design, ported from the
[`did-ts`](https://github.com/resolvingarchitecture/did-ts) reference:

- one **secp256k1 / BIP-340** keypair as an identity, with `hex` / `npub` /
  `nsec` / `did:nostr` encodings;
- **Nostr-compatible signed records** with the exact canonical serialisation that
  makes signatures reproduce across implementations;
- **attestations** — the `vouch` primitive, a decentralised replacement for
  NIP-05;
- **guardian-based key recovery and rotation**, including the normative
  acceptance rule;
- the thin **`did:nostr`** document view.

Spec: [`DESIGN.md`](https://github.com/resolvingarchitecture) (`../DESIGN.md` in
the DID workspace). Drafts: identity attestations, and social recovery + key
rotation, published on Nostr as long-form articles.

**Status:** `0.1.0`, pre-release. Kind numbers `30100`–`30103` are **provisional**
(`DESIGN.md` §8) and held in one module (`kinds`) so a reassignment is a one-line
change.

## Dependencies

Audited primitives only, no hand-rolled elliptic-curve code:

- [`secp256k1`](https://crates.io/crates/secp256k1) — libsecp256k1 bindings,
  BIP-340 Schnorr (the same crate rust-nostr builds on);
- [`sha2`](https://crates.io/crates/sha2), [`bech32`](https://crates.io/crates/bech32),
  [`hex`](https://crates.io/crates/hex);
- [`serde`](https://crates.io/crates/serde) / `serde_json` for the wire form.

## Use

```rust
use did_nostr::*;

// an identity is one keypair
let alice = generate_identity();
let bob = generate_identity();

// bob vouches for alice's name, having checked in person
let attestation = create_attestation(
    &AttestationInput {
        subject: alice.pubkey.clone(),
        claims: vec![Claim::new("name", "Alice")],
        method: "in-person".into(),
        ..Default::default()
    },
    &bob.secret_hex,
)?;
assert!(verify_event(&attestation).ok);

// the did:nostr view, produced offline from the public key alone
let doc = did_document(&alice.pubkey, &[])?;

// alice names guardians, then recovers to a new key when the old one is lost
let guardian_set = create_guardian_set(
    &GuardianSetInput {
        guardians: vec![g1.pubkey.clone(), g2.pubkey.clone(), g3.pubkey.clone()],
        threshold: 2,
        created_at: None,
    },
    &alice.secret_hex,
)?;
let claim = create_rotation_claim(
    &RotationClaimInput { old_pubkey: alice.pubkey.clone(), reason: "lost".into(), ..Default::default() },
    &alice_new.secret_hex,
)?;
let e1 = create_rotation_attestation(
    &RotationAttestationInput { old_pubkey: alice.pubkey.clone(), new_pubkey: alice_new.pubkey.clone(), method: "in-person".into(), created_at: None },
    &g1.secret_hex,
)?;
let e2 = create_rotation_attestation(
    &RotationAttestationInput { old_pubkey: alice.pubkey.clone(), new_pubkey: alice_new.pubkey.clone(), method: "existing-channel".into(), created_at: None },
    &g2.secret_hex,
)?;

let verdict = evaluate_rotation(&[guardian_set, claim, e1, e2], &EvaluateOptions::default());
assert!(verdict.accepted);
```

A full end-to-end walkthrough that prints every signed event:

```sh
cargo run --example demo
```

## API

| Area | Items |
|------|-------|
| Keys & encodings | `generate_identity`, `public_key_from_secret`, `is_valid_pubkey`, `hex_to_npub` / `npub_to_hex`, `secret_to_nsec` / `nsec_to_secret`, `hex_to_did` / `did_to_hex`, `normalize_pubkey` |
| Serialisation | `serialize_event`, `serialize_string`, `preimage_bytes`, `compute_id` |
| Events | `sign_event`, `sign_event_with_aux`, `verify_event` (four-step order, returns the failing step), `assert_valid`, `schnorr_sign_raw` / `schnorr_verify_raw` |
| Kinds | `KIND_IDENTITY_ATTESTATION` … `KIND_ROTATION_CLAIM`, `DID_KINDS`, `METHODS`, `ROTATION_REASONS`, `validate_kind` |
| Attestations | `create_attestation`, `revoke_attestation`, `parse_attestation`, `is_expired` |
| Rotation | `create_guardian_set`, `create_rotation_claim`, `create_rotation_attestation`, `prev_sig`, `evaluate_rotation`, `DEFAULT_COOLDOWN_SECONDS` |
| `did:nostr` | `did_document`, `xonly_to_multikey`, `multikey_to_xonly` |

`sign_event` uses BIP-340 `aux_rand = 0`, so events are byte-for-byte
reproducible (this is how the vectors are generated); `sign_event_with_aux` takes
your own randomness. Verification never depends on how a signature was produced.

`nsec` export lives behind `secret_to_nsec` and is never called by the library
itself — per `DESIGN.md` §6.3 a caller MUST gate it behind an explicit,
separately-confirmed user action and MUST NOT surface `nsec` incidentally.

## Conformance

The [`did-vectors`](https://github.com/resolvingarchitecture/did-vectors)
conformance suite is vendored (copied, not a submodule) at
[`tests/vectors/`](tests/vectors/) and re-copied when it changes upstream. The
test suite:

- checks canonical serialisation, `id` derivation and signature reproduction
  against `events.json`;
- verifies every valid vector and rejects every invalid one **at the stated
  step**;
- runs the rotation acceptance rule against all 19 scenarios in `rotation.json`;
- cross-verifies did-rust output with the **`nostr`** crate (rust-nostr),
  unmodified, so "Nostr-compatible" is checked and not just asserted.

```sh
cargo test
cargo run --example demo
```

## License

**Public domain** — [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/),
see [`LICENSE`](LICENSE). Copy any of it into any implementation, ship it with a
NIP, no attribution required.
