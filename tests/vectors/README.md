# DID test vectors

The interoperability contract for **Resolving Architecture's DID** work: Nostr-style
signed identity records and a guardian-based key-rotation acceptance rule. Every
language port —
[`did-ts`](https://github.com/resolvingarchitecture/did-ts),
[`did-rust`](https://github.com/resolvingarchitecture/did-rust),
[`did-python`](https://github.com/resolvingarchitecture/did-python),
[`did-java`](https://github.com/resolvingarchitecture/did-java) — MUST pass these,
unmodified. A second implementer should be able to prove compatibility from these
files alone.

The drafts these test are published on Nostr as long-form articles (kinds
`did-identity-attestations` and `did-social-recovery-key-rotation`).

## Files

| File | What it is |
|------|------------|
| [`events.json`](events.json) | Event / signature vectors. **Source of truth** — regenerate, don't hand-edit. |
| [`rotation.json`](rotation.json) | Rotation acceptance-rule scenarios. Source of truth. |
| `acceptance.py` | Reference implementation of the acceptance rule (pure Python, no deps). |
| `generate.cjs` | Regenerates `events.json` with `nostr-tools` / `@noble`. |
| `rotation.cjs` | Regenerates `rotation.json`. |
| `validate.py` | Re-checks both JSON files against independent implementations. |

## The records under test

An identity is one **secp256k1** keypair; public keys are **x-only** (32 bytes,
BIP-340), written as 64-char lowercase hex. Every record is a standard Nostr event
([NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)) with a
**BIP-340 Schnorr** signature. Four addressable kinds (numbers **provisional**):

| Kind | Record | Signed by |
|------|--------|-----------|
| `30100` | Identity Attestation — one identity vouches for attributes of another (replaces NIP-05) | the attester |
| `30101` | Guardian Set — names N guardians and a threshold M | the root identity |
| `30102` | Rotation Attestation — a guardian endorses `old → new` | that guardian |
| `30103` | Rotation Claim — announces succession from `old` | the new key |

## `events.json`

- **`serialization`** — canonical-form edge cases: non-ASCII, newlines/quotes/
  backslash, `\b`/`\f`, a 4-byte codepoint, empty `tags`/`content`, mixed tag
  arity. The preimage is `[0,pubkey,created_at,kind,tags,content]` as compact JSON;
  strings escape **only** `"` `\` `\n` `\r` `\t` `\b` `\f` (no `\/`, no `\uXXXX`).
  `id` = lowercase hex of `sha256(preimage)`. Each case carries the exact
  `preimage` and `id` so a serializer and a hash can be checked separately.
- **`valid_events`** — fully signed events that MUST verify: a plain note plus one
  of each DID kind, plus an attestation revocation.
- **`invalid_events`** — one or more per verification step. Steps, in order,
  rejecting on the first failure:
  1. `pubkey` is 64 lowercase hex chars and a valid x-only point
  2. recompute `id` from the canonical preimage; it MUST equal the stated `id`
  3. verify the Schnorr signature over the 32 raw `id` bytes against `pubkey`
  4. kind-specific validation

  Each case has `fails_step` and `rejected_by`:
  - `rejected_by: "any"` — any BIP-340 / NIP-01 verifier rejects it.
  - `rejected_by: "did"` — a permissive generic Nostr verifier *accepts* it, but a
    DID-compliant verifier MUST reject it: the lowercase-hex canonical-form rule,
    or a kind-specific rule (`kind_rule`).

`keys` lists the fixed test keypairs. The secret keys are deliberately weak,
obvious constants — **test data only**.

## `rotation.json`

Each entry in `cases` is a **bag of signed events** plus the verdict a conforming
verifier MUST reach:

- **`accept`** — `true` if some `new` key is the accepted successor of some `old`.
- **`fails_clause`** (negatives) — hint at which clause of `acceptance_rule` fails.
- **`events`** — a Guardian Set, a Rotation Claim, Rotation Attestations, and
  sometimes noise. `created_at` values carry the timing the cool-down and
  "set in effect at the claim" checks turn on.

`acceptance_rule`, `prev_sig_definition` (`prev-sig` = BIP-340 by the old key over
the 32 raw bytes of the new x-only pubkey) and `cooldown_seconds` (default 7 days,
measured against `claim.created_at`) are all stated in the file. `acceptance.py`
implements the rule, including its own BIP-340 verify.

## Regenerating

```sh
NP="$(npm root -g):$(npm root -g)/nostr-tools/node_modules"
NODE_PATH="$NP" node generate.cjs > events.json
NODE_PATH="$NP" node rotation.cjs > rotation.json
python3 validate.py
```

Signatures use BIP-340 `aux_rand` = 32 zero bytes, so regeneration is byte-for-byte
stable. Verification never depends on how a signature was produced.

## How these were checked

`generate.cjs` / `rotation.cjs` use `nostr-tools` 2.23.9 and `@noble/curves` 2.0.1.
`validate.py`:

- re-derives every `id` with a hand-rolled Python `json` + `hashlib` serializer;
- re-verifies every event signature with `nostr-sdk` 0.44.2 (rust-nostr) — no
  shared lineage with `nostr-tools`;
- runs `acceptance.py` (its own BIP-340 verify) against every `rotation.json` case
  and checks the `accept` verdict.

All independent implementations agree.

## License

Public domain, via [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/)
— full text in [`LICENSE`](LICENSE). Copy these files verbatim into any implementation
and ship them with a NIP; there is nothing to attribute or comply with. `events.json`
and `rotation.json` carry `"license": "CC0-1.0"`.
