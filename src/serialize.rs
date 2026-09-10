//! Canonical NIP-01 / `DESIGN.md` §2.1 serialisation.
//!
//! The signature preimage is the UTF-8 encoding of
//!
//! ```text
//! [0,<pubkey>,<created_at>,<kind>,<tags>,<content>]
//! ```
//!
//! serialised as compact JSON with **no whitespace anywhere**. In strings, only
//! the seven escapes below are emitted; every other character, including all
//! multi-byte UTF-8, is written literally (no `\/`, no `\uXXXX`).
//!
//! This is hand-rolled rather than delegated to `serde_json` on purpose: a
//! generic JSON encoder also escapes lone control characters as `\uXXXX`, which
//! the spec forbids. Getting this exactly right is what makes signatures
//! reproduce across the four language ports.

use sha2::{Digest, Sha256};

/// The unsigned fields of an event, in canonical order.
#[derive(Debug, Clone)]
pub struct EventTemplate {
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// Serialise one JSON string with the seven allowed escapes and nothing else.
pub fn serialize_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn serialize_tags(tags: &[Vec<String>]) -> String {
    let mut out = String::from("[");
    for (i, tag) in tags.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        for (j, item) in tag.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&serialize_string(item));
        }
        out.push(']');
    }
    out.push(']');
    out
}

/// The exact string that gets hashed to produce the event `id`.
pub fn serialize_event(ev: &EventTemplate) -> String {
    format!(
        "[0,{},{},{},{},{}]",
        serialize_string(&ev.pubkey),
        ev.created_at,
        ev.kind,
        serialize_tags(&ev.tags),
        serialize_string(&ev.content),
    )
}

/// UTF-8 bytes of the canonical preimage.
pub fn preimage_bytes(ev: &EventTemplate) -> Vec<u8> {
    serialize_event(ev).into_bytes()
}

/// The event id: lowercase hex of sha256 over the canonical preimage.
pub fn compute_id(ev: &EventTemplate) -> String {
    let mut h = Sha256::new();
    h.update(serialize_event(ev).as_bytes());
    hex::encode(h.finalize())
}
