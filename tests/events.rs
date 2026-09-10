//! Conformance against `did-vectors/events.json` — the interoperability contract
//! (`DESIGN.md` §2.3). Vendored copy in `tests/vectors/`.

use std::collections::HashMap;

use did_nostr::{
    compute_id, serialize_event, sign_event_with_aux, verify_event, EventTemplate, NostrEvent,
};
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("vectors/events.json");
    serde_json::from_str(raw).expect("events.json parses")
}

fn template(input: &Value) -> EventTemplate {
    EventTemplate {
        pubkey: input["pubkey"].as_str().unwrap().to_string(),
        created_at: input["created_at"].as_i64().unwrap(),
        kind: input["kind"].as_u64().unwrap() as u32,
        tags: serde_json::from_value(input["tags"].clone()).unwrap(),
        content: input["content"].as_str().unwrap().to_string(),
    }
}

fn event(v: &Value) -> NostrEvent {
    serde_json::from_value(v.clone()).expect("event shape")
}

#[test]
fn canonical_serialisation_edge_cases() {
    let v = vectors();
    for c in v["serialization"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let t = template(&c["input"]);
        let preimage = serialize_event(&t);
        assert_eq!(
            preimage,
            c["preimage"].as_str().unwrap(),
            "{name}: preimage"
        );
        assert_eq!(
            preimage.len() as u64,
            c["preimage_utf8_bytes"].as_u64().unwrap(),
            "{name}: preimage byte count"
        );
        assert_eq!(compute_id(&t), c["id"].as_str().unwrap(), "{name}: id");
    }
}

#[test]
fn valid_events_verify() {
    let v = vectors();
    for c in v["valid_events"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let r = verify_event(&event(&c["event"]));
        assert!(
            r.ok,
            "{name}: expected valid, got step {:?}: {:?}",
            r.step, r.reason
        );
    }
}

#[test]
fn valid_event_signatures_reproduce_with_zero_aux() {
    let v = vectors();
    let mut sec_by_pub: HashMap<String, String> = HashMap::new();
    for k in v["keys"].as_object().unwrap().values() {
        sec_by_pub.insert(
            k["pub"].as_str().unwrap().to_string(),
            k["sec"].as_str().unwrap().to_string(),
        );
    }
    for c in v["valid_events"].as_array().unwrap() {
        let ev = event(&c["event"]);
        let Some(sec) = sec_by_pub.get(&ev.pubkey) else {
            continue;
        };
        let re = sign_event_with_aux(
            &did_nostr::UnsignedEvent {
                created_at: Some(ev.created_at),
                kind: ev.kind,
                tags: ev.tags.clone(),
                content: ev.content.clone(),
            },
            sec,
            &[0u8; 32],
        )
        .unwrap();
        let name = c["name"].as_str().unwrap();
        assert_eq!(re.id, ev.id, "{name}: id");
        assert_eq!(re.sig, ev.sig, "{name}: sig");
    }
}

#[test]
fn invalid_events_rejected_at_stated_step() {
    let v = vectors();
    for c in v["invalid_events"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let want = c["fails_step"].as_u64().unwrap() as u8;
        let r = verify_event(&event(&c["event"]));
        assert!(!r.ok, "{name}: expected rejection");
        assert_eq!(
            r.step,
            Some(want),
            "{name}: expected failure at step {want}, got {:?}",
            r.step
        );
    }
}
