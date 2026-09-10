//! Conformance against `did-vectors/rotation.json` — the guardian rotation
//! acceptance rule (`DESIGN.md` §4.3). Vendored copy in `tests/vectors/`.

use did_nostr::{evaluate_rotation, verify_event, EvaluateOptions, NostrEvent};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/rotation.json")).expect("rotation.json parses")
}

fn events(c: &Value) -> Vec<NostrEvent> {
    c["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| serde_json::from_value(e.clone()).expect("event shape"))
        .collect()
}

#[test]
fn every_event_in_every_case_is_well_formed() {
    let v = vectors();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        for ev in events(c) {
            let r = verify_event(&ev);
            assert!(
                r.ok,
                "{name}: event {} failed at step {:?}: {:?}",
                ev.id, r.step, r.reason
            );
        }
    }
}

#[test]
fn acceptance_rule_reaches_stated_verdict() {
    let v = vectors();
    let cooldown = v["cooldown_seconds"].as_i64().unwrap();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let want = c["accept"].as_bool().unwrap();
        let verdict = evaluate_rotation(
            &events(c),
            &EvaluateOptions {
                cooldown_seconds: cooldown,
                ..Default::default()
            },
        );
        assert_eq!(verdict.accepted, want, "{name}: {}", verdict.reason);
        if want {
            assert!(
                verdict.new.is_some(),
                "{name}: accepted rotation names a successor"
            );
            assert!(
                verdict.old.is_some(),
                "{name}: accepted rotation names the old key"
            );
        }
    }
}
