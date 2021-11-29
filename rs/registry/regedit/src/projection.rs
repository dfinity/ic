use crate::snapshot::SPECIAL_FIELD_PREFIX;
use serde_json::Value;
use std::collections::BTreeMap;

pub fn project(value: Value, projection: Vec<String>) -> Value {
    if let Some(o) = value.as_object() {
        let res: BTreeMap<_, _> = o
            .iter()
            .filter_map(|(k, v)| {
                if projection
                    .iter()
                    .any(|p| k.starts_with(p) || k.starts_with(SPECIAL_FIELD_PREFIX))
                {
                    Some((k.clone(), v.clone()))
                } else {
                    None
                }
            })
            .collect();
        return serde_json::to_value(res).expect("Could not serialize");
    }
    panic!("Json-Value is not an object.");
}
