use std::collections::BTreeMap;
use tla_instrumentation::{TlaValue, ToTla};

#[test]
fn size_test() {
    let myval = TlaValue::Record(BTreeMap::from([
        (
            "field1".to_string(),
            TlaValue::Function(BTreeMap::from([(
                1_u64.to_tla_value(),
                true.to_tla_value(),
            )])),
        ),
        (
            "field2".to_string(),
            TlaValue::Variant {
                tag: "tag".to_string(),
                value: Box::new("abc".to_tla_value()),
            },
        ),
    ]));
    assert_eq!(myval.size(), 6);
}
