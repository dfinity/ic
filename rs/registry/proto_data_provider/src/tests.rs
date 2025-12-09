use super::*;
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_registry_common_proto::pb::test_protos::v1::TestProto;

#[test]
fn round_trip() {
    let registry = ProtoRegistryDataProvider::new();

    let test_version = RegistryVersion::new(1);

    let test_record = TestProto { test_value: 1 };

    let test_record2 = TestProto { test_value: 2 };

    let mut bytes1: Vec<u8> = Vec::new();
    let mut bytes2: Vec<u8> = Vec::new();

    test_record.encode(&mut bytes1).expect("encoding failed");
    test_record2.encode(&mut bytes2).expect("encoding failed");

    registry
        .add("A", test_version, Some(test_record))
        .expect("Could not add record to data provider");
    registry
        .add("B", test_version, Some(test_record2))
        .expect("Could not add record to data provider");
    registry
        .add::<TestProto>("C", test_version, None)
        .expect("Could not add record to data provider");

    let mut buf: Vec<u8> = vec![];
    registry.encode(&mut buf);

    let registry = ProtoRegistryDataProvider::decode(buf.as_ref());
    let records = registry.get_updates_since(ZERO_REGISTRY_VERSION).unwrap();

    let mut records = records
        .iter()
        .map(|r| (r.key.clone(), r.value.to_owned()))
        .collect::<Vec<(String, Option<Vec<u8>>)>>();
    records.sort();

    assert_eq!(
        records,
        vec![
            ("A".to_string(), Some(bytes1)),
            ("B".to_string(), Some(bytes2)),
            ("C".to_string(), None)
        ]
    );
}
