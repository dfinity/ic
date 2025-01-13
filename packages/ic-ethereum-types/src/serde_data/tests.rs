use proptest::arbitrary::any;
use proptest::collection::vec;
use proptest::{prop_assert, prop_assert_eq, proptest};
use serde::{Deserialize, Serialize};

proptest! {
    #[test]
    fn should_perform_serialization_roundtrip(bytes in vec(any::<u8>(), 0..100)) {
        let test_data = TestData(bytes);

        let serialized = serde_json::to_string(&test_data).unwrap();
        prop_assert!(serialized.starts_with("\"0x"));
        let deserialized: TestData = serde_json::from_str(&serialized).unwrap();

        prop_assert_eq!(deserialized, test_data);
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(transparent)]
struct TestData(#[serde(with = "crate::serde_data")] Vec<u8>);
