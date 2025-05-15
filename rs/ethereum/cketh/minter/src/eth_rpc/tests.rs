use super::*;
use std::str::FromStr;

#[test]
fn should_deserialize_event_data_from_str() {
    let data = "0x0000000000000000000000000000000000000000000000000163474a06d41ff6";
    let parsed_data = Data::from_str(data);
    let expected_data = Data(vec![
        0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 99, 71, 74,
        6, 212, 31, 246,
    ]);

    assert_eq!(parsed_data, Ok(expected_data));
}
