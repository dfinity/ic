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

#[test]
fn check_get_logs_param_single_topic_serialization() {
    let topic =
        &hex_literal::hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");
    let p = GetLogsParam {
        from_block: BlockNumber::new(1200).into(),
        to_block: BlockNumber::new(1301).into(),
        address: vec![Address::from_str("0x80b2886b8ef418cce2564ad16ffec4bfbff13787").unwrap()],
        topics: vec![FixedSizeData(*topic).into()],
    };
    assert_eq!(
        serde_json::to_value(p).unwrap(),
        serde_json::json!({
            "fromBlock":"0x4b0",
            "toBlock":"0x515",
            "address":["0x80b2886b8ef418cce2564ad16ffec4bfbff13787"],
            "topics":["0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435"]
        })
    );
}

#[test]
fn check_get_logs_param_multiple_topics_serialization() {
    let topic =
        &hex_literal::hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");
    let p = GetLogsParam {
        from_block: BlockNumber::new(1200).into(),
        to_block: BlockNumber::new(1301).into(),
        address: vec![Address::from_str("0x80b2886b8ef418cce2564ad16ffec4bfbff13787").unwrap()],
        topics: vec![
            FixedSizeData(*topic).into(),
            vec![
                FixedSizeData(
                    (&Address::from_str("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238").unwrap())
                        .into(),
                ),
                FixedSizeData(
                    (&Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap())
                        .into(),
                ),
            ]
            .into(),
        ],
    };
    assert_eq!(
        serde_json::to_value(p).unwrap(),
        serde_json::json!({
            "fromBlock":"0x4b0",
            "toBlock":"0x515",
            "address":["0x80b2886b8ef418cce2564ad16ffec4bfbff13787"],
            "topics":[
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                [
                "0x0000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238",
                "0x000000000000000000000000b44b5e756a894775fc32eddf3314bb1b1944dc34"
                ]
            ]
        })
    );
}
