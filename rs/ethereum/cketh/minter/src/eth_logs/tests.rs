mod parser {
    use crate::eth_logs::{
        Erc20WithSubaccountLogParser, LedgerSubaccount, LogParser, ReceivedErc20Event,
        ReceivedErc20LogParser, ReceivedEthEvent, ReceivedEthLogParser, RECEIVED_ETH_EVENT_TOPIC,
    };
    use crate::eth_rpc::LogEntry;
    use crate::numeric::{BlockNumber, Erc20Value, LogIndex, Wei};
    use candid::Principal;
    use ic_sha3::Keccak256;
    use std::str::FromStr;

    #[test]
    fn should_have_correct_topic() {
        //must match event signature in minter.sol
        let event_signature = "ReceivedEth(address,uint256,bytes32)";
        let topic = Keccak256::hash(event_signature);
        assert_eq!(topic, RECEIVED_ETH_EVENT_TOPIC)
    }

    #[test]
    fn should_parse_received_eth_event() {
        let event = r#"{
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x09efcdab00000000000100000000000000000000000000000000000000000000"
            ],
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "blockNumber": "0x3ca487",
            "transactionHash": "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3",
            "transactionIndex": "0x22",
            "blockHash": "0x8436209a391f7bc076123616ecb229602124eb6c1007f5eae84df8e098885d3c",
            "logIndex": "0x27",
            "removed": false
        }"#;
        let parsed_event =
            ReceivedEthLogParser::parse_log(serde_json::from_str::<LogEntry>(event).unwrap())
                .unwrap();
        let expected_event = ReceivedEthEvent {
            transaction_hash: "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(3974279),
            log_index: LogIndex::from(39_u8),
            from_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
                .parse()
                .unwrap(),
            value: Wei::from(10_000_000_000_000_000_u128),
            principal: Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
            subaccount: None,
        }
        .into();

        assert_eq!(parsed_event, expected_event);
    }

    #[test]
    fn should_parse_received_erc20_event() {
        let event = r#"{
            "address": "0xE1788E4834c896F1932188645cc36c54d1b80AC1",
            "topics": [
                "0x4d69d0bd4287b7f66c548f90154dc81bc98f65a1b362775df5ae171a2ccd262b",
                "0x0000000000000000000000007439e9bb6d8a84dd3a23fe621a30f95403f87fb9",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x1d9facb184cbe453de4841b6b9d9cc95bfc065344e485789b550544529020000"
            ],
            "data": "0x0000000000000000000000000000000000000000000000008ac7230489e80000",
            "blockNumber": "0x5146a4",
            "transactionHash": "0x44d8e93a8f4bbc89ad35fc4fbbdb12cb597b4832da09c0b2300777be180fde87",
            "transactionIndex": "0x22",
            "blockHash": "0x0cbfb260e2e589ef110e63314279eb3ef2e307e46fa5409f08c101976858f80a",
            "logIndex": "0x27",
            "removed": false
        }"#;
        let parsed_event =
            ReceivedErc20LogParser::parse_log(serde_json::from_str::<LogEntry>(event).unwrap())
                .unwrap();
        let expected_event = ReceivedErc20Event {
            transaction_hash: "0x44d8e93a8f4bbc89ad35fc4fbbdb12cb597b4832da09c0b2300777be180fde87"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(5326500),
            log_index: LogIndex::from(39_u8),
            from_address: "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d"
                .parse()
                .unwrap(),
            value: Erc20Value::from(10_000_000_000_000_000_000_u128),
            principal: Principal::from_str(
                "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
            )
            .unwrap(),
            erc20_contract_address: "0x7439e9bb6d8a84dd3a23fe621a30f95403f87fb9"
                .parse()
                .unwrap(),
            subaccount: None,
        }
        .into();

        assert_eq!(parsed_event, expected_event);
    }

    #[test]
    fn should_parse_received_erc20_event_with_subaccount() {
        let event = r#"{
            "address": "0x11d7c426eedc044b21066d2be9480d4b99e7cc1a",
            "topics": [
                "0xaef895090c2f5d6e81a70bef80dce496a0558487845aada57822159d5efae5cf",
                "0x0000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x1d9facb184cbe453de4841b6b9d9cc95bfc065344e485789b550544529020000"
            ],
            "data": "0x000000000000000000000000000000000000000000000000000000000001869fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "blockNumber": "0x698adb",
            "transactionHash": "0xf353e17cbcfea236a8b03d2d800205074e1f5014a3ce0f6dedcf128addb6bea4",
            "transactionIndex": "0x15",
            "blockHash": "0xeee67434b62fe62182ee51cdaf2693f112994fd3aa4d043c7e4a16fe775c37e3",
            "logIndex": "0x45",
            "removed": false
        }"#;
        let parsed_event = Erc20WithSubaccountLogParser::parse_log(
            serde_json::from_str::<LogEntry>(event).unwrap(),
        )
        .unwrap();
        let expected_event = ReceivedErc20Event {
            transaction_hash: "0xf353e17cbcfea236a8b03d2d800205074e1f5014a3ce0f6dedcf128addb6bea4"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(6916827),
            log_index: LogIndex::from(69_u8),
            from_address: "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d"
                .parse()
                .unwrap(),
            value: Erc20Value::from(99_999_u128),
            principal: Principal::from_str(
                "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
            )
            .unwrap(),
            erc20_contract_address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
                .parse()
                .unwrap(),
            subaccount: LedgerSubaccount::from_bytes([0xff; 32]),
        }
        .into();

        assert_eq!(parsed_event, expected_event);
    }

    #[test]
    fn should_not_parse_removed_event() {
        use crate::eth_logs::{EventSource, EventSourceError, ReceivedEventError};
        let event = r#"{
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x09efcdab00000000000100000000000000000000000000000000000000000000"
            ],
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "blockNumber": "0x3ca487",
            "transactionHash": "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3",
            "transactionIndex": "0x22",
            "blockHash": "0x8436209a391f7bc076123616ecb229602124eb6c1007f5eae84df8e098885d3c",
            "logIndex": "0x27",
            "removed": true
        }"#;

        let parsed_event =
            ReceivedEthLogParser::parse_log(serde_json::from_str::<LogEntry>(event).unwrap());
        let expected_error = Err(ReceivedEventError::InvalidEventSource {
            source: EventSource {
                transaction_hash:
                    "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3"
                        .parse()
                        .unwrap(),
                log_index: LogIndex::from(39_u8),
            },
            error: EventSourceError::InvalidEvent(
                "this event has been removed from the chain".to_string(),
            ),
        });
        assert_eq!(parsed_event, expected_error);
    }
}

mod parse_principal_from_slice {
    use crate::eth_logs::parse_principal_from_slice;
    use crate::eth_rpc::FixedSizeData;
    use assert_matches::assert_matches;
    use candid::Principal;
    use std::str::FromStr;

    const PRINCIPAL: &str = "2chl6-4hpzw-vqaaa-aaaaa-c";

    #[test]
    fn should_deserialize_principal() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let encoded_principal = to_bytes_with_size_prefix(&principal);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_eq!(parsed_principal, Ok(principal));
    }

    #[test]
    fn should_fail_when_first_byte_is_zero() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let mut encoded_principal = to_bytes_with_size_prefix(&principal);
        encoded_principal.insert(0, 0);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_matches!(parsed_principal, Err(_));
    }

    #[test]
    fn should_fail_when_first_byte_larger_than_29() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        for i in 30..u8::MAX {
            let mut encoded_principal = to_bytes_with_size_prefix(&principal);
            encoded_principal.insert(0, i);
            assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
        }
    }

    #[test]
    fn should_fail_when_length_shorter_than_value_in_first_byte() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let mut encoded_principal = to_bytes_with_size_prefix(&principal);

        while encoded_principal.pop().is_some() {
            assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
        }
    }

    #[test]
    fn should_fail_when_non_trailing_zeroes() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let mut encoded_principal = to_bytes_with_size_prefix(&principal);
        encoded_principal.append(&mut vec![0, 0, 0, 1, 0]);

        assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
    }

    #[test]
    fn should_fail_when_slice_longer_than_32_bytes() {
        let mut encoded_principal = [0_u8; 34];
        encoded_principal[0] = 33;

        assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
    }

    #[test]
    fn should_not_accept_management_canister_principal() {
        let principal = Principal::management_canister();
        let encoded_principal = to_bytes_with_size_prefix(&principal);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_matches!(parsed_principal, Err(err) if err.contains("management canister"));
    }

    #[test]
    fn should_not_accept_anonymous_principal() {
        let principal = Principal::anonymous();
        let encoded_principal = to_bytes_with_size_prefix(&principal);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_matches!(parsed_principal, Err(err) if err.contains("anonymous principal"));
    }

    #[test]
    fn should_encode_to_and_decode_from_eth_hex_string() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let encoded_principal = format!(
            "0x{}",
            hex::encode(to_32_bytes_with_size_prefix(&principal))
        );
        assert_eq!(
            encoded_principal,
            "0x09efcdab00000000000100000000000000000000000000000000000000000000"
        );

        let decoded_principal = parse_principal_from_slice(
            FixedSizeData::from_str(&encoded_principal)
                .unwrap()
                .as_ref(),
        );

        assert_eq!(decoded_principal, Ok(principal));
    }

    fn to_bytes_with_size_prefix(principal: &Principal) -> Vec<u8> {
        let mut principal_bytes = principal.as_slice().to_vec();
        let size = principal_bytes.len() as u8;
        principal_bytes.insert(0, size);
        principal_bytes
    }

    fn to_32_bytes_with_size_prefix(principal: &Principal) -> [u8; 32] {
        let mut principal_bytes = [0_u8; 32];
        for (index, byte) in to_bytes_with_size_prefix(principal).iter().enumerate() {
            principal_bytes[index] = *byte;
        }
        principal_bytes
    }
}

mod subaccount {
    use crate::eth_logs::LedgerSubaccount;
    use proptest::{array::uniform32, prelude::any, prop_assert_eq, prop_assume, proptest};

    proptest! {
        #[test]
        fn should_preserve_bytes_representation(bytes in uniform32(any::<u8>())) {
            prop_assume!(bytes != [0_u8; 32]);
            let subaccount = LedgerSubaccount::from_bytes(bytes).unwrap();
            let actual_bytes = subaccount.to_bytes();

            prop_assert_eq!(bytes, actual_bytes);
        }
    }
}
