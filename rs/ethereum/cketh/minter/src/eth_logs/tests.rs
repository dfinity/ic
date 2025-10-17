mod parser {
    use crate::eth_logs::parser::ReceivedEthOrErc20LogParser;
    use crate::eth_logs::{
        LedgerSubaccount, LogParser, RECEIVED_ERC20_EVENT_TOPIC, RECEIVED_ETH_EVENT_TOPIC,
        RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC, ReceivedErc20Event,
        ReceivedErc20LogParser, ReceivedEthEvent, ReceivedEthLogParser,
    };
    use crate::numeric::{BlockNumber, Erc20Value, LogIndex, Wei};
    use candid::Principal;
    use evm_rpc_types::LogEntry;
    use ic_sha3::Keccak256;
    use std::str::FromStr;

    #[test]
    fn should_have_correct_topic() {
        for (event_signature, expected_topic) in [
            (
                "ReceivedEth(address,uint256,bytes32)",
                RECEIVED_ETH_EVENT_TOPIC,
            ),
            (
                "ReceivedErc20(address,address,uint256,bytes32)",
                RECEIVED_ERC20_EVENT_TOPIC,
            ),
            (
                "ReceivedEthOrErc20(address,address,uint256,bytes32,bytes32)",
                RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC,
            ),
        ] {
            assert_eq!(Keccak256::hash(event_signature), expected_topic)
        }
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
            "blockNumber": 3974279,
            "transactionHash": "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3",
            "transactionIndex": 34,
            "blockHash": "0x8436209a391f7bc076123616ecb229602124eb6c1007f5eae84df8e098885d3c",
            "logIndex": 39,
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
            "blockNumber": 5326500,
            "transactionHash": "0x44d8e93a8f4bbc89ad35fc4fbbdb12cb597b4832da09c0b2300777be180fde87",
            "transactionIndex": 34,
            "blockHash": "0x0cbfb260e2e589ef110e63314279eb3ef2e307e46fa5409f08c101976858f80a",
            "logIndex": 39,
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
            "address": "0x2d39863d30716aaf2b7fffd85dd03dda2bfc2e38",
            "topics": [
                "0x918adbebdb8f3b36fc337ab76df10b147b2def5c9dd62cb3456d9aeca40e0b07",
                "0x0000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x1d9facb184cbe453de4841b6b9d9cc95bfc065344e485789b550544529020000"
            ],
            "data": "0x000000000000000000000000000000000000000000000000000000000000000aff00000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": 6970491,
            "transactionHash": "0x89a5cd5304b8e210e1888862be09d6bb75ba0d1b9e741021223758f92f714a15",
            "transactionIndex": 7,
            "blockHash": "0x610b7733af90f0ddbcc15756e6de041c928804ad01a1bb036aeeec43e29a1a45",
            "logIndex": 5,
            "removed": false
        }"#;
        let parsed_event = ReceivedEthOrErc20LogParser::parse_log(
            serde_json::from_str::<LogEntry>(event).unwrap(),
        )
        .unwrap();
        let expected_event = ReceivedErc20Event {
            transaction_hash: "0x89a5cd5304b8e210e1888862be09d6bb75ba0d1b9e741021223758f92f714a15"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(6970491),
            log_index: LogIndex::from(5_u8),
            from_address: "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d"
                .parse()
                .unwrap(),
            value: Erc20Value::from(10_u8),
            principal: Principal::from_str(
                "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
            )
            .unwrap(),
            erc20_contract_address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
                .parse()
                .unwrap(),
            subaccount: LedgerSubaccount::from_bytes([
                0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ]),
        }
        .into();

        assert_eq!(parsed_event, expected_event);
    }
    #[test]
    fn should_parse_received_eth_event_with_subaccount() {
        let event = r#"{
            "address": "0x2d39863d30716aaf2b7fffd85dd03dda2bfc2e38",
            "topics": [
                "0x918adbebdb8f3b36fc337ab76df10b147b2def5c9dd62cb3456d9aeca40e0b07",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x1d9facb184cbe453de4841b6b9d9cc95bfc065344e485789b550544529020000"
            ],
            "data": "0x00000000000000000000000000000000000000000000000000038d7ea4c68000ff00000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": 6970473,
            "transactionHash": "0x5a258e23fa361d60dcee4cd1eac24473cc4391e1cb4022aea722c49ab26cadf8",
            "transactionIndex": 12,
            "blockHash": "0xc419283f22e6c6d33971837a01962c9688f291499971bd22b08e596db40b167a",
            "logIndex": 10,
            "removed": false
        }"#;
        let parsed_event = ReceivedEthOrErc20LogParser::parse_log(
            serde_json::from_str::<LogEntry>(event).unwrap(),
        )
        .unwrap();
        let expected_event = ReceivedEthEvent {
            transaction_hash: "0x5a258e23fa361d60dcee4cd1eac24473cc4391e1cb4022aea722c49ab26cadf8"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(6970473),
            log_index: LogIndex::from(10_u8),
            from_address: "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d"
                .parse()
                .unwrap(),
            value: Wei::from(1_000_000_000_000_000_u64),
            principal: Principal::from_str(
                "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
            )
            .unwrap(),
            subaccount: LedgerSubaccount::from_bytes([
                0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ]),
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
            "blockNumber": 3974279,
            "transactionHash": "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3",
            "transactionIndex": 34,
            "blockHash": "0x8436209a391f7bc076123616ecb229602124eb6c1007f5eae84df8e098885d3c",
            "logIndex": 39,
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

mod scraping {
    mod received_eth_or_erc20_log_scraping {
        use crate::erc20::CkErc20Token;
        use crate::eth_logs::scraping::Scrape;
        use crate::eth_logs::{
            LogScraping, RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC,
            ReceivedEthOrErc20LogScraping,
        };
        use crate::eth_rpc::Topic;
        use crate::lifecycle::EthereumNetwork;
        use crate::numeric::BlockNumber;
        use crate::state::eth_logs_scraping::LogScrapingId;
        use crate::test_fixtures::initial_state;
        use evm_rpc_types::Hex32;
        use hex_literal::hex;
        use ic_ethereum_types::Address;

        const CONTRACT_ADDRESS: Address =
            Address::new(hex!("2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38"));

        #[test]
        fn should_be_no_scrape_when_helper_contract_address_is_none() {
            let state = initial_state();
            let scrape = ReceivedEthOrErc20LogScraping::next_scrape(&state);
            assert_eq!(scrape, None);
        }

        #[test]
        fn should_always_contain_the_zero_address_in_second_topic() {
            let last_scraped_block_number = BlockNumber::from(6_970_446_u32);
            let state = {
                let mut state = initial_state();
                state
                    .log_scrapings
                    .set_contract_address(
                        LogScrapingId::EthOrErc20DepositWithSubaccount,
                        CONTRACT_ADDRESS,
                    )
                    .unwrap();
                state.log_scrapings.set_last_scraped_block_number(
                    LogScrapingId::EthOrErc20DepositWithSubaccount,
                    last_scraped_block_number,
                );
                state
            };

            let scrape_without_erc20 = ReceivedEthOrErc20LogScraping::next_scrape(&state).unwrap();

            assert_eq!(scrape_without_erc20.contract_address, CONTRACT_ADDRESS);
            assert_eq!(
                scrape_without_erc20.last_scraped_block_number,
                last_scraped_block_number
            );
            assert_eq!(
                scrape_without_erc20.topics,
                vec![
                    Topic::Single(Hex32::from(
                        RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC
                    )),
                    Topic::Multiple(vec![Hex32::from([0_u8; 32])])
                ]
            );

            let mut state = state;
            state.record_add_ckerc20_token(CkErc20Token {
                erc20_ethereum_network: EthereumNetwork::Sepolia,
                erc20_contract_address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
                    .parse()
                    .unwrap(),
                ckerc20_token_symbol: "ckSepoliaUSDC".parse().unwrap(),
                ckerc20_ledger_id: "yfumr-cyaaa-aaaar-qaela-cai".parse().unwrap(),
            });

            let scrape_with_erc20 = ReceivedEthOrErc20LogScraping::next_scrape(&state).unwrap();
            assert_eq!(
                scrape_with_erc20,
                Scrape {
                    topics: {
                        let mut topics = scrape_without_erc20.topics;
                        let _ = std::mem::replace(
                            &mut topics[1],
                            Topic::Multiple(vec![
                                Hex32::from([0_u8; 32]),
                                Hex32::from(hex!(
                                    "0000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238"
                                )),
                            ]),
                        );
                        topics
                    },
                    ..scrape_without_erc20
                }
            )
        }
    }
}

mod parse_principal_from_slice {
    use crate::eth_logs::parse_principal_from_slice;
    use assert_matches::assert_matches;
    use candid::Principal;
    use evm_rpc_types::Hex32;
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

        let decoded_principal =
            parse_principal_from_slice(Hex32::from_str(&encoded_principal).unwrap().as_ref());

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
    use minicbor::{Decode, Encode};
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

    proptest! {
        #[test]
        fn should_migrate_struct_with_legacy_subaccount_set_to_none_to_new_struct_with_ledger_subaccount(
            field_before in any::<u64>(), field_after in any::<u64>()
        ) {
            let legacy = WithLegacySubaccount {
                field_before,
                from_subaccount: None,
                field_after,
            };
            let mut buf = vec![];
            minicbor::encode(&legacy, &mut buf).expect("encoding should succeed");
            let decoded: WithLedgerSubaccount =
                minicbor::decode(&buf).expect("decoding should succeed");

            prop_assert_eq!(
                decoded,
                WithLedgerSubaccount {
                    field_before: legacy.field_before,
                    from_subaccount: None,
                    field_after: legacy.field_after,
                }
            );
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
    pub struct WithLegacySubaccount {
        #[n(0)]
        pub field_before: u64,
        #[n(1)]
        pub from_subaccount: Option<LegacySubaccount>,
        #[n(2)]
        pub field_after: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
    #[cbor(transparent)]
    pub struct LegacySubaccount(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

    #[derive(Clone, Debug, Eq, PartialEq, Decode, Encode)]
    pub struct WithLedgerSubaccount {
        #[n(0)]
        pub field_before: u64,
        #[n(1)]
        pub from_subaccount: Option<LedgerSubaccount>,
        #[n(2)]
        pub field_after: u64,
    }
}
