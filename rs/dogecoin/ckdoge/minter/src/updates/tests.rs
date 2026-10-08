mod icrc21 {
    use crate::candid_api::RetrieveDogeWithApprovalArgs;
    use crate::lifecycle::init::Network;
    use crate::updates::icrc21::{DECIMALS, TokenSymbols, build_consent_info, format_amount};
    use candid::Encode;
    use icrc_ledger_types::icrc21::errors::Icrc21Error;
    use icrc_ledger_types::icrc21::lib::MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES;
    use icrc_ledger_types::icrc21::requests::{
        ConsentMessageMetadata, ConsentMessageRequest, ConsentMessageSpec, DisplayMessageType,
    };
    use icrc_ledger_types::icrc21::responses::{ConsentMessage, Value};

    // A valid Dogecoin mainnet P2PKH address.
    const MAINNET_ADDRESS: &str = "DJfU2p6woQ9GiBdiXsWZWJnJ9uDdZfSSNC";
    // A valid Dogecoin regtest P2PKH address.
    const REGTEST_ADDRESS: &str = "n31RjZEthBbNcW5F6ioj98HpeHkuJsPBJm";

    fn make_request(
        method: &str,
        arg: Vec<u8>,
        device_spec: Option<DisplayMessageType>,
    ) -> ConsentMessageRequest {
        ConsentMessageRequest {
            method: method.to_string(),
            arg,
            user_preferences: ConsentMessageSpec {
                metadata: ConsentMessageMetadata {
                    language: "en".to_string(),
                    utc_offset_minutes: None,
                },
                device_spec,
            },
        }
    }

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(0, 8), "0");
        assert_eq!(format_amount(1, 8), "0.00000001");
        assert_eq!(format_amount(100_000_000, 8), "1");
        assert_eq!(format_amount(150_000_000, 8), "1.5");
        assert_eq!(format_amount(123_456_789, 8), "1.23456789");
    }

    #[test]
    fn test_unsupported_method() {
        // Includes `retrieve_doge` because the minter intentionally only
        // supports ICRC-21 for the approval-based flow — wallets calling
        // `retrieve_doge` should not get a consent message rendered for them.
        for method in ["update_balance", "retrieve_doge", "get_doge_address", ""] {
            let req = make_request(method, vec![], None);
            let err = build_consent_info(req, Network::Mainnet).unwrap_err();
            assert!(
                matches!(err, Icrc21Error::UnsupportedCanisterCall(_)),
                "method {method:?} should be unsupported, got {err:?}"
            );
        }
    }

    #[test]
    fn test_argument_too_large() {
        let req = make_request(
            "retrieve_doge_with_approval",
            vec![0; MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize + 1],
            None,
        );
        let err = build_consent_info(req, Network::Mainnet).unwrap_err();
        match err {
            Icrc21Error::UnsupportedCanisterCall(info) => {
                assert!(info.description.contains("argument size is too large"));
            }
            _ => panic!("expected UnsupportedCanisterCall, got {err:?}"),
        }
    }

    #[test]
    fn test_retrieve_doge_with_approval_generic_display() {
        let args = RetrieveDogeWithApprovalArgs {
            amount: 150_000,
            address: MAINNET_ADDRESS.to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_doge_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::GenericDisplay),
        );
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        assert_eq!(info.metadata.language, "en");
        let message = match info.consent_message {
            ConsentMessage::GenericDisplayMessage(m) => m,
            other => panic!("expected GenericDisplayMessage, got {other:?}"),
        };
        assert!(message.starts_with("# Convert ckDOGE to DOGE"));
        assert!(message.contains("0.0015 ckDOGE"));
        assert!(message.contains(MAINNET_ADDRESS));
        // No subaccount section if from_subaccount is None.
        assert!(!message.contains("source subaccount"));
    }

    #[test]
    fn test_retrieve_doge_with_approval_generic_display_with_subaccount() {
        let mut subaccount = [0_u8; 32];
        subaccount[31] = 0x42;
        let args = RetrieveDogeWithApprovalArgs {
            amount: 100_000_000,
            address: MAINNET_ADDRESS.to_string(),
            from_subaccount: Some(subaccount),
        };
        let req = make_request("retrieve_doge_with_approval", Encode!(&args).unwrap(), None);
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let message = match info.consent_message {
            ConsentMessage::GenericDisplayMessage(m) => m,
            other => panic!("expected GenericDisplayMessage, got {other:?}"),
        };
        assert!(message.contains("1 ckDOGE"));
        assert!(message.contains(&hex::encode(subaccount)));
    }

    #[test]
    fn test_retrieve_doge_with_approval_fields_display() {
        // Long values (Dogecoin address, subaccount hex) are emitted as a
        // single Value::Text — wallets paginate them across screens. The
        // number of fields is therefore independent of the value length.
        let mut subaccount = [0_u8; 32];
        subaccount[0] = 0xab;
        subaccount[31] = 0xcd;
        let address = MAINNET_ADDRESS.to_string();
        let args = RetrieveDogeWithApprovalArgs {
            amount: 250_000,
            address: address.clone(),
            from_subaccount: Some(subaccount),
        };
        let req = make_request(
            "retrieve_doge_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::FieldsDisplay),
        );
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let fields_display = match info.consent_message {
            ConsentMessage::FieldsDisplayMessage(f) => f,
            other => panic!("expected FieldsDisplayMessage, got {other:?}"),
        };
        assert_eq!(fields_display.intent, "ckDOGE to DOGE");
        assert_eq!(
            fields_display.fields,
            vec![
                (
                    "Amount".to_string(),
                    Value::TokenAmount {
                        decimals: DECIMALS,
                        amount: 250_000,
                        symbol: "ckDOGE".to_string(),
                    }
                ),
                ("DOGE address".to_string(), Value::Text { content: address }),
                (
                    "From subaccount".to_string(),
                    Value::Text {
                        content: hex::encode(subaccount)
                    }
                ),
            ]
        );
    }

    #[test]
    fn test_retrieve_doge_with_approval_fields_display_no_subaccount() {
        let args = RetrieveDogeWithApprovalArgs {
            amount: 250_000,
            address: MAINNET_ADDRESS.to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_doge_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::FieldsDisplay),
        );
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let fields_display = match info.consent_message {
            ConsentMessage::FieldsDisplayMessage(f) => f,
            other => panic!("expected FieldsDisplayMessage, got {other:?}"),
        };
        assert_eq!(fields_display.fields.len(), 2);
        // No subaccount field when from_subaccount is None.
        assert!(
            !fields_display
                .fields
                .iter()
                .any(|(label, _)| label == "From subaccount")
        );
    }

    #[test]
    fn test_token_symbols_for_network() {
        assert_eq!(
            TokenSymbols::for_network(Network::Mainnet),
            TokenSymbols {
                ckdoge: "ckDOGE",
                doge: "DOGE"
            }
        );
        assert_eq!(
            TokenSymbols::for_network(Network::Regtest),
            TokenSymbols {
                ckdoge: "ckTESTDOGE",
                doge: "TESTDOGE"
            }
        );
    }

    #[test]
    fn test_retrieve_doge_with_approval_uses_regtest_symbols() {
        let args = RetrieveDogeWithApprovalArgs {
            amount: 250_000,
            address: REGTEST_ADDRESS.to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_doge_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::FieldsDisplay),
        );
        let info = build_consent_info(req, Network::Regtest).unwrap();
        let fields_display = match info.consent_message {
            ConsentMessage::FieldsDisplayMessage(f) => f,
            other => panic!("expected FieldsDisplayMessage, got {other:?}"),
        };
        assert_eq!(fields_display.intent, "ckTESTDOGE to TESTDOGE");
        match &fields_display.fields[0].1 {
            Value::TokenAmount { symbol, .. } => assert_eq!(symbol, "ckTESTDOGE"),
            other => panic!("expected TokenAmount, got {other:?}"),
        }
        // FieldsDisplay address label uses the regtest native symbol too.
        assert_eq!(fields_display.fields[1].0, "TESTDOGE address");
    }

    #[test]
    fn test_retrieve_doge_with_approval_generic_uses_regtest_symbols() {
        let args = RetrieveDogeWithApprovalArgs {
            amount: 100_000_000,
            address: REGTEST_ADDRESS.to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_doge_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::GenericDisplay),
        );
        let info = build_consent_info(req, Network::Regtest).unwrap();
        let message = match info.consent_message {
            ConsentMessage::GenericDisplayMessage(m) => m,
            other => panic!("expected GenericDisplayMessage, got {other:?}"),
        };
        assert!(message.starts_with("# Convert ckTESTDOGE to TESTDOGE"));
        assert!(message.contains("1 ckTESTDOGE"));
        assert!(message.contains("ckTESTDOGE minter"));
        assert!(message.contains("equivalent amount in TESTDOGE"));
    }

    #[test]
    fn test_invalid_args() {
        let req = make_request("retrieve_doge_with_approval", vec![1, 2, 3], None);
        let err = build_consent_info(req, Network::Mainnet).unwrap_err();
        match err {
            Icrc21Error::UnsupportedCanisterCall(info) => {
                assert!(info.description.contains("Failed to decode"));
            }
            _ => panic!("expected UnsupportedCanisterCall, got {err:?}"),
        }
    }

    #[test]
    fn test_malformed_address_is_rejected() {
        // The minter must not interpolate an unparseable address into the
        // Markdown consent message — that would be a Markdown-injection vector
        // (e.g. an "address" containing newlines, backticks, or '#' that fakes
        // additional fields).
        for bad_address in [
            "not-a-real-address",
            "DJfU2p6woQ9GiBdiXsWZWJnJ9uDdZfSSNC\n# You will receive 100 DOGE",
            "DJfU2p6woQ9GiBdiXsWZWJnJ9uDdZfSSNC`\n\n**Amount:** 100 DOGE\n`",
            REGTEST_ADDRESS, // valid regtest but on Mainnet
        ] {
            let args = RetrieveDogeWithApprovalArgs {
                amount: 50_000,
                address: bad_address.to_string(),
                from_subaccount: None,
            };
            let req = make_request(
                "retrieve_doge_with_approval",
                Encode!(&args).unwrap(),
                Some(DisplayMessageType::GenericDisplay),
            );
            let err = build_consent_info(req, Network::Mainnet).unwrap_err();
            match err {
                Icrc21Error::UnsupportedCanisterCall(info) => {
                    assert!(
                        info.description
                            .contains("Invalid Dogecoin destination address"),
                        "unexpected error description: {}",
                        info.description
                    );
                }
                other => panic!("expected UnsupportedCanisterCall, got {other:?}"),
            }
        }
    }
}

mod derivation {
    use crate::address::DogecoinAddress;
    use crate::lifecycle::init::Network;
    use crate::updates::get_doge_address::{derivation_path, derive_public_key};
    use candid::Principal;
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_be_stable() {
        let (canister_public_key, _) = crate::test_fixtures::canister_public_key_pair();
        let user_with_subaccount = Account {
            owner: Principal::from_text(
                "2oyh2-miczk-rzcqm-zbkes-q3kyi-lmen7-slvvl-byown-zz6v6-razzx-vae",
            )
            .unwrap(),
            subaccount: Some([42_u8; 32]),
        };
        let user_without_subaccount = Account::from(user_with_subaccount.owner);

        assert_eq!(
            derivation_path(&user_with_subaccount),
            vec![
                vec![1],
                b"doge".to_vec(),
                hex::decode("02caa39141990a89286d5842d846fe4bad561c3acdce7d5f4419cdea02").unwrap(),
                hex::decode("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
                    .unwrap(),
            ]
        );
        let derived_public_key = derive_public_key(&canister_public_key, &user_with_subaccount);
        assert_eq!(
            derived_public_key.to_vec(),
            hex::decode("03e62317d6e4feb57c8d5face3f16d26abbc30609e9abd38fc8c7e3f04502f36cc")
                .unwrap()
        );
        let derived_address = DogecoinAddress::p2pkh_from_public_key(&derived_public_key);
        assert_eq!(
            derived_address.display(&Network::Mainnet),
            "DSdZym6ZBa4QNPnE7jpuryF6fRtVmvGgre"
        );
        assert_eq!(
            derived_address.display(&Network::Regtest),
            "n31RjZEthBbNcW5F6ioj98HpeHkuJsPBJm"
        );

        assert_eq!(
            derivation_path(&user_without_subaccount),
            vec![
                vec![1],
                b"doge".to_vec(),
                hex::decode("02caa39141990a89286d5842d846fe4bad561c3acdce7d5f4419cdea02").unwrap(),
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
            ]
        );
        let derived_public_key = derive_public_key(&canister_public_key, &user_without_subaccount);
        assert_eq!(
            derived_public_key.to_vec(),
            hex::decode("02db987e631a12327a64695d96f7efaf355554633f8cdc37e1570a97b303cb8de8")
                .unwrap()
        );
        let derived_address = DogecoinAddress::p2pkh_from_public_key(&derived_public_key);
        assert_eq!(
            derived_address.display(&Network::Mainnet),
            "D7BZ4HNX9W1KSYv8gXi6yTSRg8Zwh6AFKw"
        );
        assert_eq!(
            derived_address.display(&Network::Regtest),
            "mhZQp5Wrf7YHgfD9fWgvFcV9ezSMJeHaNC"
        );
    }
}
