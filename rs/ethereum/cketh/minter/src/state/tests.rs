use crate::endpoints::CandidBlockTag;
use crate::eth_logs::{EventSource, ReceivedErc20Event, ReceivedEthEvent, ReceivedEvent};
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::EthereumNetwork;
use crate::lifecycle::init::InitArg;
use crate::lifecycle::upgrade::UpgradeArg;
use crate::map::DedupMultiKeyMap;
use crate::numeric::{
    BlockNumber, CkTokenAmount, Erc20Value, GasAmount, LedgerBurnIndex, LedgerMintIndex, LogIndex,
    TransactionNonce, Wei, WeiPerGas,
};
use crate::state::audit::apply_state_transition;
use crate::state::automatic_deposits::AutomaticDeposits;
use crate::state::eth_logs_scraping::{LogScrapingId, LogScrapings};
use crate::state::event::{Event, EventType};
use crate::state::transactions::{
    Erc20WithdrawalRequest, EthWithdrawalRequest, ReimbursementIndex, SweepId,
};
use crate::state::{Erc20Balances, EthBalance, State};
use crate::test_fixtures::{
    arb::{arb_address, arb_checked_amount_of, arb_hash, arb_ledger_subaccount},
    initial_state,
};
use crate::tx::{
    AccessList, AccessListItem, Eip1559TransactionRequest, GasFeeEstimate, ResubmissionStrategy,
    SignedEip1559TransactionRequest, StorageKey, TransactionSignature,
};
use candid::{Nat, Principal};
use ethnum::u256;
use ic_ethereum_types::Address;
use proptest::array::uniform32;
use proptest::collection::vec as pvec;
use proptest::prelude::*;
use std::collections::BTreeMap;

mod next_request_id {
    use super::*;

    #[test]
    fn should_retrieve_and_increment_counter() {
        let mut state = initial_state();

        assert_eq!(state.next_request_id(), 0);
        assert_eq!(state.next_request_id(), 1);
        assert_eq!(state.next_request_id(), 2);
        assert_eq!(state.next_request_id(), 3);
    }

    #[test]
    fn should_wrap_to_0_when_overflow() {
        let mut state = initial_state();
        state.http_request_counter = u64::MAX;

        assert_eq!(state.next_request_id(), u64::MAX);
        assert_eq!(state.next_request_id(), 0);
    }
}

mod mint_transaction {
    use crate::eth_logs::{EventSourceError, ReceivedEthEvent};
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::{LedgerMintIndex, LogIndex};
    use crate::state::tests::{initial_state, received_erc20_event, received_eth_event};
    use crate::state::{InvalidEventReason, MintedEvent};

    #[test]
    fn should_record_mint_task_from_event() {
        let mut state = initial_state();
        let event = received_eth_event();

        state.record_event_to_mint(&event.clone().into());

        assert!(state.events_to_mint.contains_key(&event.source()));

        let block_index = LedgerMintIndex::new(1_u64);

        let minted_event = MintedEvent {
            deposit_event: event.clone().into(),
            mint_block_index: block_index,
            token_symbol: "ckETH".to_string(),
            erc20_contract_address: None,
        };

        state.record_successful_mint(event.source(), "ckETH", block_index, None);

        assert!(!state.events_to_mint.contains_key(&event.source()));
        assert_eq!(
            state.minted_events.get(&event.source()),
            Some(&minted_event)
        );
    }

    #[test]
    fn should_record_erc20_mint_task_from_event() {
        let mut state = initial_state();
        state.ethereum_network = EthereumNetwork::Sepolia;
        let token = super::erc20::record_add_ckerc20_token::cksepolia_usdc();
        state.record_add_ckerc20_token(token.clone());

        let erc20_contract_address = token.erc20_contract_address;
        let mut event = received_erc20_event();
        event.erc20_contract_address = erc20_contract_address;

        state.record_event_to_mint(&event.clone().into());

        assert!(state.events_to_mint.contains_key(&event.source()));

        let block_index = LedgerMintIndex::new(1_u64);

        let minted_event = MintedEvent {
            deposit_event: event.clone().into(),
            mint_block_index: block_index,
            token_symbol: token.ckerc20_token_symbol.to_string(),
            erc20_contract_address: Some(erc20_contract_address),
        };

        state.record_successful_mint(
            event.source(),
            &token.ckerc20_token_symbol.to_string(),
            block_index,
            Some(token.erc20_contract_address),
        );

        assert!(!state.events_to_mint.contains_key(&event.source()));
        assert_eq!(
            state.minted_events.get(&event.source()),
            Some(&minted_event)
        );
    }

    #[test]
    fn should_allow_minting_events_with_equal_txhash() {
        let mut state = initial_state();
        let event_1 = ReceivedEthEvent {
            log_index: LogIndex::from(1_u8),
            ..received_eth_event()
        }
        .into();
        let event_2 = ReceivedEthEvent {
            log_index: LogIndex::from(2_u8),
            ..received_eth_event()
        }
        .into();

        assert_ne!(event_1, event_2);

        state.record_event_to_mint(&event_1);

        assert!(state.events_to_mint.contains_key(&event_1.source()));

        state.record_event_to_mint(&event_2);

        assert!(state.events_to_mint.contains_key(&event_2.source()));

        assert_eq!(2, state.events_to_mint.len());
    }

    #[test]
    #[should_panic = "unknown event"]
    fn should_not_allow_unknown_mints() {
        let mut state = initial_state();
        let event = received_eth_event();

        assert!(!state.events_to_mint.contains_key(&event.source()));
        state.record_successful_mint(event.source(), "ckETH", LedgerMintIndex::new(1), None);
    }

    #[test]
    #[should_panic = "invalid"]
    fn should_not_record_invalid_deposit_already_recorded_as_valid() {
        let mut state = initial_state();
        let event = received_eth_event().into();

        state.record_event_to_mint(&event);

        assert!(state.events_to_mint.contains_key(&event.source()));

        state.record_invalid_deposit(
            event.source(),
            EventSourceError::InvalidEvent("bad".to_string()).to_string(),
        );
    }

    #[test]
    fn should_not_update_already_recorded_invalid_deposit() {
        let mut state = initial_state();
        let event = received_eth_event();
        let error = EventSourceError::InvalidEvent("first".to_string());
        let other_error = EventSourceError::InvalidEvent("second".to_string());
        assert_ne!(error, other_error);

        assert!(state.record_invalid_deposit(event.source(), error.to_string()));
        assert_eq!(
            state.invalid_events[&event.source()],
            InvalidEventReason::InvalidDeposit(error.to_string())
        );

        assert!(!state.record_invalid_deposit(event.source(), other_error.to_string()));
        assert_eq!(
            state.invalid_events[&event.source()],
            InvalidEventReason::InvalidDeposit(error.to_string())
        );
    }

    #[test]
    fn should_quarantine_deposit() {
        let mut state = initial_state();
        let event = received_eth_event();
        state.record_event_to_mint(&event.clone().into());
        assert_eq!(state.events_to_mint.len(), 1);

        state.record_quarantined_deposit(event.source());

        assert!(state.events_to_mint.is_empty());
        assert!(state.invalid_events.contains_key(&event.source()));
    }

    #[test]
    fn should_have_readable_eth_debug_representation() {
        let expected = "ReceivedEthEvent { \
          transaction_hash: 0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2, \
          block_number: 3_960_623, \
          log_index: 29, \
          from_address: 0xdd2851Cdd40aE6536831558DD46db62fAc7A844d, \
          value: 10_000_000_000_000_000, \
          principal: k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae, \
          subaccount: None \
        }";
        assert_eq!(format!("{:?}", received_eth_event()), expected);
    }

    #[test]
    fn should_have_readable_erc20_debug_representation() {
        let expected = "ReceivedErc20Event { \
          transaction_hash: 0xd9335910102c08a9dc16f8cc1a42a0bf8ca93666d11dc3194c6ee1bd30d19686, \
          block_number: 5_539_903, \
          log_index: 87, \
          from_address: 0xdd2851Cdd40aE6536831558DD46db62fAc7A844d, \
          value: 5_000_000, \
          principal: hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe, \
          contract_address: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238, \
          subaccount: None \
        }";
        assert_eq!(format!("{:?}", received_erc20_event()), expected);
    }
}

fn received_eth_event() -> ReceivedEthEvent {
    ReceivedEthEvent {
        transaction_hash: "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2"
            .parse()
            .unwrap(),
        block_number: BlockNumber::new(3960623_u128),
        log_index: LogIndex::from(29_u8),
        from_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
            .parse()
            .unwrap(),
        value: Wei::from(10_000_000_000_000_000_u128),
        principal: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
            .parse()
            .unwrap(),
        subaccount: None,
    }
}

// https://sepolia.etherscan.io/tx/0xd9335910102c08a9dc16f8cc1a42a0bf8ca93666d11dc3194c6ee1bd30d19686
fn received_erc20_event() -> ReceivedErc20Event {
    ReceivedErc20Event {
        transaction_hash: "0xd9335910102c08a9dc16f8cc1a42a0bf8ca93666d11dc3194c6ee1bd30d19686"
            .parse()
            .unwrap(),
        block_number: BlockNumber::new(5539903),
        log_index: LogIndex::from(0x57_u32),
        from_address: "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d"
            .parse()
            .unwrap(),
        value: Erc20Value::from(5_000_000_u64),
        principal: "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe"
            .parse()
            .unwrap(),
        erc20_contract_address: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"
            .parse()
            .unwrap(),
        subaccount: None,
    }
}

mod upgrade {
    use crate::lifecycle::EthereumNetwork;
    use crate::lifecycle::upgrade::UpgradeArg;
    use crate::numeric::{TransactionNonce, Wei};
    use crate::state::InvalidStateError;
    use crate::state::eth_logs_scraping::LogScrapingId;
    use crate::state::tests::initial_state;
    use assert_matches::assert_matches;
    use candid::Nat;
    use ic_ethereum_types::Address;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn should_track_the_minimum_withdrawal_amount_in_the_funding_bounds() {
        let mut state = initial_state();
        let before = state.sweeper_funding_config();

        let raised = 90_000_000_000_000_000_u128; // 0.09 ETH, triple mainnet's minimum
        state
            .upgrade(UpgradeArg {
                minimum_withdrawal_amount: Some(Nat::from(raised)),
                ..Default::default()
            })
            .expect("raising the minimum withdrawal amount must be accepted");

        let after = state.sweeper_funding_config();
        assert!(
            after.target > before.target && after.low_water_mark > before.low_water_mark,
            "the bounds are derived from the minimum, so raising it must move both: \
             {before:?} -> {after:?}"
        );
        assert!(
            after
                .target
                .checked_sub(after.low_water_mark)
                .expect("the target must exceed the low-water mark")
                >= Wei::new(raised),
            "and the smallest amount a funding moves must still cover the raised minimum"
        );
    }

    #[test]
    fn should_fail_when_upgrade_args_invalid() {
        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                next_transaction_nonce: Some(Nat(BigUint::from_bytes_be(
                    &ethnum::u256::MAX.to_be_bytes(),
                ) + 1_u8)),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidTransactionNonce(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                minimum_withdrawal_amount: Some(Nat::from(0_u8)),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidMinimumWithdrawalAmount(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                minimum_withdrawal_amount: Some(Nat(BigUint::from_bytes_be(
                    &ethnum::u256::MAX.to_be_bytes(),
                ))),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidMinimumWithdrawalAmount(_))
        );

        let mut state = initial_state();
        state.ethereum_network = EthereumNetwork::Mainnet;
        assert_matches!(
            state.upgrade(UpgradeArg {
                minimum_withdrawal_amount: Some(Nat::from(2_000_000_000_000_u64 - 1)),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidMinimumWithdrawalAmount(_))
        );

        let mut state = initial_state();
        state.ethereum_network = EthereumNetwork::Sepolia;
        assert_matches!(
            state.upgrade(UpgradeArg {
                minimum_withdrawal_amount: Some(Nat::from(10_000_000_000_u64 - 1)),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidMinimumWithdrawalAmount(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                ethereum_contract_address: Some("invalid".to_string()),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidContractAddress(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                ethereum_contract_address: Some(
                    "0x0000000000000000000000000000000000000000".to_string(),
                ),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidContractAddress(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                ethereum_sweeper_contract_address: Some("invalid".to_string()),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidContractAddress(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                ethereum_sweeper_contract_address: Some(
                    "0x0000000000000000000000000000000000000000".to_string(),
                ),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidContractAddress(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                erc20_helper_contract_address: Some(
                    "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
                ),
                ethereum_sweeper_contract_address: Some(
                    "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
                ),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidContractAddress(_))
        );

        let mut state = initial_state();
        state
            .upgrade(UpgradeArg {
                ethereum_contract_address: Some(
                    "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
                ),
                ..Default::default()
            })
            .expect("valid upgrade args");
        assert_matches!(
            state.upgrade(UpgradeArg {
                erc20_helper_contract_address: Some(
                    "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
                ),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidContractAddress(_)),
            "a contract address already set by an earlier upgrade must stay distinct"
        );
    }

    #[test]
    fn should_succeed() {
        use crate::endpoints::CandidBlockTag;
        let mut state = initial_state();
        let upgrade_arg = UpgradeArg {
            next_transaction_nonce: Some(Nat::from(15_u8)),
            minimum_withdrawal_amount: Some(Nat::from(10_000_000_000_000_000_u64)),
            ethereum_contract_address: Some(
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
            ),
            ethereum_block_height: Some(CandidBlockTag::Safe),
            ethereum_sweeper_contract_address: Some(
                "0x2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38".to_string(),
            ),
            ..Default::default()
        };

        state.upgrade(upgrade_arg).expect("valid upgrade args");

        assert_eq!(
            state.withdrawal_transactions.next_transaction_nonce(),
            TransactionNonce::from(15_u64)
        );
        assert_eq!(
            state.cketh_minimum_withdrawal_amount,
            Wei::new(10_000_000_000_000_000)
        );
        assert_eq!(
            state
                .log_scrapings
                .contract_address(LogScrapingId::EthDepositWithoutSubaccount),
            Some(&Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap())
        );
        assert_eq!(state.ethereum_block_height, CandidBlockTag::Safe);
        assert_eq!(
            state.sweeper_contract_address,
            Some(Address::from_str("0x2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38").unwrap())
        );
    }
}

mod erc20 {
    pub mod record_add_ckerc20_token {
        use crate::erc20::CkErc20Token;
        use crate::lifecycle::EthereumNetwork;
        use crate::state::tests::initial_state;
        use crate::test_fixtures::expect_panic_with_message;

        #[test]
        fn should_panic_when_ethereum_network_mismatch() {
            let mut state = initial_state();
            state.ethereum_network = EthereumNetwork::Sepolia;

            expect_panic_with_message(
                || state.record_add_ckerc20_token(ckusdc()),
                "ERROR: Expected Ethereum Testnet Sepolia",
            );

            state.ethereum_network = EthereumNetwork::Mainnet;
            expect_panic_with_message(
                || state.record_add_ckerc20_token(cksepolia_usdc()),
                "ERROR: Expected Ethereum Mainnet",
            );
        }

        #[test]
        fn should_record_ckerc20_token() {
            let mut state = initial_state();
            state.ethereum_network = EthereumNetwork::Mainnet;
            let ckerc20 = ckusdc();

            state.record_add_ckerc20_token(ckerc20.clone());

            assert_eq!(
                state.supported_ck_erc20_tokens().collect::<Vec<_>>(),
                vec![CkErc20Token {
                    erc20_ethereum_network: EthereumNetwork::Mainnet,
                    erc20_contract_address: ckerc20.erc20_contract_address,
                    ckerc20_token_symbol: ckerc20.ckerc20_token_symbol,
                    ckerc20_ledger_id: ckerc20.ckerc20_ledger_id,
                }]
            );
        }

        #[test]
        fn should_panic_when_duplicate_ledger_id() {
            let mut state = initial_state();
            state.ethereum_network = EthereumNetwork::Mainnet;
            let ckusdc = ckusdc();
            state.record_add_ckerc20_token(ckusdc.clone());

            let ckusdt_with_wrong_ledger_id = CkErc20Token {
                ckerc20_ledger_id: ckusdc.ckerc20_ledger_id,
                ..ckusdt()
            };
            expect_panic_with_message(
                || state.record_add_ckerc20_token(ckusdt_with_wrong_ledger_id),
                "same ckERC20 ledger ID",
            );
        }

        #[test]
        fn should_panic_when_duplicate_erc20_smart_contract_address() {
            let mut state = initial_state();
            state.ethereum_network = EthereumNetwork::Mainnet;
            let ckusdc = ckusdc();
            state.record_add_ckerc20_token(ckusdc.clone());

            let ckusdt_with_wrong_address = CkErc20Token {
                erc20_contract_address: ckusdc.erc20_contract_address,
                ..ckusdt()
            };
            expect_panic_with_message(
                || state.record_add_ckerc20_token(ckusdt_with_wrong_address),
                "ERC-20 address",
            );
        }

        #[test]
        fn should_panic_when_duplicate_ckerc20_token_symbol() {
            let mut state = initial_state();
            state.ethereum_network = EthereumNetwork::Mainnet;
            let ckusdc = ckusdc();
            state.record_add_ckerc20_token(ckusdc.clone());

            let ckusdt_with_wrong_symbol = CkErc20Token {
                ckerc20_token_symbol: ckusdc.ckerc20_token_symbol,
                ..ckusdt()
            };
            expect_panic_with_message(
                || state.record_add_ckerc20_token(ckusdt_with_wrong_symbol),
                "symbol",
            );
        }

        fn ckusdc() -> CkErc20Token {
            CkErc20Token {
                erc20_ethereum_network: EthereumNetwork::Mainnet,
                erc20_contract_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                    .parse()
                    .unwrap(),
                ckerc20_token_symbol: "ckUSDC".parse().unwrap(),
                ckerc20_ledger_id: "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
            }
        }

        pub fn cksepolia_usdc() -> CkErc20Token {
            CkErc20Token {
                erc20_ethereum_network: EthereumNetwork::Sepolia,
                erc20_contract_address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
                    .parse()
                    .unwrap(),
                ckerc20_token_symbol: "ckSepoliaUSDC".parse().unwrap(),
                ckerc20_ledger_id: "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
            }
        }

        fn ckusdt() -> CkErc20Token {
            CkErc20Token {
                erc20_ethereum_network: EthereumNetwork::Mainnet,
                erc20_contract_address: "0xdac17f958d2ee523a2206206994597c13d831ec7"
                    .parse()
                    .unwrap(),
                ckerc20_token_symbol: "ckUSDT".parse().unwrap(),
                ckerc20_ledger_id: "nbsys-saaaa-aaaar-qaaga-cai".parse().unwrap(),
            }
        }
    }
}

fn arb_principal() -> impl Strategy<Value = Principal> {
    pvec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
}

fn arb_u256() -> impl Strategy<Value = u256> {
    uniform32(any::<u8>()).prop_map(u256::from_be_bytes)
}

fn arb_event_source() -> impl Strategy<Value = EventSource> {
    (arb_hash(), arb_checked_amount_of()).prop_map(|(transaction_hash, log_index)| EventSource {
        transaction_hash,
        log_index,
    })
}

fn arb_block_tag() -> impl Strategy<Value = CandidBlockTag> {
    prop_oneof![
        Just(CandidBlockTag::Safe),
        Just(CandidBlockTag::Latest),
        Just(CandidBlockTag::Finalized),
    ]
}

fn arb_nat() -> impl Strategy<Value = Nat> {
    any::<u128>().prop_map(Nat::from)
}

fn arb_storage_key() -> impl Strategy<Value = StorageKey> {
    uniform32(any::<u8>()).prop_map(StorageKey)
}

fn arb_access_list_item() -> impl Strategy<Value = AccessListItem> {
    (arb_address(), pvec(arb_storage_key(), 0..100)).prop_map(|(address, storage_keys)| {
        AccessListItem {
            address,
            storage_keys,
        }
    })
}

fn arb_access_list() -> impl Strategy<Value = AccessList> {
    pvec(arb_access_list_item(), 0..100).prop_map(AccessList)
}

prop_compose! {
    fn arb_init_arg()(
        contract_address in proptest::option::of(arb_address()),
        ethereum_block_height in arb_block_tag(),
        minimum_withdrawal_amount in arb_nat(),
        next_transaction_nonce in arb_nat(),
        ledger_id in arb_principal(),
        ecdsa_key_name in "[a-z_]*",
        last_scraped_block_number in arb_nat(),
        evm_rpc_id in proptest::option::of(arb_principal()),
        sweeper_contract_address in proptest::option::of(arb_address()),
        next_sweeper_transaction_nonce in proptest::option::of(arb_nat()),
    ) -> InitArg {
        InitArg {
            ethereum_network: EthereumNetwork::Sepolia,
            ecdsa_key_name,
            ethereum_contract_address: contract_address.map(|addr| addr.to_string()),
            ledger_id,
            ethereum_block_height,
            minimum_withdrawal_amount,
            next_transaction_nonce,
            last_scraped_block_number,
            evm_rpc_id,
            ethereum_sweeper_contract_address: sweeper_contract_address.map(|addr| addr.to_string()),
            next_sweeper_transaction_nonce,
        }
    }
}

prop_compose! {
    fn arb_upgrade_arg()(
        contract_address in proptest::option::of(arb_address()),
        ethereum_block_height in proptest::option::of(arb_block_tag()),
        minimum_withdrawal_amount in proptest::option::of(arb_nat()),
        next_transaction_nonce in proptest::option::of(arb_nat()),
        ledger_suite_orchestrator_id in proptest::option::of(arb_principal()),
        erc20_helper_contract_address in proptest::option::of(arb_address()),
        last_erc20_scraped_block_number in proptest::option::of(arb_nat()),
        evm_rpc_id in proptest::option::of(arb_principal()),
        deposit_with_subaccount_helper_contract_address in proptest::option::of(arb_address()),
        last_deposit_with_subaccount_scraped_block_number in proptest::option::of(arb_nat()),
        sweeper_contract_address in proptest::option::of(arb_address()),
        next_sweeper_transaction_nonce in proptest::option::of(arb_nat()),
    ) -> UpgradeArg {
        UpgradeArg {
            next_sweeper_transaction_nonce,
            ethereum_contract_address: contract_address.map(|addr| addr.to_string()),
            ethereum_block_height,
            minimum_withdrawal_amount,
            next_transaction_nonce,
            ledger_suite_orchestrator_id,
            erc20_helper_contract_address: erc20_helper_contract_address.map(|addr| addr.to_string()),
            last_erc20_scraped_block_number,
            evm_rpc_id,
            deposit_with_subaccount_helper_contract_address: deposit_with_subaccount_helper_contract_address.map(|addr| addr.to_string()),
            last_deposit_with_subaccount_scraped_block_number,
            ethereum_sweeper_contract_address: sweeper_contract_address.map(|addr| addr.to_string()),
        }
    }
}

prop_compose! {
    fn arb_received_eth_event()(
        transaction_hash in arb_hash(),
        block_number in arb_checked_amount_of(),
        log_index in arb_checked_amount_of(),
        from_address in arb_address(),
        value in arb_checked_amount_of(),
        principal in arb_principal(),
        subaccount in arb_ledger_subaccount(),
    ) -> ReceivedEthEvent {
        ReceivedEthEvent {
            transaction_hash,
            block_number,
            log_index,
            from_address,
            value,
            principal,
            subaccount
        }
    }
}

prop_compose! {
    fn arb_received_erc20_event()(
        transaction_hash in arb_hash(),
        block_number in arb_checked_amount_of(),
        log_index in arb_checked_amount_of(),
        from_address in arb_address(),
        value in arb_checked_amount_of(),
        principal in arb_principal(),
        erc20_contract_address in arb_address(),
        subaccount in arb_ledger_subaccount(),
    ) -> ReceivedErc20Event {
        ReceivedErc20Event {
            transaction_hash,
            block_number,
            log_index,
            from_address,
            value,
            principal,
            erc20_contract_address,
            subaccount
        }
    }
}

prop_compose! {
    fn arb_unsigned_tx()(
        chain_id in any::<u64>(),
        nonce in arb_checked_amount_of(),
        max_priority_fee_per_gas in arb_checked_amount_of(),
        max_fee_per_gas in arb_checked_amount_of(),
        gas_limit in arb_checked_amount_of(),
        destination in arb_address(),
        amount in arb_checked_amount_of(),
        data in pvec(any::<u8>(), 0..20),
        access_list in arb_access_list(),
    ) -> Eip1559TransactionRequest {
         Eip1559TransactionRequest {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            destination,
            amount,
            data,
            access_list,
        }
    }
}

prop_compose! {
    fn arb_signed_tx()(
        unsigned_tx in arb_unsigned_tx(),
        r in arb_u256(),
        s in arb_u256(),
        signature_y_parity in any::<bool>(),
    ) -> SignedEip1559TransactionRequest {
        SignedEip1559TransactionRequest::from((
            unsigned_tx,
            TransactionSignature {
                r,
                s,
                signature_y_parity,
            }
        ))
    }
}

fn arb_transaction_status() -> impl Strategy<Value = TransactionStatus> {
    prop_oneof![
        Just(TransactionStatus::Success),
        Just(TransactionStatus::Failure),
    ]
}

prop_compose! {
    fn arb_tx_receipt()(
        block_hash in arb_hash(),
        block_number in arb_checked_amount_of(),
        effective_gas_price in arb_checked_amount_of(),
        gas_used in arb_checked_amount_of(),
        status in arb_transaction_status(),
        transaction_hash in arb_hash(),
    ) -> TransactionReceipt {
        TransactionReceipt {
            block_hash,
            block_number,
            effective_gas_price,
            gas_used,
            status,
            transaction_hash,
        }
    }
}

prop_compose! {
    fn arb_sweeper_funding_request()(
        withdrawal_amount in arb_checked_amount_of(),
        destination in arb_address(),
        ledger_burn_index in any::<u64>(),
        from in arb_principal(),
        from_subaccount in arb_ledger_subaccount(),
        created_at in proptest::option::of(any::<u64>()),
    ) -> EthWithdrawalRequest {
        EthWithdrawalRequest {
            withdrawal_amount,
            destination,
            ledger_burn_index: ledger_burn_index.into(),
            from,
            from_subaccount,
            created_at,
        }
    }
}

fn arb_event_type() -> impl Strategy<Value = EventType> {
    prop_oneof![
        arb_init_arg().prop_map(EventType::Init),
        arb_upgrade_arg().prop_map(EventType::Upgrade),
        arb_received_eth_event().prop_map(EventType::AcceptedDeposit),
        arb_received_erc20_event().prop_map(EventType::AcceptedErc20Deposit),
        arb_event_source().prop_map(|event_source| EventType::InvalidDeposit {
            event_source,
            reason: "bad principal".to_string()
        }),
        (arb_event_source(), any::<u64>()).prop_map(|(event_source, index)| {
            EventType::MintedCkEth {
                event_source,
                mint_block_index: index.into(),
            }
        }),
        arb_sweeper_funding_request().prop_map(EventType::AcceptedSweeperFundingRequest),
        arb_checked_amount_of().prop_map(|block_number| EventType::SyncedToBlock { block_number }),
        arb_checked_amount_of()
            .prop_map(|block_number| EventType::SyncedErc20ToBlock { block_number }),
        (any::<u64>(), arb_unsigned_tx()).prop_map(|(withdrawal_id, transaction)| {
            EventType::CreatedTransaction {
                withdrawal_id: withdrawal_id.into(),
                transaction,
            }
        }),
        (any::<u64>(), arb_signed_tx()).prop_map(|(withdrawal_id, transaction)| {
            EventType::SignedTransaction {
                withdrawal_id: withdrawal_id.into(),
                transaction,
            }
        }),
        (any::<u64>(), arb_unsigned_tx()).prop_map(|(withdrawal_id, transaction)| {
            EventType::ReplacedTransaction {
                withdrawal_id: withdrawal_id.into(),
                transaction,
            }
        }),
        (any::<u64>(), arb_tx_receipt()).prop_map(|(withdrawal_id, transaction_receipt)| {
            EventType::FinalizedTransaction {
                withdrawal_id: withdrawal_id.into(),
                transaction_receipt,
            }
        }),
    ]
}

fn arb_event() -> impl Strategy<Value = Event> {
    (any::<u64>(), arb_event_type()).prop_map(|(timestamp, payload)| Event { timestamp, payload })
}

proptest! {
    #[test]
    fn event_encoding_roundtrip(event in arb_event()) {
        use ic_stable_structures::storable::Storable;
        let bytes = event.to_bytes();
        prop_assert_eq!(&event, &Event::from_bytes(bytes.clone()), "failed to decode bytes {}", hex::encode(bytes));
    }
}

#[test]
fn state_equivalence() {
    use crate::EVM_RPC_ID_PRODUCTION;
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::map::MultiKeyMap;
    use crate::state::transactions::WithdrawalRequest;
    use crate::state::transactions::tests::WithdrawalTransactionsBuilder;
    use crate::state::transactions::{EthWithdrawalRequest, Reimbursed, ReimbursementRequest};
    use crate::state::{InvalidEventReason, MintedEvent};
    use crate::timed_sized_map::Timestamp;
    use crate::tx::{
        Eip1559TransactionRequest, SignedTransactionRequest, TransactionRequest,
        TransactionSignature,
    };
    use ic_cdk_management_canister::EcdsaPublicKeyResult;
    use icrc_ledger_types::icrc1::account::Account;
    use maplit::{btreemap, btreeset};
    use std::collections::VecDeque;

    fn source(txhash: &str, index: u64) -> EventSource {
        EventSource {
            transaction_hash: txhash.parse().unwrap(),
            log_index: LogIndex::from(index),
        }
    }

    fn singleton_map<T: std::fmt::Debug>(
        nonce: u128,
        burn_index: u64,
        value: T,
    ) -> MultiKeyMap<TransactionNonce, LedgerBurnIndex, T> {
        let mut map = MultiKeyMap::new();
        map.try_insert(
            TransactionNonce::new(nonce),
            LedgerBurnIndex::new(burn_index),
            value,
        )
        .unwrap();
        map
    }

    let withdrawal_request1 = EthWithdrawalRequest {
        withdrawal_amount: Wei::new(10_999_968_499_999_664_000),
        destination: "0xA776Cc20DFdCCF0c3ba89cB9Fb0f10Aba5b98f52"
            .parse()
            .unwrap(),
        ledger_burn_index: LedgerBurnIndex::new(10),
        from: "2chl6-4hpzw-vqaaa-aaaaa-c".parse().unwrap(),
        from_subaccount: None,
        created_at: Some(1699527697000000000),
    };
    let withdrawal_request2 = EthWithdrawalRequest {
        ledger_burn_index: LedgerBurnIndex::new(20),
        ..withdrawal_request1.clone()
    };
    let pending_requests: VecDeque<WithdrawalRequest> = vec![
        withdrawal_request1.clone().into(),
        withdrawal_request2.clone().into(),
    ]
    .into_iter()
    .collect();
    let processed_requests = btreemap! {
        LedgerBurnIndex::new(4) => EthWithdrawalRequest {
            withdrawal_amount: Wei::new(1_000_000_000_000),
            ledger_burn_index: LedgerBurnIndex::new(4),
            destination: "0xA776Cc20DFdCCF0c3ba89cB9Fb0f10Aba5b98f52".parse().unwrap(),
            from: "ezu3d-2mifu-k3bh4-oqhrj-mbrql-5p67r-pp6pr-dbfra-unkx5-sxdtv-rae"
                .parse()
                .unwrap(),
            from_subaccount: None,
            created_at: Some(1699527697000000000),
        }.into(),
       withdrawal_request1.ledger_burn_index  => withdrawal_request1.clone().into(),
    };
    let created_tx = singleton_map(
        2,
        4,
        TransactionRequest {
            transaction: Eip1559TransactionRequest {
                chain_id: 1,
                nonce: TransactionNonce::new(2),
                max_priority_fee_per_gas: WeiPerGas::new(100_000_000),
                max_fee_per_gas: WeiPerGas::new(100_000_000),
                gas_limit: GasAmount::new(21_000),
                destination: "0xA776Cc20DFdCCF0c3ba89cB9Fb0f10Aba5b98f52"
                    .parse()
                    .unwrap(),
                amount: Wei::new(1_000_000_000_000),
                data: vec![],
                access_list: Default::default(),
            },
            resubmission: ResubmissionStrategy::ReduceEthAmount {
                withdrawal_amount: Wei::new(1_000_000_000_000),
            },
        },
    );
    let sent_tx = singleton_map(
        1,
        3,
        vec![SignedTransactionRequest {
            transaction: SignedEip1559TransactionRequest::from((
                Eip1559TransactionRequest {
                    chain_id: 1,
                    nonce: TransactionNonce::new(1),
                    max_priority_fee_per_gas: WeiPerGas::new(100_000_000),
                    max_fee_per_gas: WeiPerGas::new(100_000_000),
                    gas_limit: GasAmount::new(21_000),
                    destination: "0xA776Cc20DFdCCF0c3ba89cB9Fb0f10Aba5b98f52"
                        .parse()
                        .unwrap(),
                    amount: Wei::new(1_000_000_000_000),
                    data: vec![],
                    access_list: Default::default(),
                },
                TransactionSignature {
                    signature_y_parity: true,
                    r: Default::default(),
                    s: Default::default(),
                },
            )),
            resubmission: ResubmissionStrategy::ReduceEthAmount {
                withdrawal_amount: Wei::new(1_000_000_000_000),
            },
        }],
    );
    let finalized_tx = singleton_map(
        0,
        2,
        SignedEip1559TransactionRequest::from((
            Eip1559TransactionRequest {
                chain_id: 1,
                nonce: TransactionNonce::new(0),
                max_priority_fee_per_gas: WeiPerGas::new(100_000_000),
                max_fee_per_gas: WeiPerGas::new(100_000_000),
                gas_limit: GasAmount::new(21_000),
                destination: "0xA776Cc20DFdCCF0c3ba89cB9Fb0f10Aba5b98f52"
                    .parse()
                    .unwrap(),
                amount: Wei::new(1_000_000_000_000),
                data: vec![],
                access_list: Default::default(),
            },
            TransactionSignature {
                signature_y_parity: true,
                r: Default::default(),
                s: Default::default(),
            },
        ))
        .try_finalize(TransactionReceipt {
            block_hash: "0x9e1e2124a453e7b5afaabe42fb66fffb12d4b1053403d2f487d250007f3cb550"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(400_000),
            effective_gas_price: WeiPerGas::new(100_000_000),
            gas_used: GasAmount::new(21_000),
            status: TransactionStatus::Success,
            transaction_hash: "0x06afc3c693dc2ba2c19b5c287c4dddce040d766bea5fd13c8a7268b04aa94f2d"
                .parse()
                .unwrap(),
        })
        .expect("valid receipt"),
    );
    let next_nonce = TransactionNonce::new(3);
    let maybe_reimburse = btreeset! { LedgerBurnIndex::new(4) };
    let reimbursement_requests = btreemap! {
        ReimbursementIndex::CkEth { ledger_burn_index: LedgerBurnIndex::new(3) } => ReimbursementRequest {
            transaction_hash: Some("0x06afc3c693dc2ba2c19b5c287c4dddce040d766bea5fd13c8a7268b04aa94f2d"
            .parse()
            .unwrap()),
            ledger_burn_index: LedgerBurnIndex::new(3),
            reimbursed_amount: CkTokenAmount::new(100_000_000_000),
            to: "ezu3d-2mifu-k3bh4-oqhrj-mbrql-5p67r-pp6pr-dbfra-unkx5-sxdtv-rae".parse().unwrap(),
            to_subaccount: None,
        }
    };
    let reimbursed = btreemap! {
       ReimbursementIndex::CkEth { ledger_burn_index: LedgerBurnIndex::new(6) } => Ok(Reimbursed {
            transaction_hash: Some("0x06afc3c693dc2ba2c19b5c287c4dddce040d766bea5fd13c8a7268b04aa94f2d".parse().unwrap()),
            reimbursed_in_block: LedgerMintIndex::new(150),
            reimbursed_amount: CkTokenAmount::new(10_000_000_000_000),
            burn_in_block: LedgerBurnIndex::new(6),
        }),
    };
    let builder = WithdrawalTransactionsBuilder::default()
        .with_pending_requests(pending_requests)
        .with_processed_requests(processed_requests)
        .with_created_tx(created_tx)
        .with_sent_tx(sent_tx)
        .with_finalized_tx(finalized_tx)
        .with_next_nonce(next_nonce)
        .with_maybe_reimburse(maybe_reimburse)
        .with_reimbursement_requests(reimbursement_requests)
        .with_reimbursed(reimbursed);
    let withdrawal_transactions = builder.clone().build();
    let mut ckerc20_tokens = DedupMultiKeyMap::default();
    ckerc20_tokens
        .try_insert(
            "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                .parse()
                .unwrap(),
            "ckUSDC".parse().unwrap(),
        )
        .unwrap();

    let log_scrapings = LogScrapings::new(BlockNumber::new(1_000_000));
    let automatic_deposits = {
        let mut deposits = AutomaticDeposits::default();
        deposits
            .watch_deposit(
                Timestamp::from_nanos(1),
                Account {
                    owner: "2chl6-4hpzw-vqaaa-aaaaa-c".parse().unwrap(),
                    subaccount: Some([0_u8; 32]),
                },
                "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                    .parse()
                    .unwrap(),
                "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0"
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        deposits
            .watch_deposit(
                Timestamp::from_nanos(2),
                Account {
                    owner: "ss2fx-dyaaa-aaaar-qacoq-cai".parse().unwrap(),
                    subaccount: Some([1_u8; 32]),
                },
                "0xdAC17F958D2ee523a2206206994597C13D831ec7"
                    .parse()
                    .unwrap(),
                "0x9d68bd6F351bE62ed6dBEaE99d830BECD356Ed25"
                    .parse()
                    .unwrap(),
            )
            .unwrap();
        deposits
    };
    let state = State {
        sweeper_funding: Default::default(),
        next_sweep_id: SweepId(0),
        ethereum_network: EthereumNetwork::Mainnet,
        ecdsa_key_name: "test_key".to_string(),
        cketh_ledger_id: "apia6-jaaaa-aaaar-qabma-cai".parse().unwrap(),
        log_scrapings: log_scrapings.clone(),
        ecdsa_public_key: Some(EcdsaPublicKeyResult {
            public_key: vec![1; 32],
            chain_code: vec![2; 32],
        }),
        cketh_minimum_withdrawal_amount: Wei::new(1_000_000_000_000_000),
        ethereum_block_height: CandidBlockTag::Finalized,
        first_scraped_block_number: BlockNumber::new(1_000_001),
        last_observed_block_number: Some(BlockNumber::new(2_000_000)),
        latest_block_height: Some(BlockNumber::new(2_000_010)),
        events_to_mint: btreemap! {
            source("0xac493fb20c93bd3519a4a5d90ce72d69455c41c5b7e229dafee44344242ba467", 100) => ReceivedEthEvent {
                transaction_hash: "0xac493fb20c93bd3519a4a5d90ce72d69455c41c5b7e229dafee44344242ba467".parse().unwrap(),
                block_number: BlockNumber::new(500_000),
                log_index: LogIndex::new(100),
                from_address: "0x9d68bd6F351bE62ed6dBEaE99d830BECD356Ed25".parse().unwrap(),
                value: Wei::new(500_000_000_000_000_000),
                principal: "lsywz-sl5vm-m6tct-7fhwt-6gdrw-4uzsg-ibknl-44d6d-a2oyt-c2cxu-7ae".parse().unwrap(),
                subaccount: None,
            }.into()
        },
        minted_events: btreemap! {
            source("0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3", 1) => MintedEvent {
                deposit_event: ReceivedEthEvent {
                    transaction_hash: "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3".parse().unwrap(),
                    block_number: BlockNumber::new(450_000),
                    log_index: LogIndex::new(1),
                    from_address: "0x9d68bd6F351bE62ed6dBEaE99d830BECD356Ed25".parse().unwrap(),
                    value: Wei::new(10_000_000_000_000_000),
                    principal: "2chl6-4hpzw-vqaaa-aaaaa-c".parse().unwrap(),
                    subaccount: None,
                }.into(),
                mint_block_index: LedgerMintIndex::new(1),
                erc20_contract_address: None,
                token_symbol: "ckETH".to_string(),
            }
        },
        invalid_events: btreemap! {
            source("0x05c6ec45699c9a6a4b1a4ea2058b0cee852ea2f19b18fb8313c04bf8156efde4", 11) => InvalidEventReason::InvalidDeposit("failed to decode principal from bytes 0x00333c125dc9f41abaf2b8b85d49fdc7ff75b2a4000000000000000000000000".to_string()),
        },
        withdrawal_transactions: withdrawal_transactions.clone(),
        pending_withdrawal_principals: Default::default(),
        pending_deposit_principals: Default::default(),
        active_tasks: Default::default(),
        http_request_counter: 100,
        eth_balance: Default::default(),
        erc20_balances: Default::default(),
        skipped_blocks: Default::default(),
        last_transaction_price_estimate: None,
        ledger_suite_orchestrator_id: Some("2s5qh-7aaaa-aaaar-qadya-cai".parse().unwrap()),
        evm_rpc_id: EVM_RPC_ID_PRODUCTION,
        ckerc20_tokens,
        automatic_deposits,
        sweeper_contract_address: Some(
            "0x2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38"
                .parse()
                .unwrap(),
        ),
    };

    assert_eq!(
        Ok(()),
        state.is_equivalent_to(&State {
            ecdsa_public_key: None,
            last_observed_block_number: None,
            latest_block_height: None,
            http_request_counter: 0,
            ..state.clone()
        }),
        "changing only computed/transient fields should result in an equivalent state",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            first_scraped_block_number: BlockNumber::new(100_000_000_000),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            log_scrapings: {
                let mut s = log_scrapings.clone();
                s.set_last_scraped_block_number(
                    LogScrapingId::EthDepositWithoutSubaccount,
                    BlockNumber::new(100_000_000_000),
                );
                s
            },
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            ecdsa_key_name: "".to_string(),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            cketh_minimum_withdrawal_amount: Wei::new(1),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            ethereum_block_height: CandidBlockTag::Latest,
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            events_to_mint: Default::default(),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            minted_events: Default::default(),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            invalid_events: Default::default(),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            sweeper_contract_address: None,
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_eq!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder
                .clone()
                .with_pending_requests(
                    vec![
                        withdrawal_request2.clone().into(),
                        withdrawal_request1.clone().into()
                    ]
                    .into_iter()
                    .collect()
                )
                .build(),
            ..state.clone()
        },),
        "changing the order of withdrawal requests should result in an equivalent state",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder
                .clone()
                .with_pending_requests(vec![withdrawal_request1.into()].into_iter().collect())
                .build(),
            ..state.clone()
        }),
        "changing the withdrawal requests should break equivalence"
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder.clone().with_sent_tx(Default::default()).build(),
            ..state.clone()
        }),
        "changing the transactions should break equivalence"
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder.clone().with_created_tx(Default::default()).build(),
            ..state.clone()
        }),
        "changing the transactions should break equivalence"
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder
                .clone()
                .with_finalized_tx(Default::default())
                .build(),
            ..state.clone()
        }),
        "changing the transactions should break equivalence"
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder
                .clone()
                .with_maybe_reimburse(Default::default())
                .build(),
            ..state.clone()
        }),
        "changing the reimbursement data should break equivalence"
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder
                .clone()
                .with_reimbursement_requests(Default::default())
                .build(),
            ..state.clone()
        }),
        "changing the reimbursement data should break equivalence"
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder.clone().with_reimbursed(Default::default()).build(),
            ..state.clone()
        }),
        "changing the reimbursement data should break equivalence"
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            withdrawal_transactions: builder
                .clone()
                .with_next_nonce(TransactionNonce::new(1000))
                .build(),
            ..state.clone()
        }),
        "changing the next nonce should break equivalence"
    );

    assert_eq!(
        Ok(()),
        state.is_equivalent_to(&State {
            last_transaction_price_estimate: Some((
                0,
                GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::new(10_000_000),
                    max_priority_fee_per_gas: WeiPerGas::new(1_000_000),
                }
            )),
            ..state.clone()
        }),
        "changing the last transaction price estimate should result in an equivalent state",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            ledger_suite_orchestrator_id: Some(Principal::anonymous()),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            ckerc20_tokens: Default::default(),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );

    assert_ne!(
        Ok(()),
        state.is_equivalent_to(&State {
            automatic_deposits: Default::default(),
            ..state.clone()
        }),
        "changing essential fields should break equivalence",
    );
}

/// An [`EthBalance`] holding `eth_balance` of deposit-backed ETH, for tests that need the minter to
/// have received something.
pub(crate) fn eth_balance_of(eth_balance: Wei) -> EthBalance {
    EthBalance {
        eth_balance,
        ..Default::default()
    }
}

mod sweeper_funding {
    use super::*;
    use crate::eth_logs::LedgerSubaccount;
    use crate::numeric::{LedgerBurnIndex, Wei};
    use crate::state::audit::apply_state_transition;
    use crate::state::transactions::{EthWithdrawalRequest, WithdrawalRequest};
    use crate::test_fixtures::initial_state;
    use assert_matches::assert_matches;

    #[test]
    fn should_record_an_accepted_funding_as_a_funding_request() {
        let mut state = initial_state();
        let funding = EthWithdrawalRequest {
            withdrawal_amount: Wei::new(10_000_000_000_000_000),
            destination: "0x5353535353535353535353535353535353535353"
                .parse()
                .unwrap(),
            ledger_burn_index: LedgerBurnIndex::new(0),
            from: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
                .parse()
                .unwrap(),
            from_subaccount: LedgerSubaccount::from_bytes(crate::CKETH_FEE_SUBACCOUNT),
            created_at: Some(1699527697000000000),
        };

        apply_state_transition(
            &mut state,
            &EventType::AcceptedSweeperFundingRequest(funding),
        );

        let request = state
            .withdrawal_transactions
            .requests_iter()
            .next()
            .expect("BUG: the funding request was not recorded");
        assert_matches!(request, WithdrawalRequest::SweeperFunding(_));
        assert!(
            !request.is_reimbursable(),
            "recorded as an ordinary withdrawal, a failed funding would be reimbursed"
        );
    }
}

mod eth_balance {
    use super::*;
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::{
        BlockNumber, GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas,
    };
    use crate::state::audit::{EventType, apply_state_transition};
    use crate::state::tests::checked_sub;
    use crate::state::tests::{initial_state, received_eth_event};
    use crate::state::transactions::{EthWithdrawalRequest, PipelineRequest, WithdrawalRequest};
    use crate::state::{EthBalance, State};
    use crate::test_fixtures::sweeper_funding_request;
    use crate::tx::{SignedEip1559TransactionRequest, TransactionSignature};
    use maplit::btreemap;

    #[test]
    fn should_add_deposit_to_eth_balance() {
        let mut state = initial_state();
        let balance_before = state.eth_balance.clone();

        let deposit_event = received_eth_event();
        apply_state_transition(
            &mut state,
            &ReceivedEvent::from(deposit_event.clone()).into_deposit(),
        );
        let balance_after = state.eth_balance.clone();

        assert_eq!(
            balance_after,
            EthBalance {
                eth_balance: deposit_event.value,
                ..balance_before
            }
        )
    }

    #[test]
    fn should_ignore_erc20_deposit_for_eth_balance() {
        let mut state = initial_erc20_state();
        let balance_before = state.eth_balance.clone();

        let deposit_event = received_erc20_event();
        apply_state_transition(
            &mut state,
            &ReceivedEvent::from(deposit_event.clone()).into_deposit(),
        );
        let balance_after = state.eth_balance.clone();

        assert_eq!(balance_before, balance_after);
    }

    #[test]
    fn should_ignore_rejected_deposit() {
        let mut state = initial_state();
        let balance_before = state.eth_balance.clone();

        let deposit_event = received_eth_event();
        apply_state_transition(
            &mut state,
            &EventType::InvalidDeposit {
                event_source: deposit_event.source(),
                reason: "invalid principal".to_string(),
            },
        );
        let balance_after = state.eth_balance.clone();
        assert_eq!(balance_after, balance_before);

        add_erc20_token(&mut state);
        let deposit_event = received_erc20_event();
        apply_state_transition(
            &mut state,
            &EventType::InvalidDeposit {
                event_source: deposit_event.source(),
                reason: "invalid principal".to_string(),
            },
        );
        let balance_after_erc20_deposit = state.eth_balance.clone();

        assert_eq!(balance_after_erc20_deposit, balance_before);
    }

    /// Both outcomes of one flow, each applied to its own copy of the starting state.
    struct BothOutcomes {
        after_success: State,
        after_failure: State,
        receipt_succeeded: TransactionReceipt,
        receipt_failed: TransactionReceipt,
    }

    /// Runs the 21'000-gas flow twice, once finalizing successfully and once with a failure
    /// receipt. The gas fixture over-provisions the fee, so part of it is always left unspent.
    fn apply_eth_transfer_both_ways<T: Into<WithdrawalRequest>>(
        state_before: &State,
        request: T,
    ) -> BothOutcomes {
        //Values from https://sepolia.etherscan.io/tx/0xef628b8f45984bdf386f5b765b665a2e584295e1190d21c6acdfabe17c27e1bb
        let flow = WithdrawalFlow {
            tx_fee: GasFeeEstimate {
                base_fee_per_gas: WeiPerGas::from(0xbc9998d1_u64),
                max_priority_fee_per_gas: WeiPerGas::from(1_500_000_000_u64),
            },
            gas_limit: GasAmount::from(21_000_u32),
            effective_gas_price: WeiPerGas::from(0x1176e9eb9_u64),
            tx_status: TransactionStatus::Success,
            ..WithdrawalFlow::for_request(request)
        };

        let mut after_success = state_before.clone();
        let receipt_succeeded = flow.clone().apply(&mut after_success);

        let mut after_failure = state_before.clone();
        let receipt_failed = WithdrawalFlow {
            tx_status: TransactionStatus::Failure,
            ..flow
        }
        .apply(&mut after_failure);

        BothOutcomes {
            after_success,
            after_failure,
            receipt_succeeded,
            receipt_failed,
        }
    }

    #[test]
    fn should_account_for_a_successful_sweeper_funding() {
        let mut state = initial_state();
        apply_state_transition(
            &mut state,
            &EventType::AcceptedDeposit(received_eth_event()),
        );
        let eth_balance_before = state.eth_balance.eth_balance();

        let funding = sweeper_funding_request(Wei::new(10_000_000_000_000_000));
        let receipt = WithdrawalFlow {
            tx_status: TransactionStatus::Success,
            ..WithdrawalFlow::for_request(WithdrawalRequest::SweeperFunding(funding.clone()))
        }
        .apply(&mut state);

        assert_eq!(
            state.sweeper_funding.cumulative_burned(),
            funding.withdrawal_amount,
            "the burn is recorded when the funding is accepted, before any ETH moves"
        );
        let spent = state.sweeper_funding.cumulative_spent();
        let unspent_fee_allowance = state.eth_balance.total_unspent_tx_fees();
        assert!(
            unspent_fee_allowance > Wei::ZERO,
            "test setup: the effective fee must be below the charged max fee"
        );
        assert_eq!(
            spent,
            funding
                .withdrawal_amount
                .checked_sub(unspent_fee_allowance)
                .unwrap(),
            "spend is the burn minus the fee allowance that was charged but not used"
        );
        assert_eq!(
            state.sweeper_funding.burned_not_yet_spent(),
            unspent_fee_allowance,
            "the unused fee allowance stays as backing, neither re-minted nor offset"
        );
        assert_eq!(
            state.eth_balance.eth_balance(),
            eth_balance_before.checked_sub(spent).unwrap(),
            "the ETH balance is debited by exactly what was spent"
        );
        assert!(
            state.sweeper_funding.cumulative_burned() >= spent,
            "burned must never fall below spent"
        );
        assert_eq!(receipt.status, TransactionStatus::Success);
    }

    #[test]
    fn should_keep_a_failed_sweeper_funding_as_backing() {
        let mut state = initial_state();
        apply_state_transition(
            &mut state,
            &EventType::AcceptedDeposit(received_eth_event()),
        );
        let eth_balance_before = state.eth_balance.eth_balance();

        let funding = sweeper_funding_request(Wei::new(10_000_000_000_000_000));
        let receipt = WithdrawalFlow {
            tx_status: TransactionStatus::Failure,
            ..WithdrawalFlow::for_request(WithdrawalRequest::SweeperFunding(funding.clone()))
        }
        .apply(&mut state);

        let spent = state.sweeper_funding.cumulative_spent();
        assert_eq!(
            state.sweeper_funding.cumulative_burned(),
            funding.withdrawal_amount
        );
        assert_eq!(
            spent,
            receipt.effective_transaction_fee(),
            "a failed funding moved no ETH, so the gas it paid is the whole spend"
        );
        assert_eq!(
            state.sweeper_funding.burned_not_yet_spent(),
            funding.withdrawal_amount.checked_sub(spent).unwrap(),
            "the rest stays as backing, available to no later funding"
        );
        assert_eq!(
            state.eth_balance.eth_balance(),
            eth_balance_before.checked_sub(spent).unwrap(),
            "only the fee left the main address, so ckETH is over-backed, never under-backed"
        );
    }

    #[test]
    fn should_update_after_successful_and_failed_withdrawal() {
        let mut state_before_withdrawal = initial_state();
        apply_state_transition(
            &mut state_before_withdrawal,
            &EventType::AcceptedDeposit(received_eth_event()),
        );

        let eth_balance_before_withdrawal = state_before_withdrawal.eth_balance.clone();
        let erc20_balance_before_withdrawal = state_before_withdrawal.erc20_balances.clone();
        let withdrawal_request = EthWithdrawalRequest {
            withdrawal_amount: Wei::new(10_000_000_000_000_000),
            destination: "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34"
                .parse()
                .unwrap(),
            ledger_burn_index: LedgerBurnIndex::new(0),
            from: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
                .parse()
                .unwrap(),
            from_subaccount: None,
            created_at: Some(1699527697000000000),
        };
        let outcomes = apply_eth_transfer_both_ways(&state_before_withdrawal, withdrawal_request);
        let eth_balance_after_successful_withdrawal = outcomes.after_success.eth_balance.clone();
        let erc20_balance_after_successful_withdrawal =
            outcomes.after_success.erc20_balances.clone();

        assert_eq!(
            eth_balance_after_successful_withdrawal,
            EthBalance {
                eth_balance: eth_balance_before_withdrawal
                    .eth_balance
                    .checked_sub(Wei::from(9_934_054_275_043_000_u64))
                    .unwrap(),
                total_effective_tx_fees: eth_balance_before_withdrawal
                    .total_effective_tx_fees
                    .checked_add(Wei::from(98_449_949_997_000_u64))
                    .unwrap(),
                total_unspent_tx_fees: eth_balance_before_withdrawal
                    .total_unspent_tx_fees
                    .checked_add(Wei::from(65_945_724_957_000_u64))
                    .unwrap(),
            }
        );
        assert_eq!(
            erc20_balance_before_withdrawal,
            erc20_balance_after_successful_withdrawal
        );

        let receipt_failed = &outcomes.receipt_failed;
        let eth_balance_after_failed_withdrawal = outcomes.after_failure.eth_balance.clone();
        let erc20_balance_after_failed_withdrawal = outcomes.after_failure.erc20_balances.clone();

        assert_eq!(
            eth_balance_after_failed_withdrawal.eth_balance,
            eth_balance_before_withdrawal
                .eth_balance
                .checked_sub(receipt_failed.effective_transaction_fee())
                .unwrap()
        );
        assert_eq!(
            eth_balance_after_successful_withdrawal.total_effective_tx_fees,
            eth_balance_after_failed_withdrawal.total_effective_tx_fees
        );
        assert_eq!(
            eth_balance_after_successful_withdrawal.total_unspent_tx_fees,
            eth_balance_after_failed_withdrawal.total_unspent_tx_fees()
        );
        assert_eq!(
            erc20_balance_before_withdrawal,
            erc20_balance_after_failed_withdrawal
        );
    }

    #[test]
    fn should_update_after_successful_and_failed_sweeper_funding() {
        let mut state_before_funding = initial_state();
        apply_state_transition(
            &mut state_before_funding,
            &EventType::AcceptedDeposit(received_eth_event()),
        );
        let eth_balance_before_funding = state_before_funding.eth_balance.clone();

        let funding_amount = Wei::new(10_000_000_000_000_000);
        let funding_request = WithdrawalRequest::SweeperFunding(EthWithdrawalRequest {
            withdrawal_amount: funding_amount,
            destination: "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34"
                .parse()
                .unwrap(),
            ledger_burn_index: LedgerBurnIndex::new(0),
            from: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
                .parse()
                .unwrap(),
            from_subaccount: None,
            created_at: Some(1699527697000000000),
        });
        let outcomes = apply_eth_transfer_both_ways(&state_before_funding, funding_request);
        let receipt_succeeded = &outcomes.receipt_succeeded;
        let after_success = outcomes.after_success.eth_balance.clone();

        // An identity rather than a fixed number: the ceiling covers the ETH delivered plus the fee.
        let unspent = after_success
            .total_unspent_tx_fees
            .checked_sub(eth_balance_before_funding.total_unspent_tx_fees)
            .unwrap();
        assert_eq!(
            after_success.eth_balance,
            eth_balance_before_funding
                .eth_balance
                .checked_sub(
                    funding_amount
                        .checked_sub(unspent)
                        .expect("the unspent fee is part of the funding")
                )
                .unwrap(),
            "a successful funding debits what it moved plus the fee it paid"
        );
        assert_eq!(
            after_success.total_effective_tx_fees,
            eth_balance_before_funding
                .total_effective_tx_fees
                .checked_add(receipt_succeeded.effective_transaction_fee())
                .unwrap(),
            "the fee actually paid must be counted"
        );
        assert!(
            unspent > Wei::ZERO,
            "this fixture over-provisions the fee, so some of it must be recorded as unspent"
        );

        let receipt_failed = &outcomes.receipt_failed;
        let after_failure = outcomes.after_failure.eth_balance.clone();

        assert_eq!(
            after_failure.eth_balance,
            eth_balance_before_funding
                .eth_balance
                .checked_sub(receipt_failed.effective_transaction_fee())
                .unwrap(),
            "a failed funding moved no ETH, so only the fee is debited"
        );
        assert_eq!(
            after_failure.total_effective_tx_fees, after_success.total_effective_tx_fees,
            "the same fee was paid either way"
        );
        assert_eq!(
            after_failure.total_unspent_tx_fees, after_success.total_unspent_tx_fees,
            "and the same amount of it went unspent"
        );
    }

    #[test]
    fn should_update_after_successful_and_failed_erc20_withdrawal() {
        let mut state_before_withdrawal = initial_erc20_state();
        apply_state_transition(
            &mut state_before_withdrawal,
            &EventType::AcceptedErc20Deposit(received_erc20_event()),
        );
        apply_state_transition(
            &mut state_before_withdrawal,
            &EventType::AcceptedDeposit(received_eth_event()),
        );

        let mut state_after_successful_withdrawal = state_before_withdrawal.clone();
        let eth_balance_before_withdrawal = state_before_withdrawal.eth_balance.clone();
        let erc20_balance_before_withdrawal = state_before_withdrawal.erc20_balances.clone();
        //Values from https://sepolia.etherscan.io/tx/0x9695853792c636f9098844931da5e0ae7c5bdc8b9c6a7471aa44aed96875affc
        let withdrawal_request = erc20_withdrawal_request();
        let tx_fee = GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::from(0x4ce9a_u64),
            max_priority_fee_per_gas: WeiPerGas::from(1_500_000_000_u64),
        };
        let gas_limit = GasAmount::from(65_000_u64);
        let effective_gas_price = WeiPerGas::from(0x596cfd9a_u64);
        let effective_gas_used = GasAmount::from(0xb003_u32);
        let withdrawal_flow = WithdrawalFlow {
            tx_fee: tx_fee.clone(),
            gas_limit,
            effective_gas_price,
            effective_gas_used,
            tx_status: TransactionStatus::Success,
            ..WithdrawalFlow::for_request(withdrawal_request.clone())
        };
        withdrawal_flow
            .clone()
            .apply(&mut state_after_successful_withdrawal);
        let eth_balance_after_successful_withdrawal =
            state_after_successful_withdrawal.eth_balance.clone();
        let erc20_balance_after_successful_withdrawal =
            state_after_successful_withdrawal.erc20_balances.clone();

        let charged_transaction_fee = withdrawal_request.max_transaction_fee;
        let effective_transaction_fee = effective_gas_price
            .transaction_cost(effective_gas_used)
            .unwrap();
        let unspent_tx_fee = charged_transaction_fee
            .checked_sub(effective_transaction_fee)
            .unwrap();
        assert_eq!(
            eth_balance_after_successful_withdrawal,
            EthBalance {
                eth_balance: eth_balance_before_withdrawal
                    .eth_balance
                    .checked_sub(effective_transaction_fee)
                    .unwrap(),
                total_effective_tx_fees: eth_balance_before_withdrawal
                    .total_effective_tx_fees
                    .checked_add(effective_transaction_fee)
                    .unwrap(),
                total_unspent_tx_fees: eth_balance_before_withdrawal
                    .total_unspent_tx_fees
                    .checked_add(unspent_tx_fee)
                    .unwrap(),
            }
        );
        assert_eq!(
            checked_sub(
                erc20_balance_before_withdrawal.clone(),
                erc20_balance_after_successful_withdrawal
            ),
            btreemap! { withdrawal_request.erc20_contract_address => withdrawal_request.withdrawal_amount }
        );

        let mut state_after_failed_withdrawal = state_before_withdrawal.clone();
        WithdrawalFlow {
            tx_status: TransactionStatus::Failure,
            ..withdrawal_flow
        }
        .apply(&mut state_after_failed_withdrawal);
        let eth_balance_after_failed_withdrawal = state_after_failed_withdrawal.eth_balance.clone();
        let erc20_balance_after_failed_withdrawal =
            state_after_failed_withdrawal.erc20_balances.clone();
        assert_eq!(
            eth_balance_after_successful_withdrawal,
            eth_balance_after_failed_withdrawal
        );
        assert_eq!(
            erc20_balance_before_withdrawal,
            erc20_balance_after_failed_withdrawal
        );
    }

    #[derive(Clone)]
    struct WithdrawalFlow {
        withdrawal_request: WithdrawalRequest,
        nonce: TransactionNonce,
        tx_fee: GasFeeEstimate,
        gas_limit: GasAmount,
        effective_gas_price: WeiPerGas,
        effective_gas_used: GasAmount,
        tx_status: TransactionStatus,
    }

    impl WithdrawalFlow {
        fn for_request<T: Into<WithdrawalRequest>>(withdrawal_request: T) -> Self {
            Self {
                withdrawal_request: withdrawal_request.into(),
                nonce: TransactionNonce::ZERO,
                tx_fee: GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::ONE,
                    max_priority_fee_per_gas: WeiPerGas::ONE,
                },
                gas_limit: GasAmount::from(21_000_u32),
                effective_gas_price: WeiPerGas::ONE,
                effective_gas_used: GasAmount::from(21_000_u32),
                tx_status: TransactionStatus::Success,
            }
        }

        fn apply(self, state: &mut State) -> TransactionReceipt {
            let accepted_withdrawal_request_event =
                accepted_withdrawal_request_event(self.withdrawal_request.clone());
            apply_state_transition(state, &accepted_withdrawal_request_event);

            let transaction = self
                .withdrawal_request
                .create_transaction(
                    self.nonce,
                    self.tx_fee,
                    self.gas_limit,
                    EthereumNetwork::Sepolia,
                )
                .expect("BUG: failed to create transaction");
            apply_state_transition(
                state,
                &EventType::CreatedTransaction {
                    withdrawal_id: self.withdrawal_request.cketh_ledger_burn_index(),
                    transaction: transaction.clone(),
                },
            );

            let dummy_signature = TransactionSignature {
                signature_y_parity: false,
                r: Default::default(),
                s: Default::default(),
            };
            let signed_tx =
                SignedEip1559TransactionRequest::from((transaction.clone(), dummy_signature));
            apply_state_transition(
                state,
                &EventType::SignedTransaction {
                    withdrawal_id: self.withdrawal_request.cketh_ledger_burn_index(),
                    transaction: signed_tx.clone(),
                },
            );

            let tx_receipt = TransactionReceipt {
                block_hash: "0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472"
                    .parse()
                    .unwrap(),
                block_number: BlockNumber::new(4190269),
                effective_gas_price: self.effective_gas_price,
                gas_used: self.effective_gas_used,
                status: self.tx_status,
                transaction_hash: signed_tx.hash(),
            };
            apply_state_transition(
                state,
                &EventType::FinalizedTransaction {
                    withdrawal_id: self.withdrawal_request.cketh_ledger_burn_index(),
                    transaction_receipt: tx_receipt.clone(),
                },
            );
            tx_receipt
        }
    }

    fn initial_erc20_state() -> State {
        let mut state = initial_state();
        add_erc20_token(&mut state);
        state
    }

    fn accepted_withdrawal_request_event(request: WithdrawalRequest) -> EventType {
        match request {
            WithdrawalRequest::CkEth(request) => EventType::AcceptedEthWithdrawalRequest(request),
            WithdrawalRequest::CkErc20(request) => {
                EventType::AcceptedErc20WithdrawalRequest(request)
            }
            WithdrawalRequest::SweeperFunding(request) => {
                EventType::AcceptedSweeperFundingRequest(request)
            }
        }
    }

    fn add_erc20_token(state: &mut State) {
        use crate::state::CkErc20Token;
        apply_state_transition(
            state,
            &EventType::AddedCkErc20Token(CkErc20Token {
                erc20_ethereum_network: Default::default(),
                erc20_contract_address: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"
                    .parse()
                    .unwrap(),
                ckerc20_token_symbol: "ckSepoliaUSDC".parse().unwrap(),
                ckerc20_ledger_id: Principal::from_text("3sgad-taaaa-aaaar-qaedq-cai").unwrap(),
            }),
        );
    }
}

mod erc20_balance {
    use crate::eth_logs::{ReceivedErc20Event, ReceivedEvent};
    use crate::state::audit::EventType::AcceptedErc20WithdrawalRequest;
    use crate::state::audit::{EventType, apply_state_transition};
    use crate::state::tests::{
        checked_sub, erc20_withdrawal_request, initial_erc20_state, received_erc20_event,
        received_eth_event,
    };
    use crate::state::transactions::Erc20WithdrawalRequest;
    use crate::test_fixtures::expect_panic_with_message;
    use ic_ethereum_types::Address;
    use maplit::btreemap;

    #[test]
    fn should_panic_when_deposited_erc20_not_supported() {
        let mut state = initial_erc20_state();
        let unsupported_erc20_address: Address = "0x6b175474e89094c44da98b954eedeac495271d0f"
            .parse()
            .unwrap();
        assert!(
            !state
                .ckerc20_tokens
                .contains_alt(&unsupported_erc20_address)
        );

        let deposit_event = ReceivedErc20Event {
            erc20_contract_address: unsupported_erc20_address,
            ..received_erc20_event()
        };
        expect_panic_with_message(
            || {
                apply_state_transition(
                    &mut state,
                    &ReceivedEvent::from(deposit_event.clone()).into_deposit(),
                )
            },
            "BUG: unsupported ERC-20",
        );
    }

    #[test]
    fn should_panic_when_withdrawn_erc20_not_supported() {
        let mut state = initial_erc20_state();
        let unsupported_erc20_address: Address = "0x6b175474e89094c44da98b954eedeac495271d0f"
            .parse()
            .unwrap();
        assert!(
            !state
                .ckerc20_tokens
                .contains_alt(&unsupported_erc20_address)
        );
        apply_state_transition(
            &mut state,
            &EventType::AcceptedErc20Deposit(received_erc20_event()),
        );
        apply_state_transition(
            &mut state,
            &EventType::AcceptedDeposit(received_eth_event()),
        );
        let erc20_withdrawal = Erc20WithdrawalRequest {
            erc20_contract_address: unsupported_erc20_address,
            ..erc20_withdrawal_request()
        };
        expect_panic_with_message(
            || {
                apply_state_transition(
                    &mut state,
                    &AcceptedErc20WithdrawalRequest(erc20_withdrawal.clone()),
                )
            },
            "BUG: unsupported ERC-20",
        );
    }

    #[test]
    fn should_add_deposit_to_erc20_balance() {
        let mut state = initial_erc20_state();
        let balance_before = state.erc20_balances.clone();

        let deposit_event = received_erc20_event();
        apply_state_transition(
            &mut state,
            &ReceivedEvent::from(deposit_event.clone()).into_deposit(),
        );
        let balance_after = state.erc20_balances.clone();

        assert_eq!(
            checked_sub(balance_after, balance_before),
            btreemap! {
                deposit_event.erc20_contract_address => deposit_event.value
            }
        );
    }
    #[test]
    fn should_ignore_rejected_deposit() {
        let mut state = initial_erc20_state();
        let balance_before = state.erc20_balances.clone();

        let deposit_event = received_erc20_event();
        apply_state_transition(
            &mut state,
            &EventType::InvalidDeposit {
                event_source: deposit_event.source(),
                reason: "invalid principal".to_string(),
            },
        );
        let balance_after = state.erc20_balances.clone();

        assert_eq!(balance_after, balance_before);
    }
}

fn initial_erc20_state() -> State {
    let mut state = initial_state();
    add_erc20_token(&mut state);
    state
}

fn add_erc20_token(state: &mut State) {
    use crate::state::CkErc20Token;
    apply_state_transition(
        state,
        &EventType::AddedCkErc20Token(CkErc20Token {
            erc20_ethereum_network: Default::default(),
            erc20_contract_address: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"
                .parse()
                .unwrap(),
            ckerc20_token_symbol: "ckSepoliaUSDC".parse().unwrap(),
            ckerc20_ledger_id: Principal::from_text("3sgad-taaaa-aaaar-qaedq-cai").unwrap(),
        }),
    );
}

fn erc20_withdrawal_request() -> Erc20WithdrawalRequest {
    Erc20WithdrawalRequest {
        max_transaction_fee: Wei::from(30_000_000_000_000_000_u64),
        withdrawal_amount: Erc20Value::from(4_996_000_u64),
        destination: "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d"
            .parse()
            .unwrap(),
        cketh_ledger_burn_index: LedgerBurnIndex::new(5),
        erc20_contract_address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
            .parse()
            .unwrap(),
        ckerc20_ledger_id: Principal::from_text("3sgad-taaaa-aaaar-qaedq-cai").unwrap(),
        ckerc20_ledger_burn_index: LedgerBurnIndex::new(2),
        from: Principal::from_text(
            "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
        )
        .unwrap(),
        from_subaccount: None,
        created_at: 1_711_138_972_460_345_032,
    }
}

fn checked_sub(lhs: Erc20Balances, rhs: Erc20Balances) -> BTreeMap<Address, Erc20Value> {
    assert!(
        rhs.balance_by_erc20_contract
            .keys()
            .all(|rhs_erc20_contract| {
                lhs.balance_by_erc20_contract
                    .contains_key(rhs_erc20_contract)
            }),
        "BUG: Cannot subtract rhs {rhs:?} to lhs {lhs:?} since some ERC-20 contracts are missing in the lhs"
    );
    let mut result = lhs.balance_by_erc20_contract.clone();
    for (erc20_contract, rhs_value) in rhs.balance_by_erc20_contract.into_iter() {
        match lhs.balance_by_erc20_contract.get(&erc20_contract).unwrap() {
            lhs_value if lhs_value == &rhs_value => {
                result.remove(&erc20_contract);
            }
            lhs_value if lhs_value > &rhs_value => {
                result.insert(erc20_contract, lhs_value.checked_sub(rhs_value).unwrap());
            }
            lhs_value => panic!(
                "BUG: Cannot subtract rhs {rhs_value:?} to lhs {lhs_value:?} since it would underflow"
            ),
        }
    }
    result
}
