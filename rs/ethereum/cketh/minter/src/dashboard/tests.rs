use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::DashboardTemplate;
use crate::erc20::CkErc20Token;
use candid::{Nat, Principal};
use ic_cketh_minter::eth_logs::{EventSource, ReceivedErc20Event, ReceivedEthEvent};
use ic_cketh_minter::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::numeric::{
    BlockNumber, CkTokenAmount, Erc20Value, GasAmount, LedgerBurnIndex, LedgerMintIndex, LogIndex,
    TransactionNonce, Wei, WeiPerGas,
};
use ic_cketh_minter::state::audit::{apply_state_transition, EventType};
use ic_cketh_minter::state::transactions::{
    create_transaction, Erc20WithdrawalRequest, EthWithdrawalRequest, ReimbursementIndex,
    Subaccount, WithdrawalRequest,
};
use ic_cketh_minter::state::State;
use ic_cketh_minter::tx::{
    Eip1559Signature, Eip1559TransactionRequest, GasFeeEstimate, SignedEip1559TransactionRequest,
    TransactionPrice,
};
use ic_ethereum_types::Address;
use maplit::{btreemap, btreeset};
use std::str::FromStr;

#[test]
fn should_display_metadata() {
    let mut dashboard = DashboardTemplate {
        minter_address: "0x1789F79e95324A47c5Fd6693071188e82E9a3558".to_string(),
        eth_helper_contract_address: "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
        cketh_ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ecdsa_key_name: "key_1".to_string(),
        next_transaction_nonce: TransactionNonce::from(42_u8),
        minimum_withdrawal_amount: Wei::from(10_000_000_000_000_000_u64),
        ..initial_dashboard()
    };

    DashboardAssert::assert_that(dashboard.clone())
        .has_ethereum_network("Ethereum Testnet Sepolia")
        .has_minter_address("0x1789F79e95324A47c5Fd6693071188e82E9a3558")
        .has_eth_helper_contract_address("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34")
        .has_erc20_helper_contract_address("N/A")
        .has_cketh_ledger_canister_id("apia6-jaaaa-aaaar-qabma-cai")
        .has_tecdsa_key_name("key_1")
        .has_next_transaction_nonce("42")
        .has_minimum_withdrawal_amount("10_000_000_000_000_000")
        .has_eth_balance("0")
        .has_total_effective_tx_fees("0")
        .has_total_unspent_tx_fees("0");

    dashboard.erc20_helper_contract_address =
        "0xE1788E4834c896F1932188645cc36c54d1b80AC1".to_string();
    DashboardAssert::assert_that(dashboard.clone())
        .has_erc20_helper_contract_address("0xE1788E4834c896F1932188645cc36c54d1b80AC1");
}

#[test]
fn should_display_block_sync() {
    let dashboard = DashboardTemplate {
        last_observed_block: None,
        last_eth_synced_block: BlockNumber::from(4552270_u32),
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(dashboard)
        .has_no_elements_matching("#last-observed-block-number")
        .has_no_elements_matching("#last-erc20-synced-block-number")
        .has_last_eth_synced_block_href("https://sepolia.etherscan.io/block/4552270")
        .has_first_synced_block_href("https://sepolia.etherscan.io/block/3956207")
        .has_no_elements_matching("#skipped-blocks");

    let dashboard = DashboardTemplate {
        last_observed_block: Some(BlockNumber::from(4552271_u32)),
        last_eth_synced_block: BlockNumber::from(4552270_u32),
        last_erc20_synced_block: Some(BlockNumber::from(4552269_u32)),
        skipped_blocks: btreemap! {
            "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string() => btreeset! {BlockNumber::from(3552270_u32), BlockNumber::from(2552270_u32)},
            "0xE1788E4834c896F1932188645cc36c54d1b80AC1".to_string() => btreeset! {BlockNumber::from(3552370_u32), BlockNumber::from(2552370_u32)},
        },
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(dashboard)
        .has_last_observed_block_href("https://sepolia.etherscan.io/block/4552271")
        .has_last_eth_synced_block_href("https://sepolia.etherscan.io/block/4552270")
        .has_last_erc20_synced_block_href("https://sepolia.etherscan.io/block/4552269")
        .has_first_synced_block_href("https://sepolia.etherscan.io/block/3956207")
        .has_skipped_blocks(
            "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
            &[2552270, 3552270],
        )
        .has_skipped_blocks(
            "0xE1788E4834c896F1932188645cc36c54d1b80AC1",
            &[2552370, 3552370],
        );
}

#[test]
fn should_display_supported_erc20_tokens() {
    let usdc = ckusdc();
    let usdt = ckusdt();
    let dashboard = {
        let mut state = initial_state();
        state.ethereum_network = EthereumNetwork::Mainnet;
        state.record_add_ckerc20_token(usdc.clone());
        state.record_add_ckerc20_token(usdt.clone());
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_supported_erc20_tokens(
            1,
            &vec![
                "ckUSDC",
                "0",
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "mxzaz-hqaaa-aaaar-qaada-cai",
            ],
        )
        .has_supported_erc20_tokens(
            2,
            &vec![
                "ckUSDT",
                "0",
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                "sa4so-piaaa-aaaar-qacnq-cai",
            ],
        );
}

#[test]
fn should_display_pending_deposits_sorted_by_decreasing_block_number() {
    DashboardAssert::assert_that(initial_dashboard()).has_no_elements_matching("#pending-deposits");

    let dashboard = {
        let mut state = initial_state_with_usdc_support();

        let event_1 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960623_u32),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960625_u32),
            transaction_hash: "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796"
                .parse()
                .unwrap(),
            ..received_eth_event()
        };
        let event_3 = ReceivedErc20Event {
            block_number: BlockNumber::from(3960624_u32),
            ..received_erc20_event()
        };
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_1));
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_2));
        apply_state_transition(&mut state, &EventType::AcceptedErc20Deposit(event_3));
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_eth_balance("20_000_000_000_000_000")
        .has_erc20_balance(&ckusdc(), "10_000_000_000_000_000_000")
        .has_total_effective_tx_fees("0")
        .has_total_unspent_tx_fees("0")
        .has_pending_deposits(
            1,
            &vec![
                "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "ckETH",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "3960625",
            ],
        )
        .has_pending_deposits(
            2,
            &vec![
                "0x44d8e93a8f4bbc89ad35fc4fbbdb12cb597b4832da09c0b2300777be180fde87",
                "39",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "ckUSDC",
                "10_000_000_000_000_000_000",
                "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
                "3960624",
            ],
        )
        .has_pending_deposits(
            3,
            &vec![
                "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "ckETH",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "3960623",
            ],
        );
}

#[test]
fn should_display_minted_events_sorted_by_decreasing_mint_block_index() {
    DashboardAssert::assert_that(initial_dashboard()).has_no_elements_matching("#minted-events");

    let dashboard = {
        let mut state = initial_state_with_usdc_support();

        let event_1 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960623_u32),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960625_u32),
            transaction_hash: "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796"
                .parse()
                .unwrap(),
            ..received_eth_event()
        };
        let event_3 = ReceivedErc20Event {
            block_number: BlockNumber::from(3960624_u32),
            ..received_erc20_event()
        };
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_1.clone()));
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_2.clone()));
        apply_state_transition(
            &mut state,
            &EventType::AcceptedErc20Deposit(event_3.clone()),
        );
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: event_1.source(),
                mint_block_index: LedgerMintIndex::new(42),
            },
        );
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: event_2.source(),
                mint_block_index: LedgerMintIndex::new(43),
            },
        );
        apply_state_transition(
            &mut state,
            &EventType::MintedCkErc20 {
                event_source: event_3.source(),
                ckerc20_token_symbol: "ckUSDC".to_string(),
                erc20_contract_address: event_3.erc20_contract_address,
                mint_block_index: LedgerMintIndex::new(44),
            },
        );
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_minted_events(
            1,
            &vec![
                "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "ckETH",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "43",
            ],
        )
        .has_minted_events(
            2,
            &vec![
                "0x44d8e93a8f4bbc89ad35fc4fbbdb12cb597b4832da09c0b2300777be180fde87",
                "39",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "ckUSDC",
                "10_000_000_000_000_000_000",
                "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
                "44",
            ],
        )
        .has_minted_events(
            3,
            &vec![
                "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "ckETH",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "42",
            ],
        );
}

#[test]
fn should_display_rejected_deposits() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#rejected-deposits");

    let dashboard = {
        let mut state = initial_state();
        let event_source_1 = EventSource {
            transaction_hash: "0x05c6ec45699c9a6a4b1a4ea2058b0cee852ea2f19b18fb8313c04bf8156efde4"
                .parse()
                .unwrap(),
            log_index: LogIndex::from(11_u8),
        };
        let event_source_2 = EventSource {
            transaction_hash: "0x09a5ee10c942f99b79cabcfb9647fc06e79489c6a8e96d39faed4f3ac6bc83d3"
                .parse()
                .unwrap(),
            log_index: LogIndex::from(0_u8),
        };
        apply_state_transition(
            &mut state,
            &EventType::InvalidDeposit {
                event_source: event_source_1,
                reason: "failed to decode principal".to_string(),
            },
        );
        apply_state_transition(
            &mut state,
            &EventType::InvalidDeposit {
                event_source: event_source_2,
                reason: "failed to decode principal".to_string(),
            },
        );
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_eth_balance("0")
        .has_total_effective_tx_fees("0")
        .has_total_unspent_tx_fees("0")
        .has_rejected_deposits(
            1,
            &vec![
                "0x05c6ec45699c9a6a4b1a4ea2058b0cee852ea2f19b18fb8313c04bf8156efde4",
                "11",
                "Invalid deposit: failed to decode principal",
            ],
        )
        .has_rejected_deposits(
            2,
            &vec![
                "0x09a5ee10c942f99b79cabcfb9647fc06e79489c6a8e96d39faed4f3ac6bc83d3",
                "0",
                "Invalid deposit: failed to decode principal",
            ],
        );
}

#[test]
fn should_display_correct_cketh_token_symbol_based_on_network() {
    fn test(ethereum_network: EthereumNetwork, expected_symbol: &str) {
        let dashboard = {
            let mut state = initial_state();
            state.ethereum_network = ethereum_network;
            apply_state_transition(
                &mut state,
                &EventType::AcceptedEthWithdrawalRequest(cketh_withdrawal_request_with_index(
                    LedgerBurnIndex::new(15),
                )),
            );
            DashboardTemplate::from_state(&state)
        };
        DashboardAssert::assert_that(dashboard).has_withdrawal_requests(
            1,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                expected_symbol,
                "1_100_000_000_000_000",
                "N/A",
            ],
        );
    }
    test(EthereumNetwork::Sepolia, "ckSepoliaETH");
    test(EthereumNetwork::Mainnet, "ckETH");
}

#[test]
fn should_display_withdrawal_requests_sorted_by_decreasing_cketh_ledger_burn_index() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#withdrawal-requests");

    let dashboard = {
        let mut state = initial_state_with_usdc_support();
        apply_state_transition(
            &mut state,
            &EventType::AcceptedEthWithdrawalRequest(cketh_withdrawal_request_with_index(
                LedgerBurnIndex::new(15),
            )),
        );
        apply_state_transition(
            &mut state,
            &EventType::AcceptedErc20WithdrawalRequest(ckerc20_withdrawal_request_with_index(
                LedgerBurnIndex::new(16),
                &ckusdc(),
            )),
        );
        apply_state_transition(
            &mut state,
            &EventType::AcceptedEthWithdrawalRequest(EthWithdrawalRequest {
                created_at: Some(1699540751000000000),
                ..cketh_withdrawal_request_with_index(LedgerBurnIndex::new(17))
            }),
        );
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_withdrawal_requests(
            1,
            &vec![
                "17",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_100_000_000_000_000",
                "2023-11-09T14:39:11+00:00",
            ],
        )
        .has_withdrawal_requests(
            2,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckUSDC",
                "2_000_000",
                "2024-04-05T08:23:43+00:00",
            ],
        )
        .has_withdrawal_requests(
            3,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_100_000_000_000_000",
                "N/A",
            ],
        );
}

#[test]
fn should_display_pending_transactions_sorted_by_decreasing_cketh_ledger_burn_index() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#pending-transactions");

    let dashboard = {
        let mut state = initial_state_with_usdc_support();
        for (req, tx, _signed_tx, _receipt) in vec![
            cketh_withdrawal_flow(
                LedgerBurnIndex::new(15),
                TransactionNonce::from(0_u8),
                TransactionStatus::Success,
            ),
            ckerc20_withdrawal_flow(
                LedgerBurnIndex::new(16),
                TransactionNonce::from(1_u8),
                &ckusdc(),
                TransactionStatus::Success,
            ),
        ] {
            apply_state_transition(
                &mut state,
                &req.clone().into_accepted_withdrawal_request_event(),
            );
            apply_state_transition(
                &mut state,
                &EventType::CreatedTransaction {
                    withdrawal_id: req.cketh_ledger_burn_index(),
                    transaction: tx,
                },
            );
        }

        for (req, tx, signed_tx, _receipt) in vec![
            cketh_withdrawal_flow(
                LedgerBurnIndex::new(17),
                TransactionNonce::from(2_u8),
                TransactionStatus::Success,
            ),
            ckerc20_withdrawal_flow(
                LedgerBurnIndex::new(18),
                TransactionNonce::from(3_u8),
                &ckusdc(),
                TransactionStatus::Success,
            ),
        ] {
            let withdrawal_id = req.cketh_ledger_burn_index();
            apply_state_transition(&mut state, &req.into_accepted_withdrawal_request_event());
            apply_state_transition(
                &mut state,
                &EventType::CreatedTransaction {
                    withdrawal_id,
                    transaction: tx,
                },
            );
            apply_state_transition(
                &mut state,
                &EventType::SignedTransaction {
                    withdrawal_id,
                    transaction: signed_tx,
                },
            );
        }

        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_pending_transactions(
            1,
            &vec![
                "18",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckUSDC",
                "2_000_000",
                "Sent(0xd3718b4fa5863af0e14c99e1e7c05bb893fd5662215d378990077c1937372b9b)",
            ],
        )
        .has_pending_transactions(
            2,
            &vec![
                "17",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_058_000_000_000_000",
                "Sent(0xada056f5d3942fac34371527524b5ee8a45833eb5edc41a06ac7a742a6a59762)",
            ],
        )
        .has_pending_transactions(
            3,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckUSDC",
                "2_000_000",
                "Created",
            ],
        )
        .has_pending_transactions(
            4,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_058_000_000_000_000",
                "Created",
            ],
        );
}

#[test]
fn should_display_finalized_transactions_sorted_by_decreasing_cketh_ledger_burn_index() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#finalized-transactions");

    let dashboard = {
        let mut state = initial_state_with_usdc_support();
        let deposit = ReceivedEthEvent {
            //enough for withdrawals
            value: Wei::from(1_000_000_000_000_000_000_u128),
            ..received_eth_event()
        };
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(deposit.clone()));
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: deposit.source(),
                mint_block_index: LedgerMintIndex::new(42),
            },
        );
        let deposit = received_erc20_event();
        apply_state_transition(
            &mut state,
            &EventType::AcceptedErc20Deposit(deposit.clone()),
        );
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: deposit.source(),
                mint_block_index: LedgerMintIndex::new(43),
            },
        );
        for (req, tx, signed_tx, receipt) in vec![
            cketh_withdrawal_flow(
                LedgerBurnIndex::new(15),
                TransactionNonce::from(0_u8),
                TransactionStatus::Success,
            ),
            cketh_withdrawal_flow(
                LedgerBurnIndex::new(16),
                TransactionNonce::from(1_u8),
                TransactionStatus::Failure,
            ),
            ckerc20_withdrawal_flow(
                LedgerBurnIndex::new(17),
                TransactionNonce::from(2_u8),
                &ckusdc(),
                TransactionStatus::Success,
            ),
        ] {
            let id = req.cketh_ledger_burn_index();
            apply_state_transition(&mut state, &req.into_accepted_withdrawal_request_event());
            apply_state_transition(
                &mut state,
                &EventType::CreatedTransaction {
                    withdrawal_id: id,
                    transaction: tx,
                },
            );
            apply_state_transition(
                &mut state,
                &EventType::SignedTransaction {
                    withdrawal_id: id,
                    transaction: signed_tx,
                },
            );
            apply_state_transition(
                &mut state,
                &EventType::FinalizedTransaction {
                    withdrawal_id: id,
                    transaction_receipt: receipt,
                },
            );
        }

        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_eth_balance("983_900_000_000_015_000")
        .has_total_effective_tx_fees("15_041_999_999_985_000")
        .has_total_unspent_tx_fees("15_042_000_000_015_000")
        .has_erc20_balance(&ckusdc(), "9_999_999_999_998_000_000")
        .has_finalized_transactions(
            1,
            &vec![
                "17",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckUSDC",
                "2_000_000",
                "14_999_999_999_985_000",
                "5558738",
                "0xf438be51eb1fa6b1f68611ab23fab4386623013dbc8cf7791f639981542ba8c3",
                "Success",
            ],
        )
        .has_finalized_transactions(
            2,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0x9a4793ece4b3a487679a43dd465d8a4855fa2a23adc128a59eaaa9eb5837105e",
                "Failure",
            ],
        )
        .has_finalized_transactions(
            3,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0xdea6b45f0978fea7f38fe6957db7ee11dd0e351a6f24fe54598d8aec9c8a1527",
                "Success",
            ],
        );
}

#[test]
fn should_display_etherscan_links_according_to_chosen_network() {
    let sepolia_dashboard = DashboardTemplate {
        ethereum_network: EthereumNetwork::Sepolia,
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(sepolia_dashboard).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://sepolia.etherscan.io"),
    );

    let mainnet_dashboard = DashboardTemplate {
        ethereum_network: EthereumNetwork::Mainnet,
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(mainnet_dashboard).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://etherscan.io"),
    );
}

#[test]
fn should_display_reimbursed_requests() {
    use ic_cketh_minter::state::transactions::Reimbursed;

    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#reimbursed-transactions");

    let reimbursed_in_block = LedgerMintIndex::new(123);
    let reimbursed_amount = CkTokenAmount::new(100_102);

    let dashboard = {
        let mut state = initial_state_with_usdc_support();
        let deposit = ReceivedEthEvent {
            //enough for withdrawals
            value: Wei::from(1_000_000_000_000_000_000_u128),
            ..received_eth_event()
        };

        apply_state_transition(&mut state, &EventType::AcceptedDeposit(deposit.clone()));
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: deposit.source(),
                mint_block_index: LedgerMintIndex::new(42),
            },
        );

        for ((req, tx, signed_tx, receipt), is_reimbursed) in vec![
            (
                cketh_withdrawal_flow(
                    LedgerBurnIndex::new(15),
                    TransactionNonce::from(0_u8),
                    TransactionStatus::Success,
                ),
                true,
            ),
            (
                cketh_withdrawal_flow(
                    LedgerBurnIndex::new(16),
                    TransactionNonce::from(1_u8),
                    TransactionStatus::Failure,
                ),
                true,
            ),
            (
                cketh_withdrawal_flow(
                    LedgerBurnIndex::new(17),
                    TransactionNonce::from(2_u8),
                    TransactionStatus::Failure,
                ),
                true,
            ),
            (
                ckerc20_withdrawal_flow(
                    LedgerBurnIndex::new(18),
                    TransactionNonce::from(3_u8),
                    &ckusdc(),
                    TransactionStatus::Failure,
                ),
                true,
            ),
            (
                ckerc20_withdrawal_flow(
                    LedgerBurnIndex::new(19),
                    TransactionNonce::from(4_u8),
                    &ckusdc(),
                    TransactionStatus::Failure,
                ),
                false,
            ),
        ] {
            let id = req.cketh_ledger_burn_index();
            apply_state_transition(
                &mut state,
                &req.clone().into_accepted_withdrawal_request_event(),
            );
            apply_state_transition(
                &mut state,
                &EventType::CreatedTransaction {
                    withdrawal_id: id,
                    transaction: tx,
                },
            );
            apply_state_transition(
                &mut state,
                &EventType::SignedTransaction {
                    withdrawal_id: id,
                    transaction: signed_tx,
                },
            );
            apply_state_transition(
                &mut state,
                &EventType::FinalizedTransaction {
                    withdrawal_id: id,
                    transaction_receipt: receipt.clone(),
                },
            );
            if receipt.status == TransactionStatus::Failure {
                if is_reimbursed {
                    match req {
                        WithdrawalRequest::CkEth(_) => {
                            apply_state_transition(
                                &mut state,
                                &EventType::ReimbursedEthWithdrawal(Reimbursed {
                                    transaction_hash: Some(receipt.transaction_hash),
                                    burn_in_block: id,
                                    reimbursed_in_block,
                                    reimbursed_amount,
                                }),
                            );
                        }
                        WithdrawalRequest::CkErc20(r) => {
                            apply_state_transition(
                                &mut state,
                                &EventType::ReimbursedErc20Withdrawal {
                                    cketh_ledger_burn_index: id,
                                    ckerc20_ledger_id: r.ckerc20_ledger_id,
                                    reimbursed: Reimbursed {
                                        transaction_hash: Some(receipt.transaction_hash),
                                        burn_in_block: r.ckerc20_ledger_burn_index,
                                        reimbursed_in_block,
                                        reimbursed_amount,
                                    },
                                },
                            );
                        }
                    }
                } else {
                    apply_state_transition(
                        &mut state,
                        &EventType::QuarantinedReimbursement {
                            index: ReimbursementIndex::from(&req),
                        },
                    )
                }
            }
        }
        DashboardTemplate::from_state(&state)
    };

    // Check that we show latest first.
    DashboardAssert::assert_that(dashboard)
        .has_finalized_transactions(
            1,
            &vec![
                "19",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckUSDC",
                "2_000_000",
                "14_999_999_999_985_000",
                "5558738",
                "0x93ad3beb667849ae5cf0198e49e0d36110bded50eb92e8124e059f31ef0658d2",
                "Failure",
            ],
        )
        .has_finalized_transactions(
            2,
            &vec![
                "18",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckUSDC",
                "2_000_000",
                "14_999_999_999_985_000",
                "5558738",
                "0xd3718b4fa5863af0e14c99e1e7c05bb893fd5662215d378990077c1937372b9b",
                "Failure",
            ],
        )
        .has_finalized_transactions(
            3,
            &vec![
                "17",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0xada056f5d3942fac34371527524b5ee8a45833eb5edc41a06ac7a742a6a59762",
                "Failure",
            ],
        )
        .has_finalized_transactions(
            4,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0x9a4793ece4b3a487679a43dd465d8a4855fa2a23adc128a59eaaa9eb5837105e",
                "Failure",
            ],
        )
        .has_finalized_transactions(
            5,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "ckETH",
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0xdea6b45f0978fea7f38fe6957db7ee11dd0e351a6f24fe54598d8aec9c8a1527",
                "Success",
            ],
        )
        .has_reimbursed_transactions(1, &vec!["19", "N/A", "ckUSDC", "N/A", "N/A", "Quarantined"])
        .has_reimbursed_transactions(
            2,
            &vec![
                "18",
                "123",
                "ckUSDC",
                "2_000_000",
                "0xd3718b4fa5863af0e14c99e1e7c05bb893fd5662215d378990077c1937372b9b",
                "Reimbursed",
            ],
        )
        .has_reimbursed_transactions(
            3,
            &vec![
                "17",
                "123",
                "ckETH",
                "1_058_000_000_000_000",
                "0xada056f5d3942fac34371527524b5ee8a45833eb5edc41a06ac7a742a6a59762",
                "Reimbursed",
            ],
        )
        .has_reimbursed_transactions(
            4,
            &vec![
                "16",
                "123",
                "ckETH",
                "1_058_000_000_000_000",
                "0x9a4793ece4b3a487679a43dd465d8a4855fa2a23adc128a59eaaa9eb5837105e",
                "Reimbursed",
            ],
        );
}

fn initial_dashboard() -> DashboardTemplate {
    DashboardTemplate::from_state(&initial_state())
}

fn initial_state() -> State {
    use ic_cketh_minter::lifecycle::init::InitArg;
    State::try_from(InitArg {
        ethereum_network: Default::default(),
        ecdsa_key_name: "test_key_1".to_string(),
        ethereum_contract_address: None,
        ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ethereum_block_height: Default::default(),
        minimum_withdrawal_amount: Nat::from(10_000_000_000_000_000_u64),
        next_transaction_nonce: TransactionNonce::ZERO.into(),
        last_scraped_block_number: candid::Nat::from(3_956_206_u32),
    })
    .expect("valid init args")
}

fn initial_state_with_usdc_support() -> State {
    let mut state = initial_state();
    state.ethereum_network = EthereumNetwork::Mainnet;
    state.record_add_ckerc20_token(ckusdc());
    state
}

fn received_eth_event() -> ReceivedEthEvent {
    ReceivedEthEvent {
        transaction_hash: "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2"
            .parse()
            .unwrap(),
        block_number: BlockNumber::new(3960623u128),
        log_index: LogIndex::from(29u8),
        from_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
            .parse()
            .unwrap(),
        value: Wei::from(10_000_000_000_000_000_u128),
        principal: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
            .parse()
            .unwrap(),
    }
}

fn received_erc20_event() -> ReceivedErc20Event {
    ReceivedErc20Event {
        transaction_hash: "0x44d8e93a8f4bbc89ad35fc4fbbdb12cb597b4832da09c0b2300777be180fde87"
            .parse()
            .unwrap(),
        block_number: BlockNumber::new(5326500),
        log_index: LogIndex::from(39_u8),
        from_address: "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d"
            .parse()
            .unwrap(),
        value: Erc20Value::from(10_000_000_000_000_000_000_u128),
        principal: "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe"
            .parse()
            .unwrap(),
        erc20_contract_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap(),
    }
}

pub fn ckusdc() -> CkErc20Token {
    CkErc20Token {
        erc20_ethereum_network: EthereumNetwork::Mainnet,
        erc20_contract_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap(),
        ckerc20_token_symbol: "ckUSDC".parse().unwrap(),
        ckerc20_ledger_id: "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
    }
}

pub fn ckusdt() -> CkErc20Token {
    CkErc20Token {
        erc20_ethereum_network: EthereumNetwork::Mainnet,
        erc20_contract_address: "0xdac17f958d2ee523a2206206994597c13d831ec7"
            .parse()
            .unwrap(),
        ckerc20_token_symbol: "ckUSDT".parse().unwrap(),
        ckerc20_ledger_id: "sa4so-piaaa-aaaar-qacnq-cai".parse().unwrap(),
    }
}

fn cketh_withdrawal_request_with_index(ledger_burn_index: LedgerBurnIndex) -> EthWithdrawalRequest {
    const DEFAULT_WITHDRAWAL_AMOUNT: u128 = 1_100_000_000_000_000;
    const DEFAULT_PRINCIPAL: &str =
        "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae";
    const DEFAULT_SUBACCOUNT: [u8; 32] = [0x11; 32];
    const DEFAULT_RECIPIENT_ADDRESS: &str = "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34";
    EthWithdrawalRequest {
        ledger_burn_index,
        destination: Address::from_str(DEFAULT_RECIPIENT_ADDRESS).unwrap(),
        withdrawal_amount: Wei::new(DEFAULT_WITHDRAWAL_AMOUNT),
        from: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
        from_subaccount: Some(Subaccount(DEFAULT_SUBACCOUNT)),
        created_at: None,
    }
}

fn ckerc20_withdrawal_request_with_index(
    cketh_ledger_burn_index: LedgerBurnIndex,
    ckerc20_token: &CkErc20Token,
) -> Erc20WithdrawalRequest {
    const DEFAULT_PRINCIPAL: &str =
        "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae";
    const DEFAULT_SUBACCOUNT: [u8; 32] = [0x11; 32];
    const DEFAULT_RECIPIENT_ADDRESS: &str = "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34";
    Erc20WithdrawalRequest {
        max_transaction_fee: Wei::from(30_000_000_000_000_000_u64),
        withdrawal_amount: Erc20Value::from(2_000_000_u32),
        destination: Address::from_str(DEFAULT_RECIPIENT_ADDRESS).unwrap(),
        cketh_ledger_burn_index,
        erc20_contract_address: ckerc20_token.erc20_contract_address,
        ckerc20_ledger_id: ckerc20_token.ckerc20_ledger_id,
        ckerc20_ledger_burn_index: (cketh_ledger_burn_index.get() + 1_u64).into(),
        from: candid::Principal::from_str(DEFAULT_PRINCIPAL).unwrap(),
        from_subaccount: Some(Subaccount(DEFAULT_SUBACCOUNT)),
        created_at: 1712305423000000000,
    }
}

fn cketh_withdrawal_flow(
    ledger_burn_index: LedgerBurnIndex,
    nonce: TransactionNonce,
    tx_status: TransactionStatus,
) -> (
    WithdrawalRequest,
    Eip1559TransactionRequest,
    SignedEip1559TransactionRequest,
    TransactionReceipt,
) {
    let withdrawal_request = cketh_withdrawal_request_with_index(ledger_burn_index);
    let fee = TransactionPrice {
        max_priority_fee_per_gas: WeiPerGas::from(1_500_000_000_u64),
        max_fee_per_gas: WeiPerGas::from(2_000_000_000_u64),
        gas_limit: GasAmount::from(21_000_u32),
    };
    let max_fee = fee.max_transaction_fee();
    let transaction = Eip1559TransactionRequest {
        chain_id: EthereumNetwork::Sepolia.chain_id(),
        nonce,
        max_priority_fee_per_gas: fee.max_priority_fee_per_gas,
        max_fee_per_gas: fee.max_fee_per_gas,
        gas_limit: fee.gas_limit,
        destination: withdrawal_request.destination,
        amount: withdrawal_request
            .withdrawal_amount
            .checked_sub(max_fee)
            .unwrap(),
        data: vec![],
        access_list: Default::default(),
    };
    let dummy_signature = Eip1559Signature {
        signature_y_parity: false,
        r: Default::default(),
        s: Default::default(),
    };
    let signed_tx = SignedEip1559TransactionRequest::from((transaction.clone(), dummy_signature));
    let tx_receipt = TransactionReceipt {
        block_hash: "0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472"
            .parse()
            .unwrap(),
        block_number: BlockNumber::new(4190269),
        effective_gas_price: signed_tx
            .transaction()
            .max_fee_per_gas
            .checked_div_ceil(2_u8)
            .unwrap(),
        gas_used: signed_tx.transaction().gas_limit,
        status: tx_status,
        transaction_hash: signed_tx.hash(),
    };
    (
        withdrawal_request.into(),
        transaction,
        signed_tx,
        tx_receipt,
    )
}

fn ckerc20_withdrawal_flow(
    cketh_ledger_burn_index: LedgerBurnIndex,
    nonce: TransactionNonce,
    ckerc20_token: &CkErc20Token,
    tx_status: TransactionStatus,
) -> (
    WithdrawalRequest,
    Eip1559TransactionRequest,
    SignedEip1559TransactionRequest,
    TransactionReceipt,
) {
    let withdrawal_request =
        ckerc20_withdrawal_request_with_index(cketh_ledger_burn_index, ckerc20_token);
    let gas_fee = GasFeeEstimate {
        base_fee_per_gas: WeiPerGas::from(250_000_000_u64),
        max_priority_fee_per_gas: WeiPerGas::from(1_500_000_000_u64),
    };
    let transaction = create_transaction(
        &withdrawal_request.clone().into(),
        nonce,
        gas_fee,
        GasAmount::from(65_000_u32),
        EthereumNetwork::Sepolia,
    )
    .unwrap();
    let dummy_signature = Eip1559Signature {
        signature_y_parity: false,
        r: Default::default(),
        s: Default::default(),
    };
    let signed_tx = SignedEip1559TransactionRequest::from((transaction.clone(), dummy_signature));
    let tx_receipt = TransactionReceipt {
        block_hash: "0x736adb84ba42d14c2cd3611fce58bcc3d834938510739f3762c31b77d592a0e5"
            .parse()
            .unwrap(),
        block_number: BlockNumber::new(5558738),
        effective_gas_price: signed_tx
            .transaction()
            .max_fee_per_gas
            .checked_div_ceil(2_u8)
            .unwrap(),
        gas_used: signed_tx.transaction().gas_limit,
        status: tx_status,
        transaction_hash: signed_tx.hash(),
    };
    (
        withdrawal_request.into(),
        transaction,
        signed_tx,
        tx_receipt,
    )
}

mod assertions {
    use crate::dashboard::DashboardTemplate;
    use askama::Template;
    use ic_cketh_minter::erc20::CkErc20Token;
    use scraper::Html;
    use scraper::Selector;

    pub struct DashboardAssert {
        rendered_html: String,
        actual: Html,
    }

    impl DashboardAssert {
        pub fn assert_that(actual: DashboardTemplate) -> Self {
            let rendered_html = actual.render().unwrap();
            Self {
                actual: Html::parse_document(&rendered_html),
                rendered_html,
            }
        }

        pub fn has_no_elements_matching(&self, selector: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            assert!(
                self.actual.select(&selector).next().is_none(),
                "expected no elements matching '{:?}', but found some",
                selector
            );
            self
        }

        pub fn has_last_observed_block_href(&self, expected_href: &str) -> &Self {
            self.has_href_value(
                "#last-observed-block-number > td > a",
                expected_href,
                "wrong last observed block href",
            )
        }

        pub fn has_first_synced_block_href(&self, expected_href: &str) -> &Self {
            self.has_href_value(
                "#first-synced-block-number > td > a",
                expected_href,
                "wrong first synced block href",
            )
        }

        pub fn has_last_eth_synced_block_href(&self, expected_href: &str) -> &Self {
            self.has_href_value(
                "#last-eth-synced-block-number > td > a",
                expected_href,
                "wrong last ETH synced block href",
            )
        }

        pub fn has_last_erc20_synced_block_href(&self, expected_href: &str) -> &Self {
            self.has_href_value(
                "#last-erc20-synced-block-number > td > a",
                expected_href,
                "wrong last ERC20 synced block href",
            )
        }

        pub fn has_skipped_blocks(&self, contract_address: &str, expected_blocks: &[u64]) -> &Self {
            let expected_links = expected_blocks
                .iter()
                .map(|i| {
                    format!(
                        "<a href=\"https://sepolia.etherscan.io/block/{}\"><code>{}</code></a>",
                        i, i
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            self.has_html_value(
                &format!("#skipped-blocks-{} > td", contract_address),
                &expected_links,
                "wrong skipped blocks",
            )
        }

        pub fn has_links_satisfying<F: Fn(&str) -> bool, P: Fn(&str) -> bool>(
            &self,
            filter: F,
            predicate: P,
        ) -> &Self {
            let selector = Selector::parse("a").unwrap();
            for link in self.actual.select(&selector) {
                let href = link.value().attr("href").expect("href not found");
                if filter(href) {
                    assert!(
                        predicate(href),
                        "Link '{}' does not satisfy predicate",
                        href
                    );
                }
            }
            self
        }

        pub fn has_ethereum_network(&self, expected_network: &str) -> &Self {
            self.has_string_value(
                "#ethereum-network > td > a",
                expected_network,
                "wrong ethereum network",
            )
        }

        pub fn has_minter_address(&self, expected_address: &str) -> &Self {
            self.has_string_value(
                "#minter-address > td",
                expected_address,
                "wrong minter address",
            )
        }

        pub fn has_eth_helper_contract_address(&self, expected_address: &str) -> &Self {
            self.has_string_value(
                "#eth-helper-contract-address > td",
                expected_address,
                "wrong ETH helper contract address",
            )
        }

        pub fn has_erc20_helper_contract_address(&self, expected_address: &str) -> &Self {
            self.has_string_value(
                "#erc20-helper-contract-address > td",
                expected_address,
                "wrong ERC20 helper contract address",
            )
        }

        pub fn has_cketh_ledger_canister_id(&self, expected_id: &str) -> &Self {
            self.has_string_value(
                "#cketh-ledger-canister-id > td",
                expected_id,
                "wrong ledger canister ID",
            )
        }

        pub fn has_tecdsa_key_name(&self, expected_name: &str) -> &Self {
            self.has_string_value(
                "#tecdsa-key-name > td",
                expected_name,
                "wrong tECDSA key name",
            )
        }

        pub fn has_next_transaction_nonce(&self, expected_value: &str) -> &Self {
            self.has_string_value(
                "#next-transaction-nonce > td",
                expected_value,
                "wrong next transaction nonce",
            )
        }

        pub fn has_minimum_withdrawal_amount(&self, expected_value: &str) -> &Self {
            self.has_string_value(
                "#minimum-withdrawal-amount > td",
                expected_value,
                "wrong minimum withdrawal amount",
            )
        }

        pub fn has_eth_balance(&self, expected_value: &str) -> &Self {
            self.has_string_value("#eth-balance > td", expected_value, "wrong ETH balance")
        }

        pub fn has_total_effective_tx_fees(&self, expected_value: &str) -> &Self {
            self.has_string_value(
                "#total-effective-tx-fees > td",
                expected_value,
                "wrong total effective transaction fees",
            )
        }

        pub fn has_total_unspent_tx_fees(&self, expected_value: &str) -> &Self {
            self.has_string_value(
                "#total-unspent-tx-fees > td",
                expected_value,
                "wrong total unspent transaction fees",
            )
        }

        pub fn has_supported_erc20_tokens(
            &self,
            row_index: u8,
            expected_token: &Vec<&str>,
        ) -> &Self {
            self.has_table_row_string_value(
                &format!("#supported-ckerc20-tokens + table > tbody > tr:nth-child({row_index})"),
                expected_token,
                "wrong supported erc20 tokens",
            )
        }

        pub fn has_erc20_balance(&self, token: &CkErc20Token, expected_balance: &str) -> &Self {
            let token_symbol = format!("{}", token.ckerc20_token_symbol);
            let erc20_contract = format!("{}", token.erc20_contract_address);
            let ckerc20_ledger = format!("{}", token.ckerc20_ledger_id);
            let expected_value = vec![
                token_symbol.as_str(),
                expected_balance,
                erc20_contract.as_str(),
                ckerc20_ledger.as_str(),
            ];
            self.has_table_row_string_value(
                &format!("#supported-ckerc20-{}", token.ckerc20_ledger_id),
                &expected_value,
                "wrong supported erc20 tokens",
            )
        }

        pub fn has_pending_deposits(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#pending-deposits + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "pending-deposits",
            )
        }

        pub fn has_minted_events(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#minted-events + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "minted-events",
            )
        }

        pub fn has_rejected_deposits(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#rejected-deposits + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "rejected-deposits",
            )
        }

        pub fn has_withdrawal_requests(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#withdrawal-requests + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "withdrawal-requests",
            )
        }

        pub fn has_pending_transactions(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#pending-transactions + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "pending-transactions",
            )
        }

        pub fn has_finalized_transactions(
            &self,
            row_index: u8,
            expected_value: &Vec<&str>,
        ) -> &Self {
            self.has_table_row_string_value(
                &format!("#finalized-transactions + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "finalized-transactions",
            )
        }

        pub fn has_reimbursed_transactions(
            &self,
            row_index: u8,
            expected_value: &Vec<&str>,
        ) -> &Self {
            self.has_table_row_string_value(
                &format!("#reimbursed-transactions + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "reimbursed-transactions",
            )
        }

        fn has_table_row_string_value(
            &self,
            selector: &str,
            expected_value: &Vec<&str>,
            error_msg: &str,
        ) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value
                .text()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(
                &string_value, expected_value,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }

        fn has_string_value(&self, selector: &str, expected_value: &str, error_msg: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value.text().collect::<String>();
            assert_eq!(
                string_value, expected_value,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }

        fn has_html_value(&self, selector: &str, expected_value: &str, error_msg: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value.inner_html();
            assert_eq!(
                string_value, expected_value,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }

        fn has_href_value(&self, selector: &str, expected_href: &str, error_msg: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_href = only_one(&mut self.actual.select(&selector))
                .value()
                .attr("href")
                .expect("href not found");
            assert_eq!(
                actual_href, expected_href,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }
    }

    fn only_one<I, T>(iter: &mut I) -> T
    where
        I: Iterator<Item = T>,
    {
        let value = iter.next().expect("expected one element, got zero");
        assert!(iter.next().is_none(), "expected one element, got more");
        value
    }
}
