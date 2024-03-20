use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::DashboardTemplate;
use candid::Principal;
use ic_cketh_minter::eth_logs::{EventSource, ReceivedEthEvent};
use ic_cketh_minter::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::numeric::{
    BlockNumber, GasAmount, LedgerBurnIndex, LedgerMintIndex, LogIndex, TransactionNonce, Wei,
    WeiPerGas,
};
use ic_cketh_minter::state::audit::{apply_state_transition, EventType};
use ic_cketh_minter::state::transactions::{EthWithdrawalRequest, Subaccount};
use ic_cketh_minter::state::State;
use ic_cketh_minter::tx::{
    Eip1559Signature, Eip1559TransactionRequest, SignedEip1559TransactionRequest, TransactionPrice,
};
use ic_ethereum_types::Address;
use maplit::btreeset;
use std::str::FromStr;

#[test]
fn should_display_metadata() {
    let dashboard = DashboardTemplate {
        minter_address: "0x1789F79e95324A47c5Fd6693071188e82E9a3558".to_string(),
        eth_helper_contract_address: "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
        ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ecdsa_key_name: "key_1".to_string(),
        next_transaction_nonce: TransactionNonce::from(42_u8),
        minimum_withdrawal_amount: Wei::from(10_000_000_000_000_000_u64),
        ..initial_dashboard()
    };

    DashboardAssert::assert_that(dashboard)
        .has_ethereum_network("Ethereum Testnet Sepolia")
        .has_minter_address("0x1789F79e95324A47c5Fd6693071188e82E9a3558")
        .has_eth_helper_contract_address("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34")
        .has_ledger_canister_id("apia6-jaaaa-aaaar-qabma-cai")
        .has_tecdsa_key_name("key_1")
        .has_next_transaction_nonce("42")
        .has_minimum_withdrawal_amount("10_000_000_000_000_000")
        .has_eth_balance("0")
        .has_total_effective_tx_fees("0")
        .has_total_unspent_tx_fees("0");
}

#[test]
fn should_display_block_sync() {
    let dashboard = DashboardTemplate {
        last_observed_block: None,
        last_synced_block: BlockNumber::from(4552270_u32),
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(dashboard)
        .has_no_elements_matching("#last-observed-block-number")
        .has_last_synced_block_href("https://sepolia.etherscan.io/block/4552270")
        .has_first_synced_block_href("https://sepolia.etherscan.io/block/3956207")
        .has_no_elements_matching("#skipped-blocks");

    let dashboard = DashboardTemplate {
        last_observed_block: Some(BlockNumber::from(4552271_u32)),
        last_synced_block: BlockNumber::from(4552270_u32),
        skipped_blocks: btreeset! {BlockNumber::from(3552270_u32), BlockNumber::from(2552270_u32)},
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(dashboard)
        .has_last_observed_block_href("https://sepolia.etherscan.io/block/4552271")
        .has_last_synced_block_href("https://sepolia.etherscan.io/block/4552270")
        .has_first_synced_block_href("https://sepolia.etherscan.io/block/3956207")
        .has_skipped_blocks(
            r#"<a href="https://sepolia.etherscan.io/block/2552270"><code>2552270</code></a>, <a href="https://sepolia.etherscan.io/block/3552270"><code>3552270</code></a>"#,
        );

    let dashboard_with_single_skipped_block = DashboardTemplate {
        skipped_blocks: btreeset! {BlockNumber::from(3552270_u32)},
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(dashboard_with_single_skipped_block).has_skipped_blocks(
        r#"<a href="https://sepolia.etherscan.io/block/3552270"><code>3552270</code></a>"#,
    );
}

#[test]
fn should_display_events_to_mint_sorted_by_decreasing_block_number() {
    DashboardAssert::assert_that(initial_dashboard()).has_no_elements_matching("#events-to-mint");

    let dashboard = {
        let mut state = initial_state();
        let event_1 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960623_u32),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960624_u32),
            transaction_hash: "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796"
                .parse()
                .unwrap(),
            ..received_eth_event()
        };
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_1));
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_2));
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_eth_balance("20_000_000_000_000_000")
        .has_total_effective_tx_fees("0")
        .has_total_unspent_tx_fees("0")
        .has_events_to_mint(
            1,
            &vec![
                "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "3960624",
            ],
        )
        .has_events_to_mint(
            2,
            &vec![
                "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
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
        let mut state = initial_state();
        let event_1 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960623_u32),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960624_u32),
            transaction_hash: "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796"
                .parse()
                .unwrap(),
            ..received_eth_event()
        };
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_1.clone()));
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_2.clone()));
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
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_minted_events(
            1,
            &vec![
                "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "43",
            ],
        )
        .has_minted_events(
            2,
            &vec![
                "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
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
                "failed to decode principal",
            ],
        )
        .has_rejected_deposits(
            2,
            &vec![
                "0x09a5ee10c942f99b79cabcfb9647fc06e79489c6a8e96d39faed4f3ac6bc83d3",
                "0",
                "failed to decode principal",
            ],
        );
}

#[test]
fn should_display_withdrawal_requests_sorted_by_decreasing_ledger_burn_index() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#withdrawal-requests");

    let dashboard = {
        let mut state = initial_state();
        apply_state_transition(
            &mut state,
            &EventType::AcceptedEthWithdrawalRequest(withdrawal_request_with_index(
                LedgerBurnIndex::new(15),
            )),
        );
        apply_state_transition(
            &mut state,
            &EventType::AcceptedEthWithdrawalRequest(EthWithdrawalRequest {
                created_at: Some(1699540751000000000),
                ..withdrawal_request_with_index(LedgerBurnIndex::new(16))
            }),
        );
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_withdrawal_requests(
            1,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "1_100_000_000_000_000",
                "2023-11-09T14:39:11+00:00",
            ],
        )
        .has_withdrawal_requests(
            2,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "1_100_000_000_000_000",
                "N/A",
            ],
        );
}

#[test]
fn should_display_pending_transactions_sorted_by_decreasing_ledger_burn_index() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#pending-transactions");

    let dashboard = {
        let mut state = initial_state();
        let id_1 = LedgerBurnIndex::new(15);
        let (req_1, tx_1, _signed_tx_1, _receipt_1) = withdrawal_flow(
            id_1,
            TransactionNonce::from(0_u8),
            TransactionStatus::Success,
        );
        apply_state_transition(&mut state, &EventType::AcceptedEthWithdrawalRequest(req_1));
        apply_state_transition(
            &mut state,
            &EventType::CreatedTransaction {
                withdrawal_id: id_1,
                transaction: tx_1,
            },
        );

        let id_2 = LedgerBurnIndex::new(16);
        let (req_2, tx_2, signed_tx_2, _receipt_2) = withdrawal_flow(
            id_2,
            TransactionNonce::from(1_u8),
            TransactionStatus::Success,
        );
        apply_state_transition(&mut state, &EventType::AcceptedEthWithdrawalRequest(req_2));
        apply_state_transition(
            &mut state,
            &EventType::CreatedTransaction {
                withdrawal_id: id_2,
                transaction: tx_2,
            },
        );
        apply_state_transition(
            &mut state,
            &EventType::SignedTransaction {
                withdrawal_id: id_2,
                transaction: signed_tx_2,
            },
        );
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_pending_transactions(
            1,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "1_058_000_000_000_000",
                "Sent(0x9a4793ece4b3a487679a43dd465d8a4855fa2a23adc128a59eaaa9eb5837105e)",
            ],
        )
        .has_pending_transactions(
            2,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "1_058_000_000_000_000",
                "Created",
            ],
        );
}

#[test]
fn should_display_finalized_transactions_sorted_by_decreasing_ledger_burn_index() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#finalized-transactions");

    let dashboard = {
        let mut state = initial_state();
        let deposit = received_eth_event();
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(deposit.clone()));
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: deposit.source(),
                mint_block_index: LedgerMintIndex::new(42),
            },
        );
        for (req, tx, signed_tx, receipt) in vec![
            withdrawal_flow(
                LedgerBurnIndex::new(15),
                TransactionNonce::from(0_u8),
                TransactionStatus::Success,
            ),
            withdrawal_flow(
                LedgerBurnIndex::new(16),
                TransactionNonce::from(1_u8),
                TransactionStatus::Failure,
            ),
        ] {
            let id = req.ledger_burn_index;
            apply_state_transition(&mut state, &EventType::AcceptedEthWithdrawalRequest(req));
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
        .has_eth_balance("8_900_000_000_000_000")
        .has_total_effective_tx_fees("42_000_000_000_000")
        .has_total_unspent_tx_fees("42_000_000_000_000")
        .has_finalized_transactions(
            1,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0x9a4793ece4b3a487679a43dd465d8a4855fa2a23adc128a59eaaa9eb5837105e",
                "Failure",
            ],
        )
        .has_finalized_transactions(
            2,
            &vec![
                "15",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
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
    let reimbursed_amount = Wei::new(100_102);

    let dashboard = {
        let mut state = initial_state();
        let deposit = received_eth_event();
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(deposit.clone()));
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: deposit.source(),
                mint_block_index: LedgerMintIndex::new(42),
            },
        );

        for (req, tx, signed_tx, receipt) in vec![
            withdrawal_flow(
                LedgerBurnIndex::new(15),
                TransactionNonce::from(0_u8),
                TransactionStatus::Success,
            ),
            withdrawal_flow(
                LedgerBurnIndex::new(16),
                TransactionNonce::from(1_u8),
                TransactionStatus::Failure,
            ),
            withdrawal_flow(
                LedgerBurnIndex::new(17),
                TransactionNonce::from(2_u8),
                TransactionStatus::Failure,
            ),
        ] {
            let id = req.ledger_burn_index;
            apply_state_transition(&mut state, &EventType::AcceptedEthWithdrawalRequest(req));
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
                apply_state_transition(
                    &mut state,
                    &EventType::ReimbursedEthWithdrawal(Reimbursed {
                        transaction_hash: Some(receipt.transaction_hash),
                        withdrawal_id: id,
                        reimbursed_in_block,
                        reimbursed_amount,
                    }),
                );
            }
        }
        DashboardTemplate::from_state(&state)
    };

    // Check that we show latest first.
    DashboardAssert::assert_that(dashboard)
        .has_finalized_transactions(
            1,
            &vec![
                "17",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0xada056f5d3942fac34371527524b5ee8a45833eb5edc41a06ac7a742a6a59762",
                "Failure",
            ],
        )
        .has_finalized_transactions(
            2,
            &vec![
                "16",
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34",
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
                "1_058_000_000_000_000",
                "21_000_000_000_000",
                "4190269",
                "0xdea6b45f0978fea7f38fe6957db7ee11dd0e351a6f24fe54598d8aec9c8a1527",
                "Success",
            ],
        )
        .has_reimbursed_transactions(
            1,
            &vec![
                "17",
                "123",
                "1_058_000_000_000_000",
                "0xada056f5d3942fac34371527524b5ee8a45833eb5edc41a06ac7a742a6a59762",
            ],
        )
        .has_reimbursed_transactions(
            2,
            &vec![
                "16",
                "123",
                "1_058_000_000_000_000",
                "0x9a4793ece4b3a487679a43dd465d8a4855fa2a23adc128a59eaaa9eb5837105e",
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
        minimum_withdrawal_amount: Wei::TWO.into(),
        next_transaction_nonce: TransactionNonce::ZERO.into(),
        last_scraped_block_number: candid::Nat::from(3_956_206_u32),
    })
    .expect("valid init args")
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

fn withdrawal_request_with_index(ledger_burn_index: LedgerBurnIndex) -> EthWithdrawalRequest {
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

fn withdrawal_flow(
    ledger_burn_index: LedgerBurnIndex,
    nonce: TransactionNonce,
    tx_status: TransactionStatus,
) -> (
    EthWithdrawalRequest,
    Eip1559TransactionRequest,
    SignedEip1559TransactionRequest,
    TransactionReceipt,
) {
    let withdrawal_request = withdrawal_request_with_index(ledger_burn_index);
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
    (withdrawal_request, transaction, signed_tx, tx_receipt)
}

mod assertions {
    use crate::dashboard::DashboardTemplate;
    use askama::Template;
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

        pub fn has_last_synced_block_href(&self, expected_href: &str) -> &Self {
            self.has_href_value(
                "#last-synced-block-number > td > a",
                expected_href,
                "wrong last synced block href",
            )
        }

        pub fn has_skipped_blocks(&self, expected_links: &str) -> &Self {
            self.has_html_value(
                "#skipped-blocks > td",
                expected_links,
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
                "wrong contract address",
            )
        }

        pub fn has_ledger_canister_id(&self, expected_id: &str) -> &Self {
            self.has_string_value(
                "#ledger-canister-id > td",
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

        pub fn has_events_to_mint(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#events-to-mint + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "events-to-mint",
            )
        }

        pub fn has_minted_events(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#minted-events + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "events-to-mint",
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
