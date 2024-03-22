use crate::mock::{
    JsonRpcMethod, JsonRpcProvider, MockJsonRpcProviders, MockJsonRpcProvidersBuilder,
};
use crate::response::{
    block_response, fee_history, send_raw_transaction_response, transaction_count_response,
    transaction_receipt, EthLogEntry,
};
use crate::{
    assert_reply, CkEthSetup, DEFAULT_BLOCK_NUMBER, DEFAULT_DEPOSIT_BLOCK_NUMBER,
    DEFAULT_DEPOSIT_FROM_ADDRESS, DEFAULT_DEPOSIT_LOG_INDEX, DEFAULT_DEPOSIT_TRANSACTION_HASH,
    DEFAULT_PRINCIPAL_ID, EXPECTED_BALANCE, LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL, MAX_TICKS,
    MINTER_ADDRESS,
};
use candid::{Decode, Nat, Principal};
use ethers_core::utils::{hex, rlp};
use ic_base_types::PrincipalId;
use ic_cketh_minter::endpoints::events::{Event, EventPayload, EventSource};
use ic_cketh_minter::endpoints::RetrieveEthStatus::Pending;
use ic_cketh_minter::endpoints::{
    EthTransaction, RetrieveEthRequest, RetrieveEthStatus, TxFinalizedStatus, WithdrawalError,
};
use ic_cketh_minter::{
    PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL,
    SCRAPPING_ETH_LOGS_INTERVAL,
};
use ic_ethereum_types::Address;
use ic_state_machine_tests::MessageId;
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc3::transactions::{Burn, Mint, Transaction as LedgerTransaction};
use serde_json::json;
use std::convert::identity;
use std::str::FromStr;
use std::time::Duration;

pub struct DepositParams {
    pub from_address: Address,
    pub recipient: Principal,
    pub token_contract_address: Option<Address>,
    pub amount: u64,
    pub override_rpc_eth_get_block_by_number:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_eth_get_logs:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_erc20_get_logs:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_eth_log_entry: Box<dyn Fn(EthLogEntry) -> EthLogEntry>,
}

impl Default for DepositParams {
    fn default() -> Self {
        Self {
            from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
            recipient: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
            token_contract_address: None,
            amount: EXPECTED_BALANCE,
            override_rpc_eth_get_block_by_number: Box::new(identity),
            override_rpc_eth_get_logs: Box::new(identity),
            override_rpc_erc20_get_logs: Box::new(identity),
            override_eth_log_entry: Box::new(identity),
        }
    }
}

impl DepositParams {
    fn eth_log(&self) -> ethers_core::types::Log {
        ethers_core::types::Log::from((self.override_eth_log_entry)(self.eth_log_entry()))
    }

    pub fn eth_log_entry(&self) -> EthLogEntry {
        EthLogEntry {
            encoded_principal: encode_principal(self.recipient),
            amount: self.amount,
            from_address: self.from_address,
            transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
            token_contract_address: self.token_contract_address,
        }
    }

    pub fn is_erc20_deposit(&self) -> bool {
        self.token_contract_address.is_some()
    }

    pub fn with_erc20_token(mut self, token_contract_address: Address, amount: u64) -> Self {
        self.token_contract_address = Some(token_contract_address);
        self.amount = amount;
        self
    }

    pub fn with_mock_eth_get_block_by_number<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_get_block_by_number = Box::new(override_mock);
        self
    }

    pub fn with_mock_eth_get_logs<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_get_logs = Box::new(override_mock);
        self
    }

    pub fn with_mock_erc20_get_logs<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_erc20_get_logs = Box::new(override_mock);
        self
    }
}

pub struct DepositFlow {
    pub(crate) setup: CkEthSetup,
    pub(crate) params: DepositParams,
    pub(crate) minter_supports_erc20_deposit: bool,
}

impl DepositFlow {
    pub fn expect_mint(mut self) -> CkEthSetup {
        let balance_before = self.setup.balance_of(self.params.recipient);
        self.handle_deposit();
        let balance_after: Nat = self.updated_balance(&balance_before);
        assert_eq!(balance_after - balance_before, self.params.amount);

        self.setup.check_audit_log();

        let events = self.setup.get_all_events();
        assert_contains_unique_event(
            &events,
            EventPayload::AcceptedDeposit {
                transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                block_number: Nat::from(DEFAULT_DEPOSIT_BLOCK_NUMBER),
                log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                from_address: self.params.from_address.to_string(),
                value: Nat::from(self.params.amount),
                principal: self.params.recipient,
            },
        );
        assert_contains_unique_event(
            &events,
            EventPayload::MintedCkEth {
                event_source: EventSource {
                    transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                    log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                },
                mint_block_index: Nat::from(0_u8),
            },
        );
        self.setup
    }

    pub fn expect_erc20_mint(
        mut self,
        token_contract_address: Address,
        token_symbol: &str,
    ) -> CkEthSetup {
        // Set a custom block to make sure the ETH scraper makes only one RPC request.
        self.handle_deposit_until_block(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 50);

        // TODO XC-77: check changes in minter's erc20 balance

        // Pass extra time to make sure the minter finishes minting.
        for _ in 0..10 {
            self.setup.env.advance_time(Duration::from_secs(1));
            self.setup.env.tick();
        }

        self.setup.check_audit_log();

        let events = self.setup.get_all_events();
        assert_contains_unique_event(
            &events,
            EventPayload::AcceptedErc20Deposit {
                transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                block_number: Nat::from(DEFAULT_DEPOSIT_BLOCK_NUMBER),
                log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                from_address: self.params.from_address.to_string(),
                value: Nat::from(self.params.amount),
                principal: self.params.recipient,
                erc20_contract_address: token_contract_address.to_string(),
            },
        );
        assert_contains_unique_event(
            &events,
            EventPayload::MintedCkErc20 {
                event_source: EventSource {
                    transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                    log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                },
                ckerc20_token_symbol: token_symbol.to_string(),
                erc20_contract_address: token_contract_address.to_string(),
                mint_block_index: Nat::from(0_u8),
            },
        );
        self.setup
    }

    fn updated_balance(&self, balance_before: &Nat) -> Nat {
        let mut current_balance = balance_before.clone();
        for _ in 0..10 {
            self.setup.env.advance_time(Duration::from_secs(1));
            self.setup.env.tick();
            current_balance = self.setup.balance_of(self.params.recipient);
            if &current_balance != balance_before {
                break;
            }
        }
        current_balance
    }

    pub fn expect_no_mint(mut self) -> CkEthSetup {
        let balance_before = self.setup.balance_of(self.params.recipient);
        self.handle_deposit();
        let balance_after: Nat = self.updated_balance(&balance_before);
        assert_eq!(balance_before, balance_after);
        self.setup
    }

    pub fn expect_no_erc20_mint(mut self) -> CkEthSetup {
        self.handle_deposit();
        // TODO XC-77: check changes in minter's erc20 balance
        self.setup
    }

    fn handle_deposit(&mut self) {
        self.handle_deposit_until_block(DEFAULT_BLOCK_NUMBER)
    }

    fn handle_deposit_until_block(&mut self, block_number: u64) {
        self.setup.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);

        let default_get_block_by_number =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
                .respond_for_all_with(block_response(block_number));
        (self.params.override_rpc_eth_get_block_by_number)(default_get_block_by_number)
            .build()
            .expect_rpc_calls(&self.setup);

        self.setup.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);

        let mut eth_logs = vec![];
        let mut erc20_logs = vec![];

        // The deposit is either for eth or erc20, so we only push it to the right log.
        if self.params.is_erc20_deposit() {
            erc20_logs.push(self.params.eth_log())
        } else {
            eth_logs.push(self.params.eth_log())
        };

        let default_eth_get_logs =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs).respond_for_all_with(eth_logs);
        (self.params.override_rpc_eth_get_logs)(default_eth_get_logs)
            .build()
            .expect_rpc_calls(&self.setup);

        // Only minter upgraded with ERC20 helper contract will make RPC call that needs to be
        // fed with the ERC20 event logs.
        if self.minter_supports_erc20_deposit {
            let default_erc20_get_logs = MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
                .respond_for_all_with(erc20_logs);
            (self.params.override_rpc_erc20_get_logs)(default_erc20_get_logs)
                .build()
                .expect_rpc_calls(&self.setup);
        }
    }
}

pub struct LedgerTransactionAssert {
    pub(crate) setup: CkEthSetup,
    pub(crate) ledger_transaction: LedgerTransaction,
}

impl LedgerTransactionAssert {
    pub fn expect_mint(self, expected: Mint) -> CkEthSetup {
        assert_eq!(self.ledger_transaction.kind, "mint");
        assert_eq!(self.ledger_transaction.mint, Some(expected));
        assert_eq!(self.ledger_transaction.burn, None);
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }

    pub fn expect_burn(self, expected: Burn) -> CkEthSetup {
        assert_eq!(self.ledger_transaction.kind, "burn");
        assert_eq!(self.ledger_transaction.mint, None);
        assert_eq!(self.ledger_transaction.burn, Some(expected));
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }
}

pub struct ApprovalFlow {
    pub(crate) setup: CkEthSetup,
    pub(crate) approval_response: Result<Nat, ApproveError>,
}

impl ApprovalFlow {
    pub fn expect_error(self, error: ApproveError) -> CkEthSetup {
        assert_eq!(
            self.approval_response,
            Err(error),
            "BUG: unexpected result during approval"
        );
        self.setup
    }

    pub fn expect_ok(self, ledger_approval_id: u64) -> CkEthSetup {
        assert_eq!(
            self.approval_response,
            Ok(Nat::from(ledger_approval_id)),
            "BUG: unexpected result during approval"
        );
        self.setup
    }
}

pub struct WithdrawalFlow {
    pub(crate) setup: CkEthSetup,
    pub(crate) message_id: MessageId,
}

impl WithdrawalFlow {
    pub fn expect_withdrawal_request_accepted(self) -> ProcessWithdrawal {
        let response = self
            .minter_response()
            .expect("BUG: unexpected error from minter during withdrawal");
        ProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: response,
        }
    }

    pub fn expect_error(self, error: WithdrawalError) -> CkEthSetup {
        assert_eq!(
            self.minter_response(),
            Err(error),
            "BUG: unexpected result during withdrawal"
        );
        self.setup
    }

    fn minter_response(&self) -> Result<RetrieveEthRequest, WithdrawalError> {
        Decode!(&assert_reply(
        self.setup.env
            .await_ingress(self.message_id.clone(), MAX_TICKS)
            .expect("failed to resolve message with id: {message_id}"),
    ), Result<RetrieveEthRequest, WithdrawalError>)
        .unwrap()
    }
}

pub struct ProcessWithdrawal {
    pub setup: CkEthSetup,
    pub withdrawal_request: RetrieveEthRequest,
}

pub struct ProcessWithdrawalParams {
    pub override_rpc_eth_fee_history:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_latest_eth_get_transaction_count:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_eth_send_raw_transaction:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_finalized_eth_get_transaction_count:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_eth_get_transaction_receipt:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
}

impl Default for ProcessWithdrawalParams {
    fn default() -> Self {
        Self {
            override_rpc_eth_fee_history: Box::new(identity),
            override_rpc_latest_eth_get_transaction_count: Box::new(identity),
            override_rpc_eth_send_raw_transaction: Box::new(identity),
            override_rpc_finalized_eth_get_transaction_count: Box::new(identity),
            override_rpc_eth_get_transaction_receipt: Box::new(identity),
        }
    }
}

impl ProcessWithdrawalParams {
    pub fn with_mock_eth_get_transaction_receipt<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_get_transaction_receipt = Box::new(override_mock);
        self
    }

    pub fn with_mock_eth_fee_history<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_fee_history = Box::new(override_mock);
        self
    }
}

impl ProcessWithdrawal {
    pub fn withdrawal_id(&self) -> &Nat {
        &self.withdrawal_request.block_index
    }

    pub fn start_processing_withdrawals(self) -> FeeHistoryProcessWithdrawal {
        assert_eq!(
            self.setup.retrieve_eth_status(self.withdrawal_id()),
            Pending
        );
        self.setup
            .env
            .advance_time(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL);
        FeeHistoryProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }

    pub fn retry_processing_withdrawals(self) -> FeeHistoryProcessWithdrawal {
        self.setup
            .env
            .advance_time(PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL);
        FeeHistoryProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }

    pub fn wait_and_validate_withdrawal(
        self,
        params: ProcessWithdrawalParams,
    ) -> TransactionReceiptProcessWithdrawal {
        self.start_processing_withdrawals()
            .retrieve_fee_history(params.override_rpc_eth_fee_history)
            .expect_status(RetrieveEthStatus::Pending)
            .retrieve_latest_transaction_count(params.override_rpc_latest_eth_get_transaction_count)
            .expect_status(RetrieveEthStatus::TxCreated)
            .send_raw_transaction(params.override_rpc_eth_send_raw_transaction)
            .expect_status_sent()
            .retrieve_finalized_transaction_count(
                params.override_rpc_finalized_eth_get_transaction_count,
            )
            .expect_finalized_transaction()
            .retrieve_transaction_receipt(params.override_rpc_eth_get_transaction_receipt)
    }
}

pub struct FeeHistoryProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

impl FeeHistoryProcessWithdrawal {
    pub fn retrieve_fee_history<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_fee_history = MockJsonRpcProviders::when(JsonRpcMethod::EthFeeHistory)
            .respond_for_all_with(fee_history());
        (override_mock)(default_eth_fee_history)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn expect_status(
        self,
        status: RetrieveEthStatus,
    ) -> LatestTransactionCountProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        LatestTransactionCountProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct LatestTransactionCountProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

impl LatestTransactionCountProcessWithdrawal {
    pub fn retrieve_latest_transaction_count<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_get_latest_transaction_count =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetTransactionCount)
                .respond_for_all_with(transaction_count_response(0))
                .with_request_params(json!([MINTER_ADDRESS, "latest"]));
        (override_mock)(default_eth_get_latest_transaction_count)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn expect_status(self, status: RetrieveEthStatus) -> SendRawTransactionProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        SendRawTransactionProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct SendRawTransactionProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

impl SendRawTransactionProcessWithdrawal {
    pub fn send_raw_transaction<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_send_raw_transaction =
            MockJsonRpcProviders::when(JsonRpcMethod::EthSendRawTransaction)
                .respond_with(JsonRpcProvider::Ankr, send_raw_transaction_response());
        (override_mock)(default_eth_send_raw_transaction)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn send_raw_transaction_expecting(self, expected_sent_tx: &str) -> Self {
        use ethers_core::types::transaction::eip2718::TypedTransaction;

        let (tx, sig) = decode_transaction(expected_sent_tx);
        sig.verify(
            TypedTransaction::Eip1559(tx.clone()).sighash(),
            tx.from.unwrap(),
        )
        .expect("BUG: cannot verify signature of minter's ETH transaction");

        let tx_hash = hash_transaction(tx, sig);
        self.send_raw_transaction(|mock| {
            mock.with_request_params(json!([expected_sent_tx]))
                .respond_with(JsonRpcProvider::Ankr, tx_hash)
        })
    }

    pub fn expect_status_sent(self) -> FinalizedTransactionCountProcessWithdrawal {
        let tx_hash = match self
            .setup
            .retrieve_eth_status(&self.withdrawal_request.block_index)
        {
            RetrieveEthStatus::TxSent(tx) => tx.transaction_hash,
            other => panic!("BUG: unexpected transactions status {:?}", other),
        };
        FinalizedTransactionCountProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
            sent_transaction_hash: tx_hash,
        }
    }
}

pub struct FinalizedTransactionCountProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
    sent_transaction_hash: String,
}

impl FinalizedTransactionCountProcessWithdrawal {
    pub fn retrieve_finalized_transaction_count<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_get_latest_transaction_count =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetTransactionCount)
                .respond_for_all_with(transaction_count_response(1))
                .with_request_params(json!([MINTER_ADDRESS, "finalized"]));
        (override_mock)(default_eth_get_latest_transaction_count)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn expect_finalized_transaction(self) -> TransactionReceiptProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            RetrieveEthStatus::TxSent(EthTransaction {
                transaction_hash: self.sent_transaction_hash.clone()
            }),
            "BUG: unexpected status while processing withdrawal"
        );
        TransactionReceiptProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
            sent_transaction_hash: self.sent_transaction_hash,
        }
    }

    pub fn expect_pending_transaction(self) -> ProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            RetrieveEthStatus::TxSent(EthTransaction {
                transaction_hash: self.sent_transaction_hash.clone()
            }),
            "BUG: unexpected status while processing withdrawal"
        );
        ProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct TransactionReceiptProcessWithdrawal {
    pub setup: CkEthSetup,
    pub withdrawal_request: RetrieveEthRequest,
    pub sent_transaction_hash: String,
}

impl TransactionReceiptProcessWithdrawal {
    pub fn retrieve_transaction_receipt<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_get_transaction_receipt =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetTransactionReceipt)
                .respond_for_all_with(transaction_receipt(self.sent_transaction_hash.clone()));
        (override_mock)(default_eth_get_transaction_receipt)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    fn check_audit_logs_and_upgrade(mut self) -> Self {
        self.setup = self.setup.check_audit_logs_and_upgrade(Default::default());
        self
    }

    pub fn expect_status(self, status: RetrieveEthStatus) -> Self {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        self
    }

    pub fn expect_finalized_status(self, status: TxFinalizedStatus) -> CkEthSetup {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            RetrieveEthStatus::TxFinalized(status),
            "BUG: unexpected finalized status while processing withdrawal"
        );
        self.check_audit_logs_and_upgrade().setup
    }
}

fn decode_transaction(
    tx: &str,
) -> (
    ethers_core::types::Eip1559TransactionRequest,
    ethers_core::types::Signature,
) {
    use ethers_core::types::transaction::eip2718::TypedTransaction;

    TypedTransaction::decode_signed(&rlp::Rlp::new(
        &ethers_core::types::Bytes::from_str(tx).unwrap(),
    ))
    .map(|(tx, sig)| match tx {
        TypedTransaction::Eip1559(eip1559_tx) => (eip1559_tx, sig),
        _ => panic!("BUG: unexpected sent ETH transaction type {:?}", tx),
    })
    .expect("BUG: failed to deserialize sent ETH transaction")
}

fn hash_transaction(
    tx: ethers_core::types::Eip1559TransactionRequest,
    sig: ethers_core::types::Signature,
) -> ethers_core::types::TxHash {
    ethers_core::types::transaction::eip2718::TypedTransaction::Eip1559(tx).hash(&sig)
}

fn assert_contains_unique_event(events: &[Event], payload: EventPayload) {
    match events.iter().filter(|e| e.payload == payload).count() {
        0 => panic!("missing the event payload {payload:#?} in audit log {events:#?}"),
        1 => (),
        n => panic!("event payload {payload:#?} appears {n} times in audit log {events:#?}"),
    }
}

fn encode_principal(principal: Principal) -> String {
    let n = principal.as_slice().len();
    assert!(n <= 29);
    let mut fixed_bytes = [0u8; 32];
    fixed_bytes[0] = n as u8;
    fixed_bytes[1..=n].copy_from_slice(principal.as_slice());
    format!("0x{}", hex::encode(fixed_bytes))
}
