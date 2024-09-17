use crate::events::MinterEventAssert;
use crate::mock::{
    JsonRpcMethod, JsonRpcProvider, MockJsonRpcProviders, MockJsonRpcProvidersBuilder,
};
use crate::response::{
    block_response, encode_transaction, fee_history, send_raw_transaction_response,
    transaction_count_response, transaction_receipt, EthLogEntry,
};
use crate::{
    assert_reply, CkEthSetup, DEFAULT_BLOCK_NUMBER, DEFAULT_DEPOSIT_BLOCK_NUMBER,
    DEFAULT_DEPOSIT_FROM_ADDRESS, DEFAULT_DEPOSIT_LOG_INDEX, DEFAULT_DEPOSIT_TRANSACTION_HASH,
    DEFAULT_PRINCIPAL_ID, EFFECTIVE_GAS_PRICE, EXPECTED_BALANCE, GAS_USED, MAX_TICKS,
    MINTER_ADDRESS,
};
use candid::{Decode, Encode, Nat, Principal};
use ethers_core::utils::{hex, rlp};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cketh_minter::endpoints::ckerc20::RetrieveErc20Request;
use ic_cketh_minter::endpoints::events::{Event, EventPayload, EventSource};
use ic_cketh_minter::endpoints::{
    EthTransaction, RetrieveEthRequest, RetrieveEthStatus, TxFinalizedStatus, WithdrawalError,
    WithdrawalSearchParameter, WithdrawalStatus,
};
use ic_cketh_minter::{
    PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL,
    SCRAPING_ETH_LOGS_INTERVAL,
};
use ic_ethereum_types::Address;
use ic_state_machine_tests::{MessageId, StateMachine};
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc3::transactions::{Burn, Mint, Transaction as LedgerTransaction};
use num_traits::ToPrimitive;
use serde_json::json;
use std::convert::identity;
use std::str::FromStr;
use std::time::Duration;

pub struct DepositParams {
    pub from_address: Address,
    pub recipient: Principal,
    pub amount: u64,
    pub override_rpc_eth_get_block_by_number:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_eth_get_logs:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_eth_log_entry: Box<dyn Fn(EthLogEntry) -> EthLogEntry>,
}

impl Default for DepositParams {
    fn default() -> Self {
        Self {
            from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
            recipient: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
            amount: EXPECTED_BALANCE,
            override_rpc_eth_get_block_by_number: Box::new(identity),
            override_rpc_eth_get_logs: Box::new(identity),
            override_eth_log_entry: Box::new(identity),
        }
    }
}

impl DepositParams {
    pub fn eth_log(&self) -> ethers_core::types::Log {
        ethers_core::types::Log::from((self.override_eth_log_entry)(self.eth_log_entry()))
    }

    pub fn eth_log_entry(&self) -> EthLogEntry {
        EthLogEntry {
            encoded_principal: encode_principal(self.recipient),
            amount: self.amount,
            from_address: self.from_address,
            transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
        }
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
}

pub struct DepositFlow {
    pub(crate) setup: CkEthSetup,
    pub(crate) params: DepositParams,
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

    fn handle_deposit(&mut self) {
        self.handle_deposit_until_block(DEFAULT_BLOCK_NUMBER)
    }

    fn handle_deposit_until_block(&mut self, block_number: u64) {
        self.setup.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);

        let default_get_block_by_number =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
                .respond_for_all_with(block_response(block_number));
        (self.params.override_rpc_eth_get_block_by_number)(default_get_block_by_number)
            .build()
            .expect_rpc_calls(&self.setup);

        self.setup.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);

        let default_eth_get_logs = MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .respond_for_all_with(vec![self.params.eth_log()]);
        (self.params.override_rpc_eth_get_logs)(default_eth_get_logs)
            .build()
            .expect_rpc_calls(&self.setup);
    }
}

pub struct LedgerTransactionAssert<T> {
    pub(crate) setup: T,
    pub(crate) ledger_transaction: LedgerTransaction,
}

impl<T> LedgerTransactionAssert<T> {
    pub fn expect_mint(self, expected: Mint) -> T {
        assert_eq!(self.ledger_transaction.kind, "mint");
        assert_eq!(self.ledger_transaction.mint, Some(expected));
        assert_eq!(self.ledger_transaction.burn, None);
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }

    pub fn expect_burn(self, expected: Burn) -> T {
        assert_eq!(self.ledger_transaction.kind, "burn");
        assert_eq!(self.ledger_transaction.mint, None);
        assert_eq!(self.ledger_transaction.burn, Some(expected));
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }
}

pub fn call_ledger_id_get_transaction<T: Into<Nat>>(
    env: &StateMachine,
    ledger_id: CanisterId,
    ledger_index: T,
) -> LedgerTransaction {
    use icrc_ledger_types::icrc3::transactions::{GetTransactionsRequest, GetTransactionsResponse};

    let request = GetTransactionsRequest {
        start: ledger_index.into(),
        length: 1_u8.into(),
    };
    let mut response = Decode!(
        &assert_reply(
            env.query(ledger_id, "get_transactions", Encode!(&request).unwrap())
                .expect("failed to query get_transactions on the ledger")
        ),
        GetTransactionsResponse
    )
    .unwrap();
    assert_eq!(
        response.transactions.len(),
        1,
        "Expected exactly one transaction but got {:?}",
        response.transactions
    );
    response.transactions.pop().unwrap()
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
    pub fn expect_withdrawal_request_accepted(
        self,
    ) -> ProcessWithdrawal<CkEthSetup, RetrieveEthRequest> {
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

pub trait HasWithdrawalId {
    fn withdrawal_id(&self) -> &Nat;
}

impl HasWithdrawalId for RetrieveEthRequest {
    fn withdrawal_id(&self) -> &Nat {
        &self.block_index
    }
}

impl HasWithdrawalId for RetrieveErc20Request {
    fn withdrawal_id(&self) -> &Nat {
        &self.cketh_block_index
    }
}

pub struct ProcessWithdrawal<T, Req> {
    pub setup: T,
    pub withdrawal_request: Req,
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

    pub fn with_failed_transaction_receipt(self) -> Self {
        self.with_mock_eth_get_transaction_receipt(move |mock| {
            mock.modify_response_for_all(
                &mut |receipt: &mut ethers_core::types::TransactionReceipt| {
                    receipt.status = Some(0_u64.into())
                },
            )
        })
    }

    pub fn with_inconsistent_transaction_receipt(self) -> Self {
        self.with_mock_eth_get_transaction_receipt(move |mock| {
            mock.modify_response(
                JsonRpcProvider::BlockPi,
                &mut |response: &mut ethers_core::types::TransactionReceipt| {
                    response.status = Some(0.into())
                },
            )
            .modify_response(
                JsonRpcProvider::PublicNode,
                &mut |response: &mut ethers_core::types::TransactionReceipt| {
                    response.status = Some(1.into())
                },
            )
        })
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

impl<T: AsRef<CkEthSetup>, Req: HasWithdrawalId> ProcessWithdrawal<T, Req> {
    pub fn withdrawal_id(&self) -> &Nat {
        self.withdrawal_request.withdrawal_id()
    }

    fn assert_retrieve_eth_status(&self, status: RetrieveEthStatus) {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_id()),
            status,
            "BUG: unexpected retrieve_eth_status while processing withdrawal"
        );
    }

    fn assert_withdrawal_status(&self, withdrawal_status: WithdrawalStatus) {
        assert_eq!(
            self.setup
                .as_ref()
                .withdrawal_status(&WithdrawalSearchParameter::ByWithdrawalId(
                    self.withdrawal_request.withdrawal_id().0.to_u64().unwrap()
                ))
                .into_iter()
                .map(|x| x.status)
                .collect::<Vec<_>>(),
            vec![withdrawal_status],
            "BUG: unexpected withdrawal_status while processing withdrawal"
        );
    }

    pub fn start_processing_withdrawals(self) -> FeeHistoryProcessWithdrawal<T, Req> {
        self.assert_retrieve_eth_status(RetrieveEthStatus::Pending);
        self.assert_withdrawal_status(WithdrawalStatus::Pending);
        self.setup
            .as_ref()
            .env
            .advance_time(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL);
        FeeHistoryProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }

    pub fn retry_processing_withdrawals(self) -> FeeHistoryProcessWithdrawal<T, Req> {
        self.setup
            .as_ref()
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
    ) -> TransactionReceiptProcessWithdrawal<T, Req> {
        self.start_processing_withdrawals()
            .retrieve_fee_history(params.override_rpc_eth_fee_history)
            .expect_status(RetrieveEthStatus::Pending, WithdrawalStatus::Pending)
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

    pub fn process_withdrawal_with_resubmission_and_same_price(
        self,
        tx: ethers_core::types::Eip1559TransactionRequest,
        tx_sig: ethers_core::types::Signature,
    ) -> T {
        let sent_tx = encode_transaction(tx.clone(), tx_sig);
        let transaction = EthTransaction {
            transaction_hash: format!("{:?}", crate::response::hash_transaction(tx, tx_sig)),
        };
        self.start_processing_withdrawals()
            .retrieve_fee_history(identity)
            .expect_status(RetrieveEthStatus::Pending, WithdrawalStatus::Pending)
            .retrieve_latest_transaction_count(identity)
            .expect_status(RetrieveEthStatus::TxCreated)
            .send_raw_transaction_expecting(&sent_tx)
            .expect_status_sent()
            .retrieve_finalized_transaction_count(|mock| {
                mock.modify_response_for_all(&mut |count: &mut String| {
                    *count = transaction_count_response(0)
                })
            })
            .expect_pending_transaction()
            .retry_processing_withdrawals()
            .retrieve_fee_history(identity)
            .expect_status(
                RetrieveEthStatus::TxSent(transaction.clone()),
                WithdrawalStatus::TxSent(transaction.clone()),
            )
            .retrieve_latest_transaction_count(|mock| {
                mock.modify_response_for_all(&mut |count: &mut String| {
                    *count = transaction_count_response(0)
                })
            })
            .expect_status(RetrieveEthStatus::TxSent(transaction.clone()))
            .send_raw_transaction_expecting(&sent_tx)
            .expect_status_sent()
            .retrieve_finalized_transaction_count(|mock| {
                mock.modify_response_for_all(&mut |count: &mut String| {
                    *count = transaction_count_response(1)
                })
            })
            .expect_finalized_transaction()
            .retrieve_transaction_receipt(identity)
            .expect_finalized_status(TxFinalizedStatus::Success {
                transaction_hash: transaction.transaction_hash.clone(),
                effective_transaction_fee: Some((GAS_USED * EFFECTIVE_GAS_PRICE).into()),
            })
    }

    pub fn process_withdrawal_with_resubmission_and_increased_price<
        F: FnMut(&mut ethers_core::types::FeeHistory),
    >(
        self,
        first_tx: ethers_core::types::Eip1559TransactionRequest,
        first_tx_sig: ethers_core::types::Signature,
        change_fee_history: &mut F,
        resubmitted_tx: ethers_core::types::Eip1559TransactionRequest,
        resubmitted_tx_sig: ethers_core::types::Signature,
    ) -> T {
        let first_sent_tx = encode_transaction(first_tx.clone(), first_tx_sig);
        let first_tx_hash = hash_transaction(first_tx.clone(), first_tx_sig);
        let transaction = EthTransaction {
            transaction_hash: format!("{:?}", first_tx_hash),
        };
        let resubmitted_sent_tx = encode_transaction(resubmitted_tx.clone(), resubmitted_tx_sig);
        let resubmitted_tx_hash = hash_transaction(resubmitted_tx, resubmitted_tx_sig);
        let resubmitted_transaction = EthTransaction {
            transaction_hash: format!("{:?}", resubmitted_tx_hash),
        };

        self.start_processing_withdrawals()
            .retrieve_fee_history(identity)
            .expect_status(RetrieveEthStatus::Pending, WithdrawalStatus::Pending)
            .retrieve_latest_transaction_count(identity)
            .expect_status(RetrieveEthStatus::TxCreated)
            .send_raw_transaction_expecting(&first_sent_tx)
            .expect_status_sent()
            .retrieve_finalized_transaction_count(|mock| {
                mock.modify_response_for_all(&mut |count: &mut String| {
                    *count = transaction_count_response(0)
                })
            })
            .expect_pending_transaction()
            .retry_processing_withdrawals()
            .retrieve_fee_history(|mock| mock.modify_response_for_all(change_fee_history))
            .expect_status(
                RetrieveEthStatus::TxSent(transaction.clone()),
                WithdrawalStatus::TxSent(transaction),
            )
            .retrieve_latest_transaction_count(|mock| {
                mock.modify_response_for_all(&mut |count: &mut String| {
                    *count = transaction_count_response(0)
                })
            })
            .expect_status(RetrieveEthStatus::TxCreated)
            .send_raw_transaction_expecting(&resubmitted_sent_tx)
            .expect_status_sent()
            .retrieve_finalized_transaction_count(|mock| {
                mock.modify_response_for_all(&mut |count: &mut String| {
                    *count = transaction_count_response(1)
                })
            })
            .expect_finalized_transaction()
            .retrieve_transaction_receipt(|mock| {
                mock.with_request_params(json!([first_tx_hash]))
                    .respond_for_all_with(serde_json::Value::Null)
            })
            .retrieve_transaction_receipt(|mock| {
                mock.with_request_params(json!([resubmitted_tx_hash]))
                    .respond_for_all_with(transaction_receipt(format!("{:?}", resubmitted_tx_hash)))
            })
            .expect_finalized_status(TxFinalizedStatus::Success {
                transaction_hash: resubmitted_transaction.transaction_hash.clone(),
                effective_transaction_fee: Some((GAS_USED * EFFECTIVE_GAS_PRICE).into()),
            })
    }
}

pub struct FeeHistoryProcessWithdrawal<T, Req> {
    setup: T,
    withdrawal_request: Req,
}

impl<T: AsRef<CkEthSetup>, Req: HasWithdrawalId> FeeHistoryProcessWithdrawal<T, Req> {
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
        retrieve_eth_status: RetrieveEthStatus,
        withdrawal_status: WithdrawalStatus,
    ) -> LatestTransactionCountProcessWithdrawal<T, Req> {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_request.withdrawal_id()),
            retrieve_eth_status,
        );
        assert_eq!(
            self.setup
                .as_ref()
                .withdrawal_status(&WithdrawalSearchParameter::ByWithdrawalId(
                    self.withdrawal_request.withdrawal_id().0.to_u64().unwrap()
                ))
                .into_iter()
                .map(|x| x.status)
                .collect::<Vec<_>>(),
            vec![withdrawal_status],
        );
        LatestTransactionCountProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct LatestTransactionCountProcessWithdrawal<T, Req> {
    setup: T,
    withdrawal_request: Req,
}

impl<T: AsRef<CkEthSetup>, Req: HasWithdrawalId> LatestTransactionCountProcessWithdrawal<T, Req> {
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
        self.setup.as_ref().env.tick();
        self
    }

    pub fn expect_status(
        self,
        status: RetrieveEthStatus,
    ) -> SendRawTransactionProcessWithdrawal<T, Req> {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_request.withdrawal_id()),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        SendRawTransactionProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct SendRawTransactionProcessWithdrawal<T, Req> {
    setup: T,
    withdrawal_request: Req,
}

impl<T: AsRef<CkEthSetup>, Req: HasWithdrawalId> SendRawTransactionProcessWithdrawal<T, Req> {
    pub fn send_raw_transaction<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_send_raw_transaction = if self.setup.as_ref().evm_rpc_id.is_none() {
            MockJsonRpcProviders::when(JsonRpcMethod::EthSendRawTransaction)
                .respond_with(JsonRpcProvider::BlockPi, send_raw_transaction_response())
        } else {
            MockJsonRpcProviders::when(JsonRpcMethod::EthSendRawTransaction)
                .respond_for_all_with(send_raw_transaction_response())
        };
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
                .respond_with(JsonRpcProvider::BlockPi, tx_hash)
        })
    }

    pub fn expect_status_sent(self) -> FinalizedTransactionCountProcessWithdrawal<T, Req> {
        let tx_hash = match self
            .setup
            .as_ref()
            .retrieve_eth_status(self.withdrawal_request.withdrawal_id())
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

    pub fn expect_transaction_not_created(self) -> T {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_request.withdrawal_id()),
            RetrieveEthStatus::Pending,
            "BUG: unexpected status while processing withdrawal"
        );
        MinterEventAssert::from_fetching_all_events(self.setup).assert_has_no_event_satisfying(
            |event| {
                matches!(event, EventPayload::CreatedTransaction { withdrawal_id, .. }
                    if withdrawal_id == self.withdrawal_request.withdrawal_id())
            },
        )
    }
}

pub struct FinalizedTransactionCountProcessWithdrawal<T, Req> {
    setup: T,
    withdrawal_request: Req,
    sent_transaction_hash: String,
}

impl<T: AsRef<CkEthSetup>, Req: HasWithdrawalId>
    FinalizedTransactionCountProcessWithdrawal<T, Req>
{
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

    pub fn expect_finalized_transaction(self) -> TransactionReceiptProcessWithdrawal<T, Req> {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_request.withdrawal_id()),
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

    pub fn expect_pending_transaction(self) -> ProcessWithdrawal<T, Req> {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_request.withdrawal_id()),
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

pub struct TransactionReceiptProcessWithdrawal<T, Req> {
    pub setup: T,
    pub withdrawal_request: Req,
    pub sent_transaction_hash: String,
}

impl<T: AsRef<CkEthSetup>, Req: HasWithdrawalId> TransactionReceiptProcessWithdrawal<T, Req> {
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
        self.setup.as_ref().env.tick();
        self
    }

    pub fn expect_status(self, status: RetrieveEthStatus) -> Self {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_request.withdrawal_id()),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        self
    }

    pub fn expect_finalized_status(self, status: TxFinalizedStatus) -> T {
        assert_eq!(
            self.setup
                .as_ref()
                .retrieve_eth_status(self.withdrawal_request.withdrawal_id()),
            RetrieveEthStatus::TxFinalized(status),
            "BUG: unexpected finalized status while processing withdrawal"
        );
        self.setup
            .as_ref()
            .check_audit_logs_and_upgrade_as_ref(Default::default());
        self.setup
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

pub fn encode_principal(principal: Principal) -> String {
    let n = principal.as_slice().len();
    assert!(n <= 29);
    let mut fixed_bytes = [0u8; 32];
    fixed_bytes[0] = n as u8;
    fixed_bytes[1..=n].copy_from_slice(principal.as_slice());
    format!("0x{}", hex::encode(fixed_bytes))
}

pub fn increment_max_priority_fee_per_gas(fee_history: &mut ethers_core::types::FeeHistory) {
    for rewards in fee_history.reward.iter_mut() {
        for reward in rewards.iter_mut() {
            *reward = reward
                .checked_add(1_u64.into())
                .unwrap()
                .max((1_500_000_000_u64 + 1_u64).into());
        }
    }
}

pub fn increment_base_fee_per_gas(fee_history: &mut ethers_core::types::FeeHistory) {
    for base_fee_per_gas in fee_history.base_fee_per_gas.iter_mut() {
        *base_fee_per_gas = base_fee_per_gas.checked_add(1_u64.into()).unwrap();
    }
}

pub fn double_and_increment_base_fee_per_gas(fee_history: &mut ethers_core::types::FeeHistory) {
    for base_fee_per_gas in fee_history.base_fee_per_gas.iter_mut() {
        *base_fee_per_gas = base_fee_per_gas
            .checked_mul(2_u64.into())
            .and_then(|f| f.checked_add(1_u64.into()))
            .unwrap();
    }
}
