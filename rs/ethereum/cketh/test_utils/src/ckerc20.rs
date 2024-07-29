use crate::events::MinterEventAssert;
use crate::flow::{DepositParams, LedgerTransactionAssert, ProcessWithdrawal};
use crate::mock::{
    JsonRpcMethod, JsonRpcRequestMatcher, MockJsonRpcProviders, MockJsonRpcProvidersBuilder,
};
use crate::response::{block_response, empty_logs, fee_history, Erc20LogEntry};
use crate::{
    assert_reply, format_ethereum_address_to_eip_55, new_state_machine, CkEthSetup,
    DEFAULT_DEPOSIT_BLOCK_NUMBER, DEFAULT_DEPOSIT_FROM_ADDRESS, DEFAULT_DEPOSIT_LOG_INDEX,
    DEFAULT_DEPOSIT_TRANSACTION_HASH, DEFAULT_ERC20_DEPOSIT_LOG_INDEX,
    DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH, DEFAULT_PRINCIPAL_ID, ERC20_HELPER_CONTRACT_ADDRESS,
    ETH_HELPER_CONTRACT_ADDRESS, LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL, MAX_TICKS,
    RECEIVED_ERC20_EVENT_TOPIC,
};
use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cketh_minter::endpoints::ckerc20::{
    RetrieveErc20Request, WithdrawErc20Arg, WithdrawErc20Error,
};
use ic_cketh_minter::endpoints::events::{EventPayload, EventSource};
use ic_cketh_minter::endpoints::{CkErc20Token, MinterInfo};
use ic_cketh_minter::eth_rpc::FixedSizeData;
use ic_cketh_minter::numeric::{BlockNumber, Erc20Value};
use ic_cketh_minter::SCRAPING_ETH_LOGS_INTERVAL;
use ic_ethereum_types::Address;
pub use ic_ledger_suite_orchestrator::candid::AddErc20Arg as Erc20Token;
use ic_ledger_suite_orchestrator::candid::InitArg as LedgerSuiteOrchestratorInitArg;
use ic_ledger_suite_orchestrator_test_utils::{supported_erc20_tokens, LedgerSuiteOrchestrator};
use ic_state_machine_tests::{ErrorCode, MessageId, StateMachine, WasmResult};
use icrc_ledger_types::icrc1::account::Account;
use num_traits::ToPrimitive;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::identity;
use std::iter::zip;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS: &str =
    "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0";

pub const ONE_USDC: u64 = 1_000_000; //6 decimals
pub const TWO_USDC: u64 = 2_000_000; //6 decimals

pub struct CkErc20Setup {
    pub env: Arc<StateMachine>,
    pub cketh: CkEthSetup,
    pub orchestrator: LedgerSuiteOrchestrator,
    pub supported_erc20_tokens: Vec<Erc20Token>,
}

impl Default for CkErc20Setup {
    fn default() -> Self {
        Self::new(Arc::new(new_state_machine()))
    }
}

impl AsRef<CkEthSetup> for CkErc20Setup {
    fn as_ref(&self) -> &CkEthSetup {
        &self.cketh
    }
}

impl CkErc20Setup {
    pub fn new(env: Arc<StateMachine>) -> Self {
        let mut ckerc20 = Self::new_without_ckerc20_active(env);
        ckerc20.cketh = ckerc20
            .cketh
            .upgrade_minter_to_add_orchestrator_id(
                ckerc20
                    .orchestrator
                    .ledger_suite_orchestrator_id
                    .get_ref()
                    .0,
            )
            .upgrade_minter_to_add_erc20_helper_contract(ERC20_HELPER_CONTRACT_ADDRESS.to_string());
        ckerc20
    }

    pub fn new_without_ckerc20_active(env: Arc<StateMachine>) -> Self {
        let cketh = CkEthSetup::maybe_evm_rpc(env.clone());
        let orchestrator = LedgerSuiteOrchestrator::new(
            env.clone(),
            LedgerSuiteOrchestratorInitArg {
                more_controller_ids: vec![],
                minter_id: Some(cketh.minter_id.get_ref().0),
                cycles_management: None,
            },
        )
        .register_embedded_wasms();
        Self {
            env,
            cketh,
            orchestrator,
            supported_erc20_tokens: vec![],
        }
    }

    pub fn add_supported_erc20_tokens(mut self) -> Self {
        self.supported_erc20_tokens = supported_erc20_tokens();
        for token in self.supported_erc20_tokens.iter() {
            self.orchestrator = self
                .orchestrator
                .add_erc20_token(token.clone())
                .expect_new_ledger_and_index_canisters()
                .setup;
            let new_ledger_id = self
                .orchestrator
                .call_orchestrator_canister_ids(&token.contract)
                .unwrap()
                .ledger
                .unwrap();

            self.cketh = self.cketh.assert_has_unique_events_in_order(&vec![
                EventPayload::AddedCkErc20Token {
                    chain_id: token.contract.chain_id.clone(),
                    address: format_ethereum_address_to_eip_55(&token.contract.address),
                    ckerc20_token_symbol: token.ledger_init_arg.token_symbol.clone(),
                    ckerc20_ledger_id: new_ledger_id,
                },
            ]);
        }
        self
    }

    pub fn check_events(self) -> MinterEventAssert<Self> {
        MinterEventAssert::from_fetching_all_events(self)
    }

    pub fn get_minter_info(&self) -> MinterInfo {
        self.cketh.get_minter_info()
    }

    pub fn erc20_balance_from_get_minter_info(&self, erc20_contract_address: &str) -> u64 {
        let MinterInfo { erc20_balances, .. } = self.get_minter_info();
        erc20_balances
            .unwrap()
            .into_iter()
            .find(|balance| balance.erc20_contract_address == erc20_contract_address)
            .unwrap()
            .balance
            .0
            .to_u64()
            .unwrap()
    }

    pub fn deposit(self, params: CkErc20DepositParams) -> CkErc20DepositFlow {
        CkErc20DepositFlow {
            setup: self,
            params,
        }
    }

    pub fn deposit_cketh(mut self, params: DepositParams) -> Self {
        self.cketh = self.cketh.deposit(params).expect_mint();
        self
    }

    pub fn deposit_cketh_and_ckerc20(
        self,
        cketh_amount: u64,
        ckerc20_amount: u64,
        token: CkErc20Token,
        recipient: Principal,
    ) -> CkErc20DepositFlow {
        CkErc20DepositFlow {
            setup: self,
            params: CkErc20DepositParams {
                cketh_amount: Some(cketh_amount),
                recipient,
                ..CkErc20DepositParams::for_token(ckerc20_amount, token)
            },
        }
    }

    pub fn deposit_ckerc20(
        self,
        ckerc20_amount: u64,
        token: CkErc20Token,
        recipient: Principal,
    ) -> CkErc20DepositFlow {
        CkErc20DepositFlow {
            setup: self,
            params: CkErc20DepositParams {
                cketh_amount: None,
                recipient,
                ..CkErc20DepositParams::for_token(ckerc20_amount, token)
            },
        }
    }

    pub fn wait_for_updated_ledger_balance(
        &self,
        ledger_id: Principal,
        account: impl Into<Account>,
        balance_before: &Nat,
    ) -> Nat {
        let mut current_balance = balance_before.clone();
        let account = account.into();
        for _ in 0..10 {
            self.env.advance_time(Duration::from_secs(1));
            self.env.tick();
            current_balance = self.balance_of_ledger(ledger_id, account);
            if &current_balance != balance_before {
                break;
            }
        }
        current_balance
    }

    pub fn stop_ckerc20_ledger(&self, ledger_id: Principal) {
        let stop_res = self.env.stop_canister_as(
            self.orchestrator.ledger_suite_orchestrator_id.get(),
            CanisterId::unchecked_from_principal(ledger_id.into()),
        );
        assert_matches!(
            stop_res,
            Ok(WasmResult::Reply(_)),
            "Failed to stop ckERC20 ledger"
        );
    }

    pub fn start_ckerc20_ledger(&self, ledger_id: Principal) {
        let start_res = self.env.start_canister_as(
            self.orchestrator.ledger_suite_orchestrator_id.get(),
            CanisterId::unchecked_from_principal(ledger_id.into()),
        );
        assert_matches!(
            start_res,
            Ok(WasmResult::Reply(_)),
            "Failed to start ckERC20 ledger"
        );
    }

    pub fn balance_of_ledger(&self, ledger_id: Principal, account: impl Into<Account>) -> Nat {
        self.cketh.balance_of_ledger(
            CanisterId::unchecked_from_principal(ledger_id.into()),
            account,
        )
    }

    pub fn call_cketh_ledger_approve_minter(
        mut self,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> Self {
        self.cketh = self
            .cketh
            .call_ledger_approve_minter(from, amount, from_subaccount)
            .expect_ok(1);
        self
    }

    pub fn call_ckerc20_ledger_approve_minter(
        mut self,
        ledger_id: Principal,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> Self {
        self.cketh = self
            .cketh
            .call_ledger_id_approve_minter(
                CanisterId::unchecked_from_principal(ledger_id.into()),
                from,
                amount,
                from_subaccount,
            )
            .expect_ok(1);
        self
    }

    pub fn call_cketh_ledger_get_transaction<T: Into<Nat>>(
        self,
        ledger_index: T,
    ) -> LedgerTransactionAssert<Self> {
        let ledger_transaction = crate::flow::call_ledger_id_get_transaction(
            &self.env,
            self.cketh.ledger_id,
            ledger_index,
        );
        LedgerTransactionAssert {
            setup: self,
            ledger_transaction,
        }
    }

    pub fn call_ckerc20_ledger_get_transaction<T: Into<Nat>>(
        self,
        ledger_id: Principal,
        ledger_index: T,
    ) -> LedgerTransactionAssert<Self> {
        let ledger_transaction = crate::flow::call_ledger_id_get_transaction(
            &self.env,
            CanisterId::unchecked_from_principal(ledger_id.into()),
            ledger_index,
        );
        LedgerTransactionAssert {
            setup: self,
            ledger_transaction,
        }
    }

    pub fn call_minter_withdraw_erc20<A: Into<Nat>, R: Into<String>>(
        self,
        from: Principal,
        amount: A,
        ckerc20_ledger_id: Principal,
        recipient: R,
    ) -> RefreshGasFeeEstimate {
        let arg = WithdrawErc20Arg {
            amount: amount.into(),
            ckerc20_ledger_id,
            recipient: recipient.into(),
        };
        let message_id = self.env.send_ingress(
            PrincipalId::from(from),
            self.cketh.minter_id,
            "withdraw_erc20",
            Encode!(&arg).expect("failed to encode withdraw args"),
        );
        RefreshGasFeeEstimate {
            setup: self,
            message_id,
        }
    }

    pub fn caller(&self) -> Principal {
        self.cketh.caller.into()
    }

    pub fn cketh_ledger_id(&self) -> Principal {
        self.cketh.ledger_id.get_ref().0
    }

    pub fn find_ckerc20_token(&self, token_symbol: &str) -> CkErc20Token {
        self.cketh
            .get_minter_info()
            .supported_ckerc20_tokens
            .expect("BUG: no ckERC20 tokens supported")
            .iter()
            .find(|t| t.ckerc20_token_symbol == token_symbol)
            .unwrap()
            .clone()
    }

    pub fn supported_erc20_contract_addresses(&self) -> BTreeSet<Address> {
        self.supported_erc20_tokens
            .iter()
            .map(|token| Address::from_str(&token.contract.address).unwrap())
            .collect()
    }

    pub fn supported_erc20_contract_address_topics(&self) -> Vec<String> {
        self.supported_erc20_contract_addresses()
            .iter()
            .map(|erc20_address| FixedSizeData(erc20_address.into()).to_string())
            .collect()
    }

    pub fn received_erc20_event_topic(&self) -> serde_json::Value {
        self.as_ref()
            .json_topic(RECEIVED_ERC20_EVENT_TOPIC.to_string())
    }
}

pub struct CkErc20DepositParams {
    pub from_address: Address,
    pub cketh_amount: Option<u64>,
    pub ckerc20_amount: u64,
    pub recipient: Principal,
    pub token: CkErc20Token,
    pub override_erc20_log_entry: Box<dyn Fn(Erc20LogEntry) -> Erc20LogEntry>,
}

impl CkErc20DepositParams {
    pub fn for_token(ckerc20_amount: u64, token: CkErc20Token) -> Self {
        Self {
            from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
            cketh_amount: None,
            ckerc20_amount,
            recipient: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
            token,
            override_erc20_log_entry: Box::new(identity),
        }
    }

    pub fn erc20_log(&self) -> ethers_core::types::Log {
        ethers_core::types::Log::from((self.override_erc20_log_entry)(self.erc20_log_entry()))
    }

    pub fn erc20_log_entry(&self) -> Erc20LogEntry {
        Erc20LogEntry {
            encoded_principal: crate::flow::encode_principal(self.recipient),
            amount: self.ckerc20_amount,
            from_address: self.from_address,
            transaction_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.to_string(),
            erc20_contract_address: self.token.erc20_contract_address.parse().unwrap(),
        }
    }
}

pub struct CkErc20DepositFlow {
    pub setup: CkErc20Setup,
    params: CkErc20DepositParams,
}

impl AsRef<CkEthSetup> for CkErc20DepositFlow {
    fn as_ref(&self) -> &CkEthSetup {
        &self.setup.cketh
    }
}

impl CkErc20DepositFlow {
    pub fn expect_mint(mut self) -> CkErc20Setup {
        let cketh_balance_before = self
            .setup
            .balance_of_ledger(self.setup.cketh_ledger_id(), self.params.recipient);
        let ckerc20_balance_before = self
            .setup
            .balance_of_ledger(self.params.token.ledger_canister_id, self.params.recipient);
        let MinterInfo {
            erc20_balances: erc20_balances_before,
            ..
        } = self.setup.get_minter_info();

        self.handle_log_scraping();

        let cketh_balance_after = self.setup.wait_for_updated_ledger_balance(
            self.setup.cketh_ledger_id(),
            self.params.recipient,
            &cketh_balance_before,
        );
        let ckerc20_balance_after = self.setup.wait_for_updated_ledger_balance(
            self.params.token.ledger_canister_id,
            self.params.recipient,
            &ckerc20_balance_before,
        );
        let MinterInfo {
            erc20_balances: erc20_balances_after,
            ..
        } = self.setup.get_minter_info();

        assert_eq!(
            cketh_balance_after - cketh_balance_before,
            self.params.cketh_amount.unwrap_or_default()
        );
        assert_eq!(
            ckerc20_balance_after - ckerc20_balance_before,
            self.params.ckerc20_amount
        );

        let erc20_balances_before = erc20_balances_before.unwrap();
        let erc20_balances_after = erc20_balances_after.unwrap();
        assert_eq!(erc20_balances_before.len(), erc20_balances_after.len());
        let mut has_deposited_token = false;
        for (balance_before, balance_after) in zip(erc20_balances_before, erc20_balances_after) {
            if balance_before.erc20_contract_address == self.params.token.erc20_contract_address {
                assert_eq!(
                    balance_after.balance - balance_before.balance,
                    self.params.ckerc20_amount
                );
                has_deposited_token = true;
            } else {
                assert_eq!(balance_after.balance, balance_before.balance);
            }
        }
        assert!(has_deposited_token);

        self.setup.cketh.check_audit_log();

        let mut expected_events = match self.params.cketh_amount {
            Some(amount) => {
                vec![
                    EventPayload::AcceptedDeposit {
                        transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                        block_number: Nat::from(DEFAULT_DEPOSIT_BLOCK_NUMBER),
                        log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                        from_address: format_ethereum_address_to_eip_55(
                            DEFAULT_DEPOSIT_FROM_ADDRESS,
                        ),
                        value: amount.into(),
                        principal: self.params.recipient,
                    },
                    EventPayload::MintedCkEth {
                        event_source: EventSource {
                            transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                            log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                        },
                        mint_block_index: Nat::from(0_u8),
                    },
                ]
            }
            None => vec![],
        };
        expected_events.extend(vec![
            EventPayload::AcceptedErc20Deposit {
                transaction_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.to_string(),
                block_number: Nat::from(DEFAULT_DEPOSIT_BLOCK_NUMBER),
                log_index: Nat::from(DEFAULT_ERC20_DEPOSIT_LOG_INDEX),
                from_address: format_ethereum_address_to_eip_55(DEFAULT_DEPOSIT_FROM_ADDRESS),
                value: self.params.ckerc20_amount.into(),
                principal: self.params.recipient,
                erc20_contract_address: self.params.token.erc20_contract_address.clone(),
            },
            EventPayload::MintedCkErc20 {
                event_source: EventSource {
                    transaction_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.to_string(),
                    log_index: Nat::from(DEFAULT_ERC20_DEPOSIT_LOG_INDEX),
                },
                ckerc20_token_symbol: self.params.token.ckerc20_token_symbol,
                erc20_contract_address: self.params.token.erc20_contract_address,
                mint_block_index: Nat::from(0_u8),
            },
        ]);

        self.setup.cketh = self
            .setup
            .cketh
            .assert_has_unique_events_in_order(&expected_events);
        self.setup
    }

    pub fn handle_log_scraping(&self) {
        let max_eth_logs_block_range = self.as_ref().max_logs_block_range();
        let latest_finalized_block =
            LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1 + max_eth_logs_block_range;
        self.setup.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
            .respond_for_all_with(block_response(latest_finalized_block))
            .build()
            .expect_rpc_calls(self);
        let erc20_topics = self.setup.supported_erc20_contract_address_topics();

        let first_from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
        let first_to_block = first_from_block
            .checked_add(BlockNumber::from(max_eth_logs_block_range))
            .unwrap();

        let eth_logs = match self.params.cketh_amount {
            Some(amount) => vec![DepositParams {
                amount,
                recipient: self.params.recipient,
                ..Default::default()
            }
            .eth_log()],
            None => empty_logs(),
        };
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": first_from_block,
                "toBlock": first_to_block,
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [self.as_ref().received_eth_event_topic()]
            }]))
            .respond_for_all_with(eth_logs)
            .build()
            .expect_rpc_calls(self);

        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": first_from_block,
                "toBlock": first_to_block,
                "address": [ERC20_HELPER_CONTRACT_ADDRESS],
                "topics": [self.setup.received_erc20_event_topic(), erc20_topics.clone()]
            }]))
            .respond_for_all_with(vec![self.params.erc20_log()])
            .build()
            .expect_rpc_calls(self);
    }

    pub fn expect_no_mint(self) -> CkErc20Setup {
        let cketh_balance_before = self
            .setup
            .balance_of_ledger(self.setup.cketh_ledger_id(), self.params.recipient);
        let ckerc20_balance_before = self
            .setup
            .balance_of_ledger(self.params.token.ledger_canister_id, self.params.recipient);

        self.handle_log_scraping();

        let cketh_balance_after = self.setup.wait_for_updated_ledger_balance(
            self.setup.cketh_ledger_id(),
            self.params.recipient,
            &cketh_balance_before,
        );
        let ckerc20_balance_after = self.setup.wait_for_updated_ledger_balance(
            self.params.token.ledger_canister_id,
            self.params.recipient,
            &ckerc20_balance_before,
        );

        assert_eq!(cketh_balance_before, cketh_balance_after);
        assert_eq!(ckerc20_balance_before, ckerc20_balance_after);
        self.setup
    }
}

pub struct RefreshGasFeeEstimate {
    pub setup: CkErc20Setup,
    pub message_id: MessageId,
}

impl RefreshGasFeeEstimate {
    pub fn expect_refresh_gas_fee_estimate<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Erc20WithdrawalFlow {
        let default_eth_fee_history = MockJsonRpcProviders::when(JsonRpcMethod::EthFeeHistory)
            .respond_for_all_with(fee_history());
        (override_mock)(default_eth_fee_history)
            .build()
            .expect_rpc_calls(&self.setup);
        Erc20WithdrawalFlow {
            setup: self.setup,
            message_id: self.message_id,
        }
    }

    pub fn expect_no_refresh_gas_fee_estimate(self) -> Erc20WithdrawalFlow {
        assert_eq!(
            JsonRpcRequestMatcher::new_for_all_providers(JsonRpcMethod::EthFeeHistory)
                .iter()
                .filter(|(_provider, matcher)| matcher.find_rpc_call(&self.setup.env).is_some())
                .collect::<BTreeMap<_, _>>(),
            BTreeMap::new(),
            "BUG: unexpected EthFeeHistory RPC call"
        );

        Erc20WithdrawalFlow {
            setup: self.setup,
            message_id: self.message_id,
        }
    }
}

pub struct Erc20WithdrawalFlow {
    pub setup: CkErc20Setup,
    pub message_id: MessageId,
}

impl Erc20WithdrawalFlow {
    pub fn expect_trap(self, error_substring: &str) -> CkErc20Setup {
        let result = self
            .setup
            .env
            .await_ingress(self.message_id.clone(), MAX_TICKS);
        assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains(error_substring));
        self.setup
    }

    pub fn expect_error(self, error: WithdrawErc20Error) -> CkErc20Setup {
        assert_eq!(
            self.minter_response(),
            Err(error),
            "BUG: unexpected result during withdrawal"
        );
        self.setup
    }

    pub fn expect_withdrawal_request_accepted(
        self,
    ) -> ProcessWithdrawal<CkErc20Setup, RetrieveErc20Request> {
        let response = self
            .minter_response()
            .expect("BUG: unexpected error from minter during withdrawal");
        ProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: response,
        }
    }

    #[allow(clippy::result_large_err)]
    fn minter_response(&self) -> Result<RetrieveErc20Request, WithdrawErc20Error> {
        Decode!(&assert_reply(
        self.setup.env
            .await_ingress(self.message_id.clone(), MAX_TICKS)
            .expect("failed to resolve message with id: {message_id}"),
    ), Result<RetrieveErc20Request, WithdrawErc20Error>)
        .unwrap()
    }
}

#[allow(deprecated)]
pub fn erc20_transfer_data(expected_address: &Address, expected_amount: &Erc20Value) -> Vec<u8> {
    use ethers_core::abi::{Param, ParamType, Token};

    let erc20_transfer = ethers_core::abi::Function {
        name: "transfer".to_string(),
        inputs: vec![
            Param {
                name: "_to".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            },
            Param {
                name: "_value".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            },
        ],
        outputs: vec![Param {
            name: "success".to_string(),
            kind: ParamType::Bool,
            internal_type: None,
        }],
        constant: None,
        state_mutability: ethers_core::abi::StateMutability::NonPayable,
    };
    assert_eq!(
        erc20_transfer.short_signature().to_vec(),
        hex::decode("a9059cbb").unwrap()
    );
    erc20_transfer
        .encode_input(&[
            Token::Address(expected_address.to_string().parse().unwrap()),
            Token::Uint(expected_amount.to_be_bytes().into()),
        ])
        .expect("failed to encode transfer data")
}
