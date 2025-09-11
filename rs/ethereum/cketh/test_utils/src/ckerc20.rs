use crate::events::MinterEventAssert;
use crate::flow::{
    DepositCkEthParams, DepositParams, DepositTransactionData, LedgerTransactionAssert,
    ProcessWithdrawal, encode_principal,
};
use crate::mock::{
    JsonRpcMethod, JsonRpcRequestMatcher, MockJsonRpcProviders, MockJsonRpcProvidersBuilder,
};
use crate::response::{block_response, empty_logs, fee_history};
use crate::{
    CkEthSetup, DEFAULT_DEPOSIT_FROM_ADDRESS, DEFAULT_ERC20_DEPOSIT_LOG_INDEX,
    DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH, DEFAULT_PRINCIPAL_ID,
    DEPOSIT_WITH_SUBACCOUNT_HELPER_CONTRACT_ADDRESS, ERC20_HELPER_CONTRACT_ADDRESS,
    ETH_HELPER_CONTRACT_ADDRESS, LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL, LedgerBalance, MAX_TICKS,
    RECEIVED_ERC20_EVENT_TOPIC, RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC, assert_reply,
    format_ethereum_address_to_eip_55, new_state_machine,
};
use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use evm_rpc_types::Hex32;
use ic_base_types::{CanisterId, PrincipalId};
use ic_cketh_minter::SCRAPING_ETH_LOGS_INTERVAL;
use ic_cketh_minter::endpoints::ckerc20::{
    RetrieveErc20Request, WithdrawErc20Arg, WithdrawErc20Error,
};
use ic_cketh_minter::endpoints::events::{EventPayload, EventSource};
use ic_cketh_minter::endpoints::{CkErc20Token, MinterInfo};
use ic_cketh_minter::numeric::{BlockNumber, Erc20Value};
use ic_ethereum_types::Address;
pub use ic_ledger_suite_orchestrator::candid::AddErc20Arg as Erc20Token;
use ic_ledger_suite_orchestrator::candid::InitArg as LedgerSuiteOrchestratorInitArg;
use ic_ledger_suite_orchestrator_test_utils::{LedgerSuiteOrchestrator, supported_erc20_tokens};
use ic_state_machine_tests::{ErrorCode, StateMachine, WasmResult};
use ic_types::messages::MessageId;
use icrc_ledger_types::icrc1::account::Account;
use num_traits::ToPrimitive;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::identity;
use std::iter::{once, zip};
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
        let cketh = CkEthSetup::new(env.clone());
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

    pub fn add_support_for_subaccount(mut self) -> Self {
        self.cketh = self.cketh.add_support_for_subaccount();
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

    pub fn deposit<T: Into<DepositCkErc20>>(self, params: T) -> CkErc20DepositFlow {
        CkErc20DepositFlow::new(self, params)
    }

    pub fn deposit_cketh<T: Into<DepositParams>>(mut self, params: T) -> Self {
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
        CkErc20DepositFlow::new(
            self,
            DepositCkErc20Params {
                cketh_deposit: Some(DepositParams::from(DepositCkEthParams {
                    recipient,
                    amount: cketh_amount,
                    ..Default::default()
                })),
                recipient,
                ..DepositCkErc20Params::new(ckerc20_amount, token)
            },
        )
    }

    pub fn deposit_ckerc20(
        self,
        ckerc20_amount: u64,
        token: CkErc20Token,
        recipient: Principal,
    ) -> CkErc20DepositFlow {
        CkErc20DepositFlow::new(
            self,
            DepositCkErc20Params {
                recipient,
                ..DepositCkErc20Params::new(ckerc20_amount, token)
            },
        )
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
            from_cketh_subaccount: None,
            from_ckerc20_subaccount: None,
        };
        self.call_minter_withdraw_erc20_with(from, arg)
    }

    pub fn call_minter_withdraw_erc20_with(
        self,
        from: Principal,
        withdraw_erc20_arg: WithdrawErc20Arg,
    ) -> RefreshGasFeeEstimate {
        let message_id = self.env.send_ingress(
            PrincipalId::from(from),
            self.cketh.minter_id,
            "withdraw_erc20",
            Encode!(&withdraw_erc20_arg).expect("failed to encode withdraw args"),
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
            .map(|erc20_address| Hex32::from(<[u8; 32]>::from(erc20_address)).to_string())
            .collect()
    }

    pub fn received_erc20_event_topic(&self) -> serde_json::Value {
        self.as_ref()
            .json_topic(RECEIVED_ERC20_EVENT_TOPIC.to_string())
    }

    pub fn received_eth_or_erc20_with_subaccount_event_topic(&self) -> serde_json::Value {
        self.as_ref()
            .json_topic(RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositCkErc20 {
    CkErc20(DepositCkErc20Params),
    CkErc20WithSubaccount(DepositCkErc20WithSubaccountParams),
}

impl DepositCkErc20 {
    pub fn from_address(&self) -> &Address {
        match self {
            Self::CkErc20(params) => &params.from_address,
            Self::CkErc20WithSubaccount(params) => &params.from_address,
        }
    }

    pub fn recipient(&self) -> Account {
        match self {
            Self::CkErc20(params) => Account {
                owner: params.recipient,
                subaccount: None,
            },
            Self::CkErc20WithSubaccount(params) => Account {
                owner: params.recipient,
                subaccount: params.recipient_subaccount,
            },
        }
    }

    pub fn token(&self) -> &CkErc20Token {
        match self {
            Self::CkErc20(params) => &params.token,
            Self::CkErc20WithSubaccount(params) => &params.token,
        }
    }

    pub fn cketh_deposit(&self) -> Option<&DepositParams> {
        match self {
            Self::CkErc20(params) => params.cketh_deposit.as_ref(),
            Self::CkErc20WithSubaccount(params) => params.cketh_deposit.as_ref(),
        }
    }

    pub fn ckerc20_amount(&self) -> u64 {
        match self {
            Self::CkErc20(params) => params.ckerc20_amount,
            Self::CkErc20WithSubaccount(params) => params.ckerc20_amount,
        }
    }

    pub fn transaction_data(&self) -> &DepositTransactionData {
        match self {
            Self::CkErc20(params) => &params.transaction_data,
            Self::CkErc20WithSubaccount(params) => &params.transaction_data,
        }
    }

    pub fn to_log_entry(&self) -> ethers_core::types::Log {
        match self {
            Self::CkErc20(params) => params.to_log_entry(),
            Self::CkErc20WithSubaccount(params) => params.to_log_entry(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositCkErc20Params {
    pub cketh_deposit: Option<DepositParams>,
    pub from_address: Address,
    pub ckerc20_amount: u64,
    pub recipient: Principal,
    pub token: CkErc20Token,
    pub transaction_data: DepositTransactionData,
}

impl DepositCkErc20Params {
    pub fn new(ckerc20_amount: u64, token: CkErc20Token) -> Self {
        Self {
            cketh_deposit: None,
            from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
            recipient: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
            ckerc20_amount,
            token,
            transaction_data: erc20_default_deposit_transaction_data(),
        }
    }

    pub fn to_log_entry(&self) -> ethers_core::types::Log {
        let amount_hex = format!("0x{:0>64x}", self.ckerc20_amount);
        let topics = vec![
            RECEIVED_ERC20_EVENT_TOPIC.to_string(),
            format!(
                "0x000000000000000000000000{}",
                hex::encode(
                    self.token
                        .erc20_contract_address
                        .parse::<Address>()
                        .unwrap()
                ),
            ),
            format!(
                "0x000000000000000000000000{}",
                hex::encode(self.from_address.as_ref())
            ),
            encode_principal(self.recipient),
        ];

        let json_value = json!({
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": self.transaction_data.block_hash,
            "blockNumber": format!("0x{:x}", self.transaction_data.block_number),
            "data": amount_hex,
            "logIndex": format!("0x{:x}", self.transaction_data.log_index),
            "removed": false,
            "topics": topics,
            "transactionHash": self.transaction_data.transaction_hash,
            "transactionIndex": format!("0x{:x}", self.transaction_data.transaction_index),
        });
        serde_json::from_value(json_value).expect("BUG: invalid log entry")
    }
}

impl From<DepositCkErc20Params> for DepositCkErc20 {
    fn from(params: DepositCkErc20Params) -> Self {
        DepositCkErc20::CkErc20(params)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositCkErc20WithSubaccountParams {
    pub cketh_deposit: Option<DepositParams>,
    pub from_address: Address,
    pub ckerc20_amount: u64,
    pub recipient: Principal,
    pub recipient_subaccount: Option<[u8; 32]>,
    pub token: CkErc20Token,
    pub transaction_data: DepositTransactionData,
}

impl DepositCkErc20WithSubaccountParams {
    pub fn new(ckerc20_amount: u64, token: CkErc20Token, recipient: Account) -> Self {
        Self {
            cketh_deposit: None,
            from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
            recipient: recipient.owner,
            recipient_subaccount: recipient.subaccount,
            ckerc20_amount,
            token,
            transaction_data: erc20_default_deposit_transaction_data(),
        }
    }

    pub fn to_log_entry(&self) -> ethers_core::types::Log {
        let data = {
            let amount_hex = format!("{:0>64x}", self.ckerc20_amount);
            assert_eq!(amount_hex.len(), 64);
            let subaccount = hex::encode(self.recipient_subaccount.unwrap_or([0; 32]));
            assert_eq!(amount_hex.len(), 64);
            format!("0x{amount_hex}{subaccount}")
        };

        let topics = vec![
            RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC.to_string(),
            format!(
                "0x000000000000000000000000{}",
                hex::encode(
                    self.token
                        .erc20_contract_address
                        .parse::<Address>()
                        .unwrap()
                ),
            ),
            format!(
                "0x000000000000000000000000{}",
                ethers_core::utils::hex::encode(self.from_address.as_ref())
            ),
            encode_principal(self.recipient),
        ];

        let json_value = json!({
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": self.transaction_data.block_hash,
            "blockNumber": format!("0x{:x}", self.transaction_data.block_number),
            "data": data,
            "logIndex": format!("0x{:x}", self.transaction_data.log_index),
            "removed": false,
            "topics": topics,
            "transactionHash": self.transaction_data.transaction_hash,
            "transactionIndex": format!("0x{:x}", self.transaction_data.transaction_index),
        });
        serde_json::from_value(json_value).expect("BUG: invalid log entry")
    }
}

impl From<DepositCkErc20WithSubaccountParams> for DepositCkErc20 {
    fn from(params: DepositCkErc20WithSubaccountParams) -> Self {
        DepositCkErc20::CkErc20WithSubaccount(params)
    }
}

fn erc20_default_deposit_transaction_data() -> DepositTransactionData {
    DepositTransactionData {
        transaction_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.to_string(),
        log_index: DEFAULT_ERC20_DEPOSIT_LOG_INDEX,
        ..Default::default()
    }
}

pub struct CkErc20DepositFlow {
    pub setup: CkErc20Setup,
    params: DepositCkErc20,
    override_erc20_log_entry: Box<dyn Fn(ethers_core::types::Log) -> ethers_core::types::Log>,
}

impl AsRef<CkEthSetup> for CkErc20DepositFlow {
    fn as_ref(&self) -> &CkEthSetup {
        &self.setup.cketh
    }
}

impl CkErc20DepositFlow {
    pub fn new<T: Into<DepositCkErc20>>(setup: CkErc20Setup, params: T) -> Self {
        Self {
            setup,
            params: params.into(),
            override_erc20_log_entry: Box::new(identity),
        }
    }

    pub fn with_override_erc20_log_entry<
        F: Fn(ethers_core::types::Log) -> ethers_core::types::Log + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_erc20_log_entry = Box::new(override_mock);
        self
    }

    pub fn expect_mint(mut self) -> CkErc20Setup {
        let mut initial_balances = Vec::new();
        let mut expected_balances_diff = Vec::new();
        if let Some(cketh_deposit) = self.params.cketh_deposit() {
            let account = cketh_deposit.recipient();
            let ledger_id = self.setup.cketh_ledger_id();
            let balance = self.setup.balance_of_ledger(ledger_id, account);
            initial_balances.push(LedgerBalance {
                ledger_id,
                account,
                balance,
            });
            expected_balances_diff.push(LedgerBalance {
                ledger_id,
                account,
                balance: Nat::from(cketh_deposit.amount()),
            })
        }
        {
            let account = self.params.recipient();
            let ledger_id = self.params.token().ledger_canister_id;
            let balance = self.setup.balance_of_ledger(ledger_id, account);
            initial_balances.push(LedgerBalance {
                ledger_id,
                account,
                balance,
            });
            expected_balances_diff.push(LedgerBalance {
                ledger_id,
                account,
                balance: Nat::from(self.params.ckerc20_amount()),
            })
        }
        assert_eq!(initial_balances.len(), expected_balances_diff.len());
        let MinterInfo {
            erc20_balances: erc20_balances_before,
            ..
        } = self.setup.get_minter_info();

        self.handle_log_scraping();

        for (initial_balance, expected_balance_diff) in
            zip(initial_balances, expected_balances_diff)
        {
            let balance_after = self.setup.wait_for_updated_ledger_balance(
                initial_balance.ledger_id,
                initial_balance.account,
                &initial_balance.balance,
            );
            assert_eq!(
                balance_after - initial_balance.balance,
                expected_balance_diff.balance,
                "Unexpected balance difference for ledger {} and account {}",
                initial_balance.ledger_id,
                initial_balance.account
            );
        }

        let MinterInfo {
            erc20_balances: erc20_balances_after,
            ..
        } = self.setup.get_minter_info();

        let erc20_balances_before = erc20_balances_before.unwrap();
        let erc20_balances_after = erc20_balances_after.unwrap();
        assert_eq!(erc20_balances_before.len(), erc20_balances_after.len());
        let mut has_deposited_token = false;
        for (balance_before, balance_after) in zip(erc20_balances_before, erc20_balances_after) {
            if balance_before.erc20_contract_address == self.params.token().erc20_contract_address {
                assert_eq!(
                    balance_after.balance - balance_before.balance,
                    self.params.ckerc20_amount()
                );
                has_deposited_token = true;
            } else {
                assert_eq!(balance_after.balance, balance_before.balance);
            }
        }
        assert!(has_deposited_token);

        self.setup.cketh.check_audit_log();

        if let Some(deposit) = self.params.cketh_deposit() {
            let eth_tx_data = deposit.transaction_data();

            self.setup.cketh = self.setup.cketh.assert_has_unique_events_in_order(&vec![
                EventPayload::AcceptedDeposit {
                    transaction_hash: eth_tx_data.transaction_hash.to_string(),
                    block_number: Nat::from(eth_tx_data.block_number),
                    log_index: Nat::from(eth_tx_data.log_index),
                    from_address: deposit.from_address().to_string(),
                    value: Nat::from(deposit.amount()),
                    principal: deposit.recipient().owner,
                    subaccount: deposit.recipient().subaccount,
                },
                EventPayload::MintedCkEth {
                    event_source: EventSource {
                        transaction_hash: eth_tx_data.transaction_hash.clone(),
                        log_index: Nat::from(eth_tx_data.log_index),
                    },
                    mint_block_index: Nat::from(0_u8),
                },
            ]);
        }

        let erc20_tx_data = self.params.transaction_data();
        self.setup.cketh = self.setup.cketh.assert_has_unique_events_in_order(&vec![
            EventPayload::AcceptedErc20Deposit {
                transaction_hash: erc20_tx_data.transaction_hash.to_string(),
                block_number: Nat::from(erc20_tx_data.block_number),
                log_index: Nat::from(erc20_tx_data.log_index),
                from_address: format_ethereum_address_to_eip_55(
                    &self.params.from_address().to_string(),
                ),
                value: self.params.ckerc20_amount().into(),
                principal: self.params.recipient().owner,
                erc20_contract_address: self.params.token().erc20_contract_address.clone(),
                subaccount: self.params.recipient().subaccount,
            },
            EventPayload::MintedCkErc20 {
                event_source: EventSource {
                    transaction_hash: erc20_tx_data.transaction_hash.to_string(),
                    log_index: Nat::from(erc20_tx_data.log_index),
                },
                ckerc20_token_symbol: self.params.token().ckerc20_token_symbol.clone(),
                erc20_contract_address: self.params.token().erc20_contract_address.clone(),
                mint_block_index: Nat::from(0_u8),
            },
        ]);
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

        let eth_logs = match self.params.cketh_deposit() {
            Some(DepositParams::CkEth(deposit)) => vec![deposit.to_log_entry()],
            Some(DepositParams::CkEthWithSubaccount(_)) | None => empty_logs(),
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

        let erc20_logs = match &self.params {
            DepositCkErc20::CkErc20(params) => {
                vec![(self.override_erc20_log_entry)(params.to_log_entry())]
            }
            DepositCkErc20::CkErc20WithSubaccount(_) => empty_logs(),
        };
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": first_from_block,
                "toBlock": first_to_block,
                "address": [ERC20_HELPER_CONTRACT_ADDRESS],
                "topics": [self.setup.received_erc20_event_topic(), erc20_topics.clone()]
            }]))
            .respond_for_all_with(erc20_logs)
            .build()
            .expect_rpc_calls(self);

        if self.setup.as_ref().support_subaccount {
            let deposit_with_subaccount_logs = match (&self.params, self.params.cketh_deposit()) {
                (DepositCkErc20::CkErc20(_), Some(DepositParams::CkEth(_)) | None) => empty_logs(),
                (DepositCkErc20::CkErc20(_), Some(DepositParams::CkEthWithSubaccount(deposit))) => {
                    vec![deposit.to_log_entry()]
                }
                (
                    DepositCkErc20::CkErc20WithSubaccount(deposit),
                    Some(DepositParams::CkEth(_)) | None,
                ) => {
                    vec![deposit.to_log_entry()]
                }
                (
                    DepositCkErc20::CkErc20WithSubaccount(erc20_deposit),
                    Some(DepositParams::CkEthWithSubaccount(eth_deposit)),
                ) => {
                    vec![eth_deposit.to_log_entry(), erc20_deposit.to_log_entry()]
                }
            };

            let deposit_with_subaccount_2nd_topics: Vec<_> = once(
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            )
            .chain(erc20_topics)
            .collect();
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
                .with_request_params(json!([{
                "fromBlock": first_from_block,
                "toBlock": first_to_block,
                "address": [DEPOSIT_WITH_SUBACCOUNT_HELPER_CONTRACT_ADDRESS.to_lowercase()],
                "topics": [self.setup.received_eth_or_erc20_with_subaccount_event_topic(), deposit_with_subaccount_2nd_topics]
            }]))
                .respond_for_all_with(deposit_with_subaccount_logs)
                .build()
                .expect_rpc_calls(self);
        }
    }

    pub fn expect_no_mint(self) -> CkErc20Setup {
        let cketh_balance_before = self
            .setup
            .balance_of_ledger(self.setup.cketh_ledger_id(), self.params.recipient());
        let ckerc20_balance_before = self.setup.balance_of_ledger(
            self.params.token().ledger_canister_id,
            self.params.recipient(),
        );

        self.handle_log_scraping();

        let cketh_balance_after = self.setup.wait_for_updated_ledger_balance(
            self.setup.cketh_ledger_id(),
            self.params.recipient(),
            &cketh_balance_before,
        );
        let ckerc20_balance_after = self.setup.wait_for_updated_ledger_balance(
            self.params.token().ledger_canister_id,
            self.params.recipient(),
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
