use crate::events::MinterEventAssert;
use crate::flow::{
    ApprovalFlow, DepositFlow, DepositParams, LedgerTransactionAssert, WithdrawalFlow,
};
use crate::mock::JsonRpcMethod;
use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cketh_minter::endpoints::events::{Event, EventPayload, GetEventsResult};
use ic_cketh_minter::endpoints::{
    AddCkErc20Token, Eip1559TransactionPriceArg, MinterInfo, RetrieveEthStatus, WithdrawalArg,
    WithdrawalDetail, WithdrawalSearchParameter,
};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::logs::Log;
use ic_cketh_minter::{
    endpoints::{CandidBlockTag, Eip1559TransactionPrice},
    lifecycle::{EthereumNetwork, MinterArg, init::InitArg as MinterInitArgs},
};
use ic_ethereum_types::Address;
use ic_http_types::{HttpRequest, HttpResponse};
use ic_icrc1_ledger::{InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_management_canister_types_private::{CanisterHttpResponsePayload, CanisterStatusType};
use ic_state_machine_tests::{
    PayloadBuilder, StateMachine, StateMachineBuilder, UserError, WasmResult,
};
use ic_test_utilities_load_wasm::load_wasm;
use ic_types::Cycles;
use ic_types::ingress::IngressStatus;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use num_traits::cast::ToPrimitive;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

pub mod ckerc20;
pub mod events;
mod evm_rpc_provider;
pub mod flow;
pub mod mock;
pub mod response;

pub use evm_rpc_provider::JsonRpcProvider;

#[cfg(test)]
mod tests;

pub const CKETH_TRANSFER_FEE: u64 = 2_000_000_000_000;
pub const CKETH_MINIMUM_WITHDRAWAL_AMOUNT: u64 = 30_000_000_000_000_000;
pub const MAX_TICKS: usize = 10;
pub const DEFAULT_PRINCIPAL_ID: u64 = 10352385;
pub const DEFAULT_USER_SUBACCOUNT: [u8; 32] = [42; 32];
pub const DEFAULT_DEPOSIT_BLOCK_NUMBER: u64 = 0x9;
pub const DEFAULT_DEPOSIT_BLOCK_HASH: &str =
    "0x79cfe76d69337dae199e32c2b6b3d7c2668bfe71a05f303f95385e70031b9ef8";
pub const DEFAULT_DEPOSIT_FROM_ADDRESS: &str = "0x55654e7405fcb336386ea8f36954a211b2cda764";
pub const DEFAULT_DEPOSIT_TRANSACTION_HASH: &str =
    "0xcfa48c44dc89d18a898a42b4a5b02b6847a3c2019507d5571a481751c7a2f353";
pub const DEFAULT_DEPOSIT_TRANSACTION_INDEX: u64 = 0x33;
pub const DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH: &str =
    "0x2044da6b095d6be2308b868287b8b70d9e01b226c02546b7abcce31dabc34929";

pub const DEFAULT_DEPOSIT_LOG_INDEX: u64 = 0x24;
pub const DEFAULT_ERC20_DEPOSIT_LOG_INDEX: u64 = 0x42;
pub const DEFAULT_BLOCK_HASH: &str =
    "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4";
pub const LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL: u64 = 3_956_206;
pub const DEFAULT_BLOCK_NUMBER: u64 = 0x4132ec; //4_272_876
pub const EXPECTED_BALANCE: u64 = 100_000_000_000_000_000 + CKETH_TRANSFER_FEE - 10_u64;
pub const CKETH_WITHDRAWAL_AMOUNT: u64 = EXPECTED_BALANCE - CKETH_TRANSFER_FEE;
pub const EFFECTIVE_GAS_PRICE: u64 = 4_277_923_390;
pub const GAS_USED: u64 = 0x5208;

pub const DEFAULT_WITHDRAWAL_TRANSACTION_HASH: &str =
    "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5";
pub const DEFAULT_WITHDRAWAL_TRANSACTION: &str = "0x02f87301808459682f008507af2c9f6282520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cf1e9917a0e680c001a0b27af25a08e87836a778ac2858fdfcff1f6f3a0d43313782c81d05ca34b80271a078026b399a32d3d7abab625388a3c57f651c66a182eb7f8b1a58d9aef7547256";

pub const DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION: &str = "0x02f8b001808459682f008507af2c9f6282fde894a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb000000000000000000000000221e931fbfcb9bd54ddd26ce6f5e29e98add01c000000000000000000000000000000000000000000000000000000000001e8480c080a0bb694aec6175b489523a55d5fce39452368e97096d4afa2cdcc35cf2d805152fa00112b26a028af84dd397d23549844efdaf761d90cdcfdbe6c3608239648a85a3";
pub const DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH: &str =
    "0x2c0c328876b8d60580e00d8e5a82599e22099e78d9d9c25cc5e6164bc8f4db62";

pub const DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE: u64 = 2_145_241_036_770_000_u64;
pub const USDC_ERC20_CONTRACT_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
pub const MINTER_ADDRESS: &str = "0xfd644a761079369962386f8e4259217c2a10b8d0";
pub const DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS: &str =
    "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0";
pub const ETH_HELPER_CONTRACT_ADDRESS: &str = "0x907b6efc1a398fd88a8161b3ca02eec8eaf72ca1";
pub const ERC20_HELPER_CONTRACT_ADDRESS: &str = "0xe1788e4834c896f1932188645cc36c54d1b80ac1";
pub const DEPOSIT_WITH_SUBACCOUNT_HELPER_CONTRACT_ADDRESS: &str =
    "0x2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38";
const RECEIVED_ETH_EVENT_TOPIC: &str =
    "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435";
const RECEIVED_ERC20_EVENT_TOPIC: &str =
    "0x4d69d0bd4287b7f66c548f90154dc81bc98f65a1b362775df5ae171a2ccd262b";
const RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC: &str =
    "0x918adbebdb8f3b36fc337ab76df10b147b2def5c9dd62cb3456d9aeca40e0b07";
pub const HEADER_SIZE_LIMIT: u64 = 2 * 1024;

pub struct CkEthSetup {
    pub env: Arc<StateMachine>,
    pub caller: PrincipalId,
    pub ledger_id: CanisterId,
    pub minter_id: CanisterId,
    pub evm_rpc_id: CanisterId,
    pub support_subaccount: bool,
}

impl Default for CkEthSetup {
    fn default() -> Self {
        Self::new(Arc::new(new_state_machine()))
    }
}

impl AsRef<CkEthSetup> for CkEthSetup {
    fn as_ref(&self) -> &CkEthSetup {
        self
    }
}

impl CkEthSetup {
    pub fn new(env: Arc<StateMachine>) -> Self {
        // Create minter canister first to match canister ID and Ethereum address hardcoded in tests.
        let minter_id =
            env.create_canister_with_cycles(None, Cycles::new(100_000_000_000_000), None);
        let ledger_id = env.create_canister(None);
        let evm_rpc_id = env.create_canister(None);

        env.install_existing_canister(
            ledger_id,
            ledger_wasm(),
            Encode!(&LedgerArgument::Init(
                LedgerInitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
                    .with_minting_account(minter_id.get().0)
                    .with_transfer_fee(CKETH_TRANSFER_FEE)
                    .with_max_memo_length(80)
                    .with_decimals(18)
                    .with_feature_flags(ic_icrc1_ledger::FeatureFlags { icrc2: true })
                    .build(),
            ))
            .unwrap(),
        )
        .unwrap();
        let minter_id = install_minter(&env, ledger_id, minter_id, evm_rpc_id);
        install_evm_rpc(&env, evm_rpc_id);

        let caller = PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID);
        let cketh = Self {
            env,
            caller,
            ledger_id,
            minter_id,
            evm_rpc_id,
            support_subaccount: false,
        };

        assert_eq!(
            Address::from_str(MINTER_ADDRESS).unwrap(),
            Address::from_str(&cketh.minter_address()).unwrap()
        );

        cketh
    }

    pub fn add_support_for_subaccount(self) -> Self {
        self.upgrade_minter_to_add_deposit_with_subaccount_helper_contract(
            DEPOSIT_WITH_SUBACCOUNT_HELPER_CONTRACT_ADDRESS.to_string(),
        )
    }

    pub fn deposit<T: Into<DepositParams>>(self, params: T) -> DepositFlow {
        DepositFlow::new(self, params)
    }

    pub fn minter_address(&self) -> String {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "minter_address",
                        Encode!().unwrap(),
                    )
                    .expect("failed to get eth address")
            ),
            String
        )
        .unwrap()
    }

    pub fn retrieve_eth_status(&self, block_index: &Nat) -> RetrieveEthStatus {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "retrieve_eth_status",
                        Encode!(&block_index.0.to_u64().unwrap()).unwrap(),
                    )
                    .expect("failed to get eth address")
            ),
            RetrieveEthStatus
        )
        .unwrap()
    }

    pub fn withdrawal_status(
        &self,
        parameter: &WithdrawalSearchParameter,
    ) -> Vec<WithdrawalDetail> {
        Decode!(
            &assert_reply(
                self.env
                    .query_as(
                        self.caller,
                        self.minter_id,
                        "withdrawal_status",
                        Encode!(parameter).unwrap(),
                    )
                    .expect("failed to get eth address")
            ),
            Vec<WithdrawalDetail>
        )
        .unwrap()
    }

    pub fn balance_of(&self, account: impl Into<Account>) -> Nat {
        let ledger_id = self.ledger_id;
        self.balance_of_ledger(ledger_id, account)
    }

    pub fn balance_of_ledger(&self, ledger_id: CanisterId, account: impl Into<Account>) -> Nat {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        ledger_id,
                        "icrc1_balance_of",
                        Encode!(&account.into()).unwrap()
                    )
                    .expect("failed to query balance on the ledger")
            ),
            Nat
        )
        .unwrap()
    }

    pub fn eip_1559_transaction_price(
        &self,
        ledger_id: Option<Principal>,
    ) -> Result<WasmResult, ic_state_machine_tests::UserError> {
        let arg = match ledger_id {
            None => Encode!().unwrap(),
            Some(ckerc20_ledger_id) => {
                Encode!(&Some(Eip1559TransactionPriceArg { ckerc20_ledger_id })).unwrap()
            }
        };
        self.env
            .query(self.minter_id, "eip_1559_transaction_price", arg)
    }

    pub fn eip_1559_transaction_price_expecting_ok(
        &self,
        ledger_id: Option<Principal>,
    ) -> Eip1559TransactionPrice {
        Decode!(
            &assert_reply(self.eip_1559_transaction_price(ledger_id).unwrap()),
            Eip1559TransactionPrice
        )
        .unwrap()
    }

    pub fn eip_1559_transaction_price_expecting_err(&self, principal_id: Principal) {
        let error = self
            .eip_1559_transaction_price(Some(principal_id))
            .expect_err("Expecting Err but got Ok");
        assert!(error.description().contains(&format!(
            "ERROR: Unsupported ckERC20 token ledger {principal_id}"
        )));
    }

    pub fn add_ckerc20_token(
        &self,
        from: Principal,
        erc20: &AddCkErc20Token,
    ) -> Result<WasmResult, UserError> {
        self.env.execute_ingress_as(
            PrincipalId::from(from),
            self.minter_id,
            "add_ckerc20_token",
            Encode!(erc20).unwrap(),
        )
    }

    pub fn add_ckerc20_token_expecting_ok(self, from: Principal, erc20: &AddCkErc20Token) -> Self {
        Decode!(
            &assert_reply(self.add_ckerc20_token(from, erc20).unwrap()),
            ()
        )
        .unwrap();
        self
    }

    pub fn get_minter_info(&self) -> MinterInfo {
        Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "get_minter_info", Encode!().unwrap())
                    .unwrap()
            ),
            MinterInfo
        )
        .unwrap()
    }

    pub fn call_ledger_approve_minter(
        self,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> ApprovalFlow {
        let cketh_ledger_id = self.ledger_id;
        self.call_ledger_id_approve_minter(cketh_ledger_id, from, amount, from_subaccount)
    }

    pub fn call_ledger_id_approve_minter(
        self,
        ledger_id: CanisterId,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> ApprovalFlow {
        let approval_response = Decode!(&assert_reply(self.env.execute_ingress_as(
            PrincipalId::from(from),
            ledger_id,
            "icrc2_approve",
            Encode!(&ApproveArgs {
                from_subaccount,
                spender: Account {
                    owner: self.minter_id.into(),
                    subaccount: None
                },
                amount: Nat::from(amount),
                expected_allowance: None,
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()
            ).expect("failed to execute token transfer")),
            Result<Nat, ApproveError>
        )
        .unwrap();
        ApprovalFlow {
            setup: self,
            approval_response,
        }
    }

    pub fn call_ledger_get_transaction<T: Into<Nat>>(
        self,
        ledger_index: T,
    ) -> LedgerTransactionAssert<Self> {
        let ledger_id = self.ledger_id;
        self.call_ledger_id_get_transaction(ledger_id, ledger_index)
    }

    pub fn call_ledger_id_get_transaction<T: Into<Nat>>(
        self,
        ledger_id: CanisterId,
        ledger_index: T,
    ) -> LedgerTransactionAssert<Self> {
        let ledger_transaction =
            crate::flow::call_ledger_id_get_transaction(&self.env, ledger_id, ledger_index);
        LedgerTransactionAssert {
            setup: self,
            ledger_transaction,
        }
    }

    pub fn call_minter_withdraw_eth<T: Into<Account>>(
        self,
        from: T,
        amount: Nat,
        recipient: String,
    ) -> WithdrawalFlow {
        let from = from.into();
        let arg = WithdrawalArg {
            amount,
            recipient,
            from_subaccount: from.subaccount,
        };
        let message_id = self.env.send_ingress(
            PrincipalId::from(from.owner),
            self.minter_id,
            "withdraw_eth",
            Encode!(&arg).expect("failed to encode withdraw args"),
        );
        WithdrawalFlow {
            setup: self,
            message_id,
        }
    }

    pub fn _get_logs(&self, priority: &str) -> Log {
        let request = HttpRequest {
            method: "".to_string(),
            url: format!("/logs?priority={priority}"),
            headers: vec![],
            body: serde_bytes::ByteBuf::new(),
        };
        let response = Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "http_request", Encode!(&request).unwrap(),)
                    .expect("failed to get minter info")
            ),
            HttpResponse
        )
        .unwrap();
        serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log")
    }

    pub fn check_events(self) -> MinterEventAssert<Self> {
        MinterEventAssert::from_fetching_all_events(self)
    }

    pub fn assert_has_unique_events_in_order(self, expected_events: &[EventPayload]) -> Self {
        MinterEventAssert::from_fetching_all_events(self)
            .assert_has_unique_events_in_order(expected_events)
    }

    pub fn assert_has_no_event_satisfying<P: Fn(&EventPayload) -> bool>(
        self,
        predicate: P,
    ) -> Self {
        MinterEventAssert::from_fetching_all_events(self).assert_has_no_event_satisfying(predicate)
    }

    fn get_events(&self, start: u64, length: u64) -> GetEventsResult {
        use ic_cketh_minter::endpoints::events::GetEventsArg;

        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(
                        self.minter_id,
                        "get_events",
                        Encode!(&GetEventsArg { start, length }).unwrap(),
                    )
                    .expect("failed to get minter info")
            ),
            GetEventsResult
        )
        .unwrap()
    }

    pub fn get_all_events(&self) -> Vec<Event> {
        const FIRST_BATCH_SIZE: u64 = 100;
        let GetEventsResult {
            mut events,
            total_event_count,
        } = self.get_events(0, FIRST_BATCH_SIZE);
        while events.len() < total_event_count as usize {
            let mut next_batch =
                self.get_events(events.len() as u64, total_event_count - events.len() as u64);
            events.append(&mut next_batch.events);
        }
        events
    }

    fn check_audit_log(&self) {
        Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "check_audit_log", Encode!().unwrap())
                    .unwrap(),
            ),
            ()
        )
        .unwrap()
    }

    fn upgrade_minter(&self, upgrade_arg: UpgradeArg) {
        self.stop_minter();
        self.env
            .upgrade_canister(
                self.minter_id,
                minter_wasm(),
                Encode!(&MinterArg::UpgradeArg(upgrade_arg)).unwrap(),
            )
            .unwrap();
        self.start_minter();
    }

    pub fn try_stop_minter_without_stopping_ongoing_https_outcalls(&self) -> IngressStatus {
        const MAX_TICKS: u64 = 100;
        let stop_msg_id = self.env.stop_canister_non_blocking(self.minter_id);
        for _ in 0..MAX_TICKS {
            self.env.tick();
        }
        self.env.ingress_status(&stop_msg_id)
    }

    pub fn stop_minter(&self) {
        let stop_msg_id = self.env.stop_canister_non_blocking(self.minter_id);
        self.stop_ongoing_https_outcalls();
        let stop_res = self.env.await_ingress(stop_msg_id, 100);
        assert_matches!(stop_res, Ok(WasmResult::Reply(_)));
    }

    pub fn stop_ongoing_https_outcalls(&self) {
        let server_error_response = CanisterHttpResponsePayload {
            status: 500_u128,
            headers: vec![],
            body: vec![],
        };
        let ongoing_https_outcalls: Vec<_> = self
            .env
            .canister_http_request_contexts()
            .into_keys()
            .collect();
        let mut payload = PayloadBuilder::new();
        for callback_id in ongoing_https_outcalls {
            payload = payload.http_response(callback_id, &server_error_response);
        }
        self.env.execute_payload(payload);
    }

    pub fn start_minter(&self) {
        let start_res = self.env.start_canister(self.minter_id);
        assert_matches!(start_res, Ok(WasmResult::Reply(_)));
    }

    pub fn minter_status(&self) -> CanisterStatusType {
        self.env
            .canister_status(self.minter_id)
            .unwrap()
            .unwrap()
            .status()
    }

    pub fn upgrade_minter_to_add_orchestrator_id(self, orchestrator_id: Principal) -> Self {
        self.upgrade_minter(UpgradeArg {
            ledger_suite_orchestrator_id: Some(orchestrator_id),
            ..Default::default()
        });
        self
    }

    pub fn upgrade_minter_to_add_erc20_helper_contract(self, contract_address: String) -> Self {
        self.upgrade_minter(UpgradeArg {
            erc20_helper_contract_address: Some(contract_address),
            ..Default::default()
        });
        self
    }

    pub fn upgrade_minter_to_add_deposit_with_subaccount_helper_contract(
        mut self,
        contract_address: String,
    ) -> Self {
        self.upgrade_minter(UpgradeArg {
            deposit_with_subaccount_helper_contract_address: Some(contract_address),
            ..Default::default()
        });
        self.support_subaccount = true;
        self
    }

    pub fn check_audit_logs_and_upgrade(self, upgrade_arg: UpgradeArg) -> Self {
        self.check_audit_logs_and_upgrade_as_ref(upgrade_arg);
        self
    }

    pub fn check_audit_logs_and_upgrade_as_ref(&self, upgrade_arg: UpgradeArg) {
        self.check_audit_log();
        self.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
        self.upgrade_minter(upgrade_arg);
    }

    pub fn assert_has_no_rpc_call(self, method: &JsonRpcMethod) -> Self {
        for _ in 0..MAX_TICKS {
            if let Some(unexpected_request) = self
                .env
                .canister_http_request_contexts()
                .values()
                .map(|context| {
                    crate::mock::JsonRpcRequest::from_str(
                        std::str::from_utf8(&context.body.clone().unwrap()).unwrap(),
                    )
                    .expect("BUG: invalid JSON RPC method")
                })
                .find(|rpc_request| rpc_request.method.to_string() == method.to_string())
            {
                panic!("Unexpected RPC call: {unexpected_request:?}");
            }
            self.env.tick();
            self.env.advance_time(Duration::from_nanos(1));
        }
        self
    }

    pub fn max_logs_block_range(&self) -> u64 {
        499
    }

    pub fn received_eth_event_topic(&self) -> serde_json::Value {
        self.json_topic(RECEIVED_ETH_EVENT_TOPIC.to_string())
    }

    fn json_topic(&self, topic: String) -> serde_json::Value {
        // The EVM-RPC canister models topics as `opt vec vec text`, see
        // https://github.com/internet-computer-protocol/evm-rpc-canister/blob/3cce151d4c1338d83e6741afa354ccf11dff41e8/candid/evm_rpc.did#L69.
        // This means that a simple topic such as `["0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435"]`
        // must actually be represented as `[["0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435"]].
        // The JSON-RPC providers seem to be able to handle both formats.
        serde_json::Value::Array(vec![serde_json::Value::String(topic)])
    }

    fn eth_get_logs_response_size_initial_estimate(&self) -> u64 {
        const ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE: u64 = 100;
        ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE + HEADER_SIZE_LIMIT
    }

    pub fn all_eth_get_logs_response_size_estimates(&self) -> Vec<u64> {
        let initial_estimate = self.eth_get_logs_response_size_initial_estimate();
        vec![
            initial_estimate,
            initial_estimate << 1,
            initial_estimate << 2,
            initial_estimate << 3,
            initial_estimate << 4,
            initial_estimate << 5,
            initial_estimate << 6,
            initial_estimate << 7,
            initial_estimate << 8,
            initial_estimate << 9,
            2_000_000,
        ]
    }
}

pub fn format_ethereum_address_to_eip_55(address: &str) -> String {
    Address::from_str(address).unwrap().to_string()
}

fn new_state_machine() -> StateMachine {
    StateMachineBuilder::new()
        .with_master_ecdsa_public_key()
        .with_default_canister_range()
        .build()
}

fn ledger_wasm() -> Vec<u8> {
    let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rosetta-api")
        .join("icrc1")
        .join("ledger");
    load_wasm(path, "ledger_canister", &[])
}

fn minter_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "cketh_minter",
        &[],
    )
}

fn evm_rpc_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "evm_rpc_canister",
        &[],
    )
}

fn install_minter(
    env: &StateMachine,
    ledger_id: CanisterId,
    minter_id: CanisterId,
    evm_rpc_id: CanisterId,
) -> CanisterId {
    let args = MinterInitArgs {
        ecdsa_key_name: "master_ecdsa_public_key".parse().unwrap(),
        ethereum_network: EthereumNetwork::Mainnet,
        ledger_id: ledger_id.get().0,
        next_transaction_nonce: 0_u8.into(),
        ethereum_block_height: CandidBlockTag::Finalized,
        ethereum_contract_address: Some(ETH_HELPER_CONTRACT_ADDRESS.to_string()),
        minimum_withdrawal_amount: CKETH_MINIMUM_WITHDRAWAL_AMOUNT.into(),
        last_scraped_block_number: LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into(),
        evm_rpc_id: Some(evm_rpc_id.into()),
    };
    let minter_arg = MinterArg::InitArg(args);
    env.install_existing_canister(minter_id, minter_wasm(), Encode!(&minter_arg).unwrap())
        .unwrap();
    minter_id
}

fn install_evm_rpc(env: &StateMachine, evm_rpc_id: CanisterId) {
    let args = evm_rpc_types::InstallArgs::default();
    env.install_existing_canister(evm_rpc_id, evm_rpc_wasm(), Encode!(&args).unwrap())
        .unwrap();
}

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("Expected a successful reply, got a reject: {reject}")
        }
    }
}

pub struct LedgerBalance {
    pub ledger_id: Principal,
    pub account: Account,
    pub balance: Nat,
}
