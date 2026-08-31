use crate::anvil::{Anvil, SweepContracts};
use crate::events::MinterEventAssert;
use crate::flow::{
    ApprovalFlow, DepositFlow, DepositParams, LedgerTransactionAssert, WithdrawalFlow,
};
use crate::mock::JsonRpcMethod;
use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use evm_rpc_types::{InstallArgs, OverrideProvider, RegexSubstitution};
use ic_base_types::PrincipalId;
use ic_cketh_minter::endpoints::events::{Event, EventPayload, GetEventsResult};
use ic_cketh_minter::endpoints::{
    AddCkErc20Token, DecodeLedgerMemoArgs, DecodeLedgerMemoResult, Eip1559TransactionPriceArg,
    MemoType, MinterInfo, RetrieveEthStatus, WithdrawalArg, WithdrawalDetail,
    WithdrawalSearchParameter,
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
use ic_management_canister_types::{CanisterId, CanisterIdRecord, CanisterStatusType};
use ic_metrics_assert::{MetricsAssert, PocketIcHttpQuery};
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use num_traits::cast::ToPrimitive;
use pocket_ic::common::rest::{
    CanisterHttpReject, CanisterHttpReply, CanisterHttpRequest, CanisterHttpResponse, IcpConfig,
    IcpConfigFlag, MockCanisterHttpResponse, RawEffectivePrincipal, RawMessageId,
};
use pocket_ic::{PocketIc, PocketIcBuilder, RejectResponse};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

pub mod anvil;
pub mod ckerc20;
pub mod events;
mod evm_rpc_provider;
pub mod flow;
pub mod live;
pub mod mock;
pub mod response;

pub use evm_rpc_provider::JsonRpcProvider;

#[cfg(test)]
mod tests;

pub const CKETH_TRANSFER_FEE: u64 = 2_000_000_000_000;
pub const CKETH_MINIMUM_WITHDRAWAL_AMOUNT: u64 = 30_000_000_000_000_000;
pub const MAX_TICKS: usize = 10;

// `ic_error_types::RejectCode` value relevant to canister-http mocking.
pub(crate) const REJECT_CODE_SYS_FATAL: u64 = 1;
pub(crate) const REJECT_CODE_SYS_TRANSIENT: u64 = 2;
// ic_types::canister_http::CANISTER_HTTP_TIMEOUT_INTERVAL, past which PocketIC fails
// canister http requests still in flight.
const CANISTER_HTTP_TIMEOUT_INTERVAL: Duration = Duration::from_secs(60);
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
    "0xa31221e733b030eb72eeb6973593a4d920c2c3391433429eed3c16b8f4f3ba7a";
pub const DEFAULT_WITHDRAWAL_TRANSACTION: &str = "0x02f87301808459682f008507af2c9f6282520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cf1e9917a0e680c001a0ad488ebb7c3cdf69ac424ab1e64e52c01fc4f93ac877946f707b0f29199f8a13a01996863aed39f3fca6350d907622c24864f9a04c21d16d4b27d37d8a3531653b";

pub const DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION: &str = "0x02f8b001808459682f008507af2c9f6282fde894a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb000000000000000000000000221e931fbfcb9bd54ddd26ce6f5e29e98add01c000000000000000000000000000000000000000000000000000000000001e8480c080a0da4f476ede0aaf7da633371a938d5e2525a65a23699b55761779871a313f8cb3a045833d409eba50e3e9b145d04ea294ee791c14465503818f8b325a881938ddc1";
pub const DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH: &str =
    "0x31d6e7ad4b7c167ca17777fd4aafd11a02c9fd8d3bc660f7ea4d7a2e2bf4a985";

pub const DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE: u64 = 2_145_241_036_770_000_u64;
pub const USDC_ERC20_CONTRACT_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
pub const USDC_ERC20_CONTRACT_ADDRESS_LOWERCASE: &str =
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
pub const MINTER_ADDRESS: &str = "0x30a14171b7c4c93ff5213f82eeb74f7c7e3f1ebc";
/// The minter's dedicated sweeper address, derived from the same test key as [`MINTER_ADDRESS`]
/// under the sweeper derivation path. Hardcoded as the value that derivation is expected to
/// produce, so a test can name it before the minter is installed; `MinterInfo::sweeper_address`
/// reports what the running minter actually derived. A test that funds it asserts the sweep really
/// was sent from here, so a stale value fails loudly.
pub const SWEEPER_ADDRESS: &str = "0x07e326c6604e3801270fc52ffb7ad3d6c5dfe89c";
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
    pub env: Arc<PocketIc>,
    pub caller: PrincipalId,
    pub ledger_id: Principal,
    pub minter_id: Principal,
    pub evm_rpc_id: Principal,
    pub support_subaccount: bool,
}

impl Default for CkEthSetup {
    fn default() -> Self {
        Self::new(EthereumBackend::Mocked)
    }
}

impl AsRef<CkEthSetup> for CkEthSetup {
    fn as_ref(&self) -> &CkEthSetup {
        self
    }
}

impl PocketIcHttpQuery for &CkEthSetup {
    fn get_pocket_ic(&self) -> &PocketIc {
        &self.env
    }

    fn get_canister_id(&self) -> CanisterId {
        self.minter_id
    }
}

impl CkEthSetup {
    /// Builds a fresh PocketIC instance (fiduciary subnet only, non-live) and installs the minter,
    /// its ckETH ledger and the EVM RPC canister on it — each under the anonymous controller —
    /// against `backend`. [`Default`] uses [`EthereumBackend::Mocked`]; [`crate::live`] passes
    /// [`EthereumBackend::Anvil`] for the live balance-scan harness.
    fn new(backend: EthereumBackend) -> Self {
        let env = Arc::new(new_env());
        let canisters = create_cketh_canisters(&env);
        install_ledger(&env, &canisters);
        install_evm_rpc(&env, &canisters, &backend);
        install_minter(&env, &canisters, &backend);

        Self {
            env,
            caller: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID),
            ledger_id: canisters.ledger_id,
            minter_id: canisters.minter_id,
            evm_rpc_id: canisters.evm_rpc_id,
            support_subaccount: false,
        }
    }

    pub fn add_support_for_subaccount(self) -> Self {
        self.add_support_for_subaccount_helper(
            Address::from_str(DEPOSIT_WITH_SUBACCOUNT_HELPER_CONTRACT_ADDRESS).unwrap(),
        )
    }

    /// Points the minter at a specific deposit helper, for a harness that deploys its own rather
    /// than mocking the mainnet one.
    pub fn add_support_for_subaccount_helper(self, helper: Address) -> Self {
        self.upgrade_minter_to_add_deposit_with_subaccount_helper_contract(helper.to_string())
    }

    pub fn deposit<T: Into<DepositParams>>(self, params: T) -> DepositFlow {
        DepositFlow::new(self, params)
    }

    pub fn minter_address(&self) -> String {
        Decode!(
            &assert_reply(self.env.update_call(
                self.minter_id,
                self.caller.into(),
                "minter_address",
                Encode!().unwrap(),
            )),
            String
        )
        .unwrap()
    }

    pub fn retrieve_eth_status(&self, block_index: &Nat) -> RetrieveEthStatus {
        Decode!(
            &assert_reply(self.env.update_call(
                self.minter_id,
                self.caller.into(),
                "retrieve_eth_status",
                Encode!(&block_index.0.to_u64().unwrap()).unwrap(),
            )),
            RetrieveEthStatus
        )
        .unwrap()
    }

    pub fn withdrawal_status(
        &self,
        parameter: &WithdrawalSearchParameter,
    ) -> Vec<WithdrawalDetail> {
        Decode!(
            &assert_reply(self.env.query_call(
                self.minter_id,
                self.caller.into(),
                "withdrawal_status",
                Encode!(parameter).unwrap(),
            )),
            Vec<WithdrawalDetail>
        )
        .unwrap()
    }

    pub fn balance_of(&self, account: impl Into<Account>) -> Nat {
        let ledger_id = self.ledger_id;
        self.balance_of_ledger(ledger_id, account)
    }

    pub fn balance_of_ledger(&self, ledger_id: Principal, account: impl Into<Account>) -> Nat {
        Decode!(
            &assert_reply(self.env.query_call(
                ledger_id,
                Principal::anonymous(),
                "icrc1_balance_of",
                Encode!(&account.into()).unwrap()
            )),
            Nat
        )
        .unwrap()
    }

    pub fn eip_1559_transaction_price(
        &self,
        ledger_id: Option<Principal>,
    ) -> Result<Vec<u8>, RejectResponse> {
        let arg = match ledger_id {
            None => Encode!().unwrap(),
            Some(ckerc20_ledger_id) => {
                Encode!(&Some(Eip1559TransactionPriceArg { ckerc20_ledger_id })).unwrap()
            }
        };
        self.env.query_call(
            self.minter_id,
            Principal::anonymous(),
            "eip_1559_transaction_price",
            arg,
        )
    }

    pub fn eip_1559_transaction_price_expecting_ok(
        &self,
        ledger_id: Option<Principal>,
    ) -> Eip1559TransactionPrice {
        Decode!(
            &assert_reply(self.eip_1559_transaction_price(ledger_id)),
            Eip1559TransactionPrice
        )
        .unwrap()
    }

    pub fn eip_1559_transaction_price_expecting_err(&self, principal_id: Principal) {
        let error = self
            .eip_1559_transaction_price(Some(principal_id))
            .expect_err("Expecting Err but got Ok");
        assert!(error.reject_message.contains(&format!(
            "ERROR: Unsupported ckERC20 token ledger {principal_id}"
        )));
    }

    pub fn add_ckerc20_token(
        &self,
        from: Principal,
        erc20: &AddCkErc20Token,
    ) -> Result<Vec<u8>, RejectResponse> {
        self.env.update_call(
            self.minter_id,
            from,
            "add_ckerc20_token",
            Encode!(erc20).unwrap(),
        )
    }

    pub fn add_ckerc20_token_expecting_ok(self, from: Principal, erc20: &AddCkErc20Token) -> Self {
        Decode!(&assert_reply(self.add_ckerc20_token(from, erc20)), ()).unwrap();
        self
    }

    pub fn get_minter_info(&self) -> MinterInfo {
        Decode!(
            &assert_reply(self.env.query_call(
                self.minter_id,
                Principal::anonymous(),
                "get_minter_info",
                Encode!().unwrap()
            )),
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
        ledger_id: Principal,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> ApprovalFlow {
        let approval_response = Decode!(&assert_reply(self.env.update_call(
            ledger_id,
            from,
            "icrc2_approve",
            Encode!(&ApproveArgs {
                from_subaccount,
                spender: Account {
                    owner: self.minter_id,
                    subaccount: None
                },
                amount: Nat::from(amount),
                expected_allowance: None,
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()
            )),
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
        ledger_id: Principal,
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
        let message_id = self
            .env
            .submit_call(
                self.minter_id,
                from.owner,
                "withdraw_eth",
                Encode!(&arg).expect("failed to encode withdraw args"),
            )
            .expect("failed to submit withdraw_eth call");
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
            &assert_reply(self.env.query_call(
                self.minter_id,
                Principal::anonymous(),
                "http_request",
                Encode!(&request).unwrap(),
            )),
            HttpResponse
        )
        .unwrap();
        serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log")
    }

    pub fn check_events(self) -> MinterEventAssert<Self> {
        MinterEventAssert::from_fetching_all_events(self)
    }

    pub fn check_minter_metrics(&self) -> MetricsAssert<&Self> {
        MetricsAssert::from_http_query(self)
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
            &assert_reply(self.env.update_call(
                self.minter_id,
                Principal::anonymous(),
                "get_events",
                Encode!(&GetEventsArg { start, length }).unwrap(),
            )),
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
            &assert_reply(self.env.query_call(
                self.minter_id,
                Principal::anonymous(),
                "check_audit_log",
                Encode!().unwrap()
            )),
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
                None,
            )
            .unwrap();
        self.start_minter();
    }

    pub fn submit_stop_minter(&self) -> RawMessageId {
        self.env
            .submit_call_with_effective_principal(
                Principal::management_canister(),
                RawEffectivePrincipal::CanisterId(self.minter_id.as_slice().to_vec()),
                Principal::anonymous(),
                "stop_canister",
                Encode!(&CanisterIdRecord {
                    canister_id: self.minter_id
                })
                .unwrap(),
            )
            .expect("failed to submit stop_canister call")
    }

    /// Try to stop the minter without first stopping the ongoing HTTPS outcalls. Assert that the
    /// call is still processing (i.e. blocked on the open call contexts for those outcalls).
    pub fn try_stop_minter_without_stopping_ongoing_https_outcalls(&self) {
        let stop_msg_id = self.submit_stop_minter();
        // The stop request only takes effect in the next round, and the outcalls the
        // minter's timers issue in that last running round become visible only after
        // it, so a drain placed before this tick would run too early and leave them
        // pending forever.
        self.env.tick();
        assert!(
            self.env.ingress_status(stop_msg_id).is_none(),
            "expected the minter's stop_canister call to still be processing after one tick"
        );
    }

    pub fn tick_until_minter_canister_status(&self, expected_canister_status: CanisterStatusType) {
        const MAX_TICKS: u64 = 10;
        let mut status = self.minter_status();
        for _ in 0..MAX_TICKS {
            if status == expected_canister_status {
                break;
            }
            self.env.tick();
            status = self.minter_status();
        }
        assert_eq!(status, expected_canister_status);
    }

    pub fn stop_minter(&self) {
        let stop_msg_id = self.submit_stop_minter();
        self.env.tick();
        self.stop_ongoing_https_outcalls();
        let stop_res = self.env.await_call(stop_msg_id);
        assert_matches!(stop_res, Ok(_));
    }

    pub fn stop_ongoing_https_outcalls(&self) {
        for request in self.env.get_canister_http() {
            reply_500(&self.env, &request);
        }
        self.env.tick();
    }

    pub fn start_minter(&self) {
        let start_res = self.env.start_canister(self.minter_id, None);
        assert_matches!(start_res, Ok(()));
    }

    /// Advancing past the canister http timeout fails every outcall in flight, but the
    /// requests stay listed until a round processes the failures, and the cycle awaiting
    /// them keeps holding its TimerGuard until it learns of them. A stub could then bind
    /// to a request that is already dead, and the firing due at the new time would be
    /// dropped as AlreadyProcessing. Do to those outcalls up front, and deterministically,
    /// what the advance would have done to them anyway.
    pub fn advance_time(&self, duration: Duration) {
        if duration > CANISTER_HTTP_TIMEOUT_INTERVAL {
            self.fail_pending_https_outcalls();
        }
        self.env.advance_time(duration);
    }

    fn fail_pending_https_outcalls(&self) {
        let pending = self.env.get_canister_http();
        // Ticking with nothing in flight would let the timers of a fixture that has
        // executed no round fire early, which the flows rely on doing themselves.
        if pending.is_empty() {
            return;
        }
        for request in &pending {
            fail_as_timed_out(&self.env, request);
        }
        self.env.tick();
    }

    pub fn minter_status(&self) -> CanisterStatusType {
        self.env
            .canister_status(self.minter_id, None)
            .unwrap()
            .status
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
                .get_canister_http()
                .into_iter()
                .map(|request| {
                    crate::mock::JsonRpcRequest::from_str(
                        std::str::from_utf8(&request.body).unwrap(),
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

    pub fn decode_ledger_memo(
        &self,
        memo_type: MemoType,
        encoded_memo: Vec<u8>,
    ) -> DecodeLedgerMemoResult {
        Decode!(
            &assert_reply(
                self.env.query_call(
                    self.minter_id,
                    Principal::anonymous(),
                    "decode_ledger_memo",
                    Encode!(&DecodeLedgerMemoArgs {
                        memo_type,
                        encoded_memo
                    })
                    .unwrap()
                )
            ),
            DecodeLedgerMemoResult
        )
        .unwrap()
    }

    pub fn minter_canister_logs(&self) -> Vec<CanisterLog> {
        let mut records = self
            .env
            .fetch_canister_logs(self.minter_id, Principal::anonymous())
            .expect("failed to fetch canister logs");

        records.sort_by_key(|record| record.idx);
        records
            .into_iter()
            .map(|log| CanisterLog {
                timestamp_nanos: log.timestamp_nanos,
                idx: log.idx,
                content: String::from_utf8_lossy(&log.content).to_string(),
            })
            .collect()
    }
}

/// Switches a fixture built against [`EthereumBackend::Anvil`] to live outcalls, so that from here
/// on the EVM RPC canister's requests reach anvil for real. Both steps are load-bearing and both
/// have bitten this crate; [`crate::live`]'s module documentation explains them at length.
///
/// In short: the in-flight outcalls from construction are answered while their request time is still
/// current, because the clock jump below would otherwise time them all out and leave the minter's
/// timer guards held; and the jump itself is applied synchronously, so an ingress message submitted
/// once this returns cannot be stamped behind `auto_progress`'s own asynchronous time-set and then
/// be retroactively expired.
pub(crate) fn switch_to_live(cketh: &CkEthSetup) {
    cketh.stop_ongoing_https_outcalls();
    cketh.env.set_certified_time(SystemTime::now().into());
    cketh.env.auto_progress();
}

/// Builds the PocketIC instance for [`CkEthSetup::new`]: the fiduciary subnet every ckETH fixture
/// needs for the secp256k1 `key_1` used by the minter. Always a non-live (manual-round) instance,
/// even for [`EthereumBackend::Anvil`]: [`crate::live`] builds its whole fixture here first and
/// only switches to live outcalls once construction is complete, so `await_call` ticks
/// deterministically for every setup call in between.
fn new_env() -> PocketIc {
    PocketIcBuilder::new()
        .with_fiduciary_subnet()
        .with_icp_config(IcpConfig {
            canister_execution_rate_limiting: Some(IcpConfigFlag::Disabled),
            ..Default::default()
        })
        .build()
}

pub fn format_ethereum_address_to_eip_55(address: &str) -> String {
    Address::from_str(address).unwrap().to_string()
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

/// The minter, its ckETH ledger and the EVM RPC canister it calls out to. Built by
/// [`create_cketh_canisters`] and installed by
/// [`install_ledger`]/[`install_minter`]/[`install_evm_rpc`] in the same order for every backend;
/// only the init args differ.
struct CkEthCanisters {
    minter_id: Principal,
    ledger_id: Principal,
    evm_rpc_id: Principal,
}

/// Cycles every canister this fixture creates is funded with — mocked and live fixtures alike,
/// deliberately the same amount rather than a second constant scoped to the live backend.
/// `u128::MAX`, the natural "as much as possible" choice, reproducibly crashes the live harness'
/// PocketIC replica with a cycle-accounting assertion failure (`Invalid cycle change`) on the
/// minter's first HTTPS outcall, because a canister already at the saturating `Cycles` balance
/// ceiling cannot observe any further addition; this amount leaves headroom below that ceiling.
const CANISTER_CYCLES: u128 = u64::MAX as u128;

fn create_cketh_canisters(env: &PocketIc) -> CkEthCanisters {
    // Create minter canister first to match canister ID and Ethereum address hardcoded in tests.
    let minter_id = env.create_canister();
    env.add_cycles(minter_id, CANISTER_CYCLES);
    let ledger_id = env.create_canister();
    env.add_cycles(ledger_id, CANISTER_CYCLES);
    let evm_rpc_id = env.create_canister();
    env.add_cycles(evm_rpc_id, CANISTER_CYCLES);
    CkEthCanisters {
        minter_id,
        ledger_id,
        evm_rpc_id,
    }
}

fn install_ledger(env: &PocketIc, canisters: &CkEthCanisters) {
    env.install_canister(
        canisters.ledger_id,
        ledger_wasm(),
        Encode!(&LedgerArgument::Init(
            LedgerInitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
                .with_minting_account(canisters.minter_id)
                .with_transfer_fee(CKETH_TRANSFER_FEE)
                .with_max_memo_length(80)
                .with_decimals(18)
                .with_feature_flags(ic_icrc1_ledger::FeatureFlags {
                    icrc2: true,
                    icrc152: false
                })
                .build(),
        ))
        .unwrap(),
        None,
    );
}

/// The Ethereum chain under test: which JSON-RPC endpoint the EVM RPC canister's outcalls reach,
/// and the corresponding minter init/upgrade assumptions about that chain's state (the block height
/// to track, and where its log-scraping cursor starts).
enum EthereumBackend {
    /// Canned JSON-RPC mocks pinned to a historical mainnet snapshot.
    Mocked,
    /// A live anvil node, reached over HTTP at its own URL: a fresh chain with no finalized blocks
    /// yet. `Arc` because this is a clone shared with the harness that started the node and keeps
    /// it running for the fixture's lifetime; this particular clone is dropped once
    /// [`CkEthSetup::new`] returns, having done its job of computing the install args below. The
    /// canisters themselves are created and installed in the same order as for
    /// [`EthereumBackend::Mocked`] — only their init args differ; [`crate::live`] is the one
    /// that switches the PocketIC instance to live outcalls, once its whole fixture is built.
    ///
    /// `sweep_contracts` are already deployed on that node when set, so the minter is installed
    /// knowing which delegate its deposit addresses delegate to.
    Anvil {
        anvil: Arc<Anvil>,
        sweep_contracts: Option<SweepContracts>,
    },
}

impl EthereumBackend {
    fn install_args(&self) -> InstallArgs {
        InstallArgs {
            override_provider: match self {
                EthereumBackend::Mocked => None,
                EthereumBackend::Anvil { anvil, .. } => Some(OverrideProvider {
                    override_url: Some(RegexSubstitution {
                        pattern: ".*".into(),
                        replacement: anvil.url().to_string(),
                    }),
                }),
            },
            ..Default::default()
        }
    }

    fn ethereum_block_height(&self) -> CandidBlockTag {
        match self {
            // The mocked responses replay a historical mainnet snapshot, long since finalized.
            EthereumBackend::Mocked => CandidBlockTag::Finalized,
            // A fresh anvil chain has no finalized blocks, so track its "latest" head instead.
            EthereumBackend::Anvil { .. } => CandidBlockTag::Latest,
        }
    }

    /// The delegate the minter sweeps through, if this backend has one deployed.
    fn sweeper_contract_address(&self) -> Option<String> {
        match self {
            EthereumBackend::Mocked => None,
            EthereumBackend::Anvil {
                sweep_contracts, ..
            } => sweep_contracts.map(|contracts| contracts.delegate.to_string()),
        }
    }

    fn last_scraped_block_number(&self) -> Nat {
        match self {
            // The block the mocked JSON-RPC responses are canned to scrape logs from onward.
            EthereumBackend::Mocked => LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into(),
            EthereumBackend::Anvil { .. } => 0_u8.into(),
        }
    }
}

/// PocketIC's fiduciary subnet holds the secp256k1 test key under this name, the key the minter
/// derives deposit addresses from.
const ECDSA_KEY_NAME: &str = "key_1";

fn install_minter(env: &PocketIc, canisters: &CkEthCanisters, backend: &EthereumBackend) {
    let args = MinterInitArgs {
        ecdsa_key_name: ECDSA_KEY_NAME.to_string(),
        ethereum_network: EthereumNetwork::Mainnet,
        ledger_id: canisters.ledger_id,
        next_transaction_nonce: 0_u8.into(),
        ethereum_block_height: backend.ethereum_block_height(),
        ethereum_contract_address: Some(ETH_HELPER_CONTRACT_ADDRESS.to_string()),
        minimum_withdrawal_amount: CKETH_MINIMUM_WITHDRAWAL_AMOUNT.into(),
        last_scraped_block_number: backend.last_scraped_block_number(),
        evm_rpc_id: Some(canisters.evm_rpc_id),
        ethereum_sweeper_contract_address: backend.sweeper_contract_address(),
        next_sweeper_transaction_nonce: None,
    };
    env.install_canister(
        canisters.minter_id,
        minter_wasm(),
        Encode!(&MinterArg::InitArg(args)).unwrap(),
        None,
    );
}

fn install_evm_rpc(env: &PocketIc, canisters: &CkEthCanisters, backend: &EthereumBackend) {
    env.install_canister(
        canisters.evm_rpc_id,
        evm_rpc_wasm(),
        Encode!(&backend.install_args()).unwrap(),
        None,
    );
}

fn fail_as_timed_out(env: &PocketIc, request: &CanisterHttpRequest) {
    env.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: request.subnet_id,
        request_id: request.request_id,
        response: CanisterHttpResponse::CanisterHttpReject(CanisterHttpReject {
            reject_code: REJECT_CODE_SYS_TRANSIENT,
            message: "Canister http request timed out".to_string(),
        }),
        additional_responses: vec![],
    });
}

fn reply_500(env: &PocketIc, request: &CanisterHttpRequest) {
    env.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: request.subnet_id,
        request_id: request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 500,
            headers: vec![],
            body: vec![],
        }),
        additional_responses: vec![],
    });
}

fn assert_reply(result: Result<Vec<u8>, RejectResponse>) -> Vec<u8> {
    result.unwrap_or_else(|reject| panic!("Expected a successful reply, got a reject: {reject}"))
}

pub struct LedgerBalance {
    pub ledger_id: Principal,
    pub account: Account,
    pub balance: Nat,
}

#[derive(Debug)]
pub struct CanisterLog {
    pub timestamp_nanos: u64,
    pub idx: u64,
    pub content: String,
}
