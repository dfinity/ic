/*

TODO - REQUIRED
- Unit tests: WIP.
- Neuron creation: implement.
- Canister methods for token distributions.

TODO - OPTIONAL / SEMI-REQUIRED
- Introduce Min ICP.
- No participant can buy more than or equal to half (or X% for some config paramter X) of the tokens.
- Refine approach to fee handling.
- Address occurrences of TODO in the code.
- What if ICP target is reached but there is an insufficient number of participants?

 */

use async_trait::async_trait;
use candid::candid_method;
use dfn_candid::{candid_one, CandidOne};
use dfn_core::CanisterId;
use dfn_core::{
    api::{caller, id, now},
    over, over_async, over_init, println,
};
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::stable_mem_utils::{
    BufferedStableMemReader, BufferedStableMemWriter,
};
use ic_sns_governance::ledger::{Ledger, LedgerCanister};
use ic_sns_governance::pb::v1::{ManageNeuron, ManageNeuronResponse, SetMode, SetModeResponse};
use ic_sns_governance::types::DEFAULT_TRANSFER_FEE;
use ic_sns_swap::pb::v1::{
    CanisterCallError, ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapRequest,
    FinalizeSwapResponse, GetBuyerStateRequest, GetBuyerStateResponse, GetBuyersTotalRequest,
    GetBuyersTotalResponse, GetCanisterStatusRequest, GetStateRequest, GetStateResponse, Init,
    Lifecycle, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse, RefreshSnsTokensRequest,
    RefreshSnsTokensResponse, SetOpenTimeWindowRequest, SetOpenTimeWindowResponse, Swap,
};
use ic_sns_swap::swap::{SnsGovernanceClient, LOG_PREFIX};

use std::str::FromStr;

use ic_ic00_types::CanisterStatusResultV2;
use prost::Message;
use std::time::{Duration, SystemTime};

/// Size of the buffer for stable memory reads and writes.
const STABLE_MEM_BUFFER_SIZE: u32 = 1024 * 1024; // 1MiB

// =============================================================================
// ===               Global state of the canister                            ===
// =============================================================================

/// The global state of the this canister.
static mut SWAP: Option<Swap> = None;

/// Returns an immutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn swap() -> &'static Swap {
    unsafe { SWAP.as_ref().expect("Canister not initialized!") }
}

/// Returns a mutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn swap_mut() -> &'static mut Swap {
    unsafe { SWAP.as_mut().expect("Canister not initialized!") }
}

// =============================================================================
// ===               Canister's public interface                             ===
// =============================================================================

/// See `GetStateResponse`.
#[export_name = "canister_query get_state"]
fn get_state() {
    over(candid_one, get_state_)
}

/// See `GetStateResponse`.
#[candid_method(query, rename = "get_state")]
fn get_state_(_arg: GetStateRequest) -> GetStateResponse {
    GetStateResponse {
        swap: Some(swap().clone()),
        derived: Some(swap().derived_state()),
    }
}

/// Get the state of a buyer. This will return a `GetBuyerStateResponse`
/// with an optional `BuyerState` struct if the Swap Canister has
/// been successfully notified of a buyer's ICP transfer.
#[export_name = "canister_query get_buyer_state"]
fn get_buyer_state() {
    over(candid_one, get_buyer_state_)
}

/// Get the state of a buyer. This will return a `GetBuyerStateResponse`
/// with an optional `BuyerState` struct if the Swap Canister has
/// been successfully notified of a buyer's ICP transfer.
#[candid_method(query, rename = "get_buyer_state")]
fn get_buyer_state_(request: GetBuyerStateRequest) -> GetBuyerStateResponse {
    println!("{}get_buyer_state", LOG_PREFIX);
    swap().get_buyer_state(&request)
}

/// Sets the window of time when buyers can participate.
///
/// See Swap.set_open_time_window.
#[export_name = "canister_update set_open_time_window"]
fn set_open_time_window() {
    over(candid_one, set_open_time_window_)
}

/// See `set_open_time_window`.
#[candid_method(update, rename = "set_open_time_window")]
fn set_open_time_window_(request: SetOpenTimeWindowRequest) -> SetOpenTimeWindowResponse {
    println!("{}set_open_time_window", LOG_PREFIX);
    swap_mut().set_open_time_window(caller(), now_seconds(), &request)
}

/// See `Swap.refresh_sns_token_e8s`.
#[export_name = "canister_update refresh_sns_tokens"]
fn refresh_sns_tokens() {
    over_async(candid_one, refresh_sns_tokens_)
}

/// See `Swap.refresh_sns_token_e8`.
#[candid_method(update, rename = "refresh_sns_tokens")]
async fn refresh_sns_tokens_(_: RefreshSnsTokensRequest) -> RefreshSnsTokensResponse {
    println!("{}refresh_sns_tokens", LOG_PREFIX);
    let ledger_factory = &create_real_icrc1_ledger;
    match swap_mut().refresh_sns_token_e8s(id(), ledger_factory).await {
        Ok(()) => RefreshSnsTokensResponse {},
        Err(msg) => panic!("{}", msg),
    }
}

/// See `Swap.refresh_buyer_token_e8`.
#[export_name = "canister_update refresh_buyer_tokens"]
fn refresh_buyer_tokens() {
    over_async(candid_one, refresh_buyer_tokens_)
}

/// See `Swap.refresh_buyer_token_e8`.
#[candid_method(update, rename = "refresh_buyer_tokens")]
async fn refresh_buyer_tokens_(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    println!("{}refresh_buyer_tokens", LOG_PREFIX);
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
    };
    let ledger_factory = &create_real_icp_ledger;
    match swap_mut()
        .refresh_buyer_token_e8s(p, id(), ledger_factory)
        .await
    {
        Ok(()) => RefreshBuyerTokensResponse {},
        Err(msg) => panic!("{}", msg),
    }
}

struct RealSnsGovernanceClient {
    canister_id: CanisterId,
}

impl RealSnsGovernanceClient {
    fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl SnsGovernanceClient for RealSnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError> {
        dfn_core::api::call(
            self.canister_id,
            "manage_neuron",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError> {
        // TODO: Eliminate repetitive code. At least textually, the only
        // difference is the second argument that gets passed to
        // dfn_core::api::call (the name of the method).
        dfn_core::api::call(
            self.canister_id,
            "set_mode",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }
}

/// See Swap.finalize.
#[export_name = "canister_update finalize_swap"]
fn finalize_swap() {
    over_async(candid_one, finalize_swap_)
}

/// See Swap.finalize.
#[candid_method(update, rename = "finalize_swap")]
async fn finalize_swap_(_arg: FinalizeSwapRequest) -> FinalizeSwapResponse {
    // Helpers.
    let mut sns_governance_client = RealSnsGovernanceClient::new(swap().init().sns_governance());
    let icp_ledger_factory = create_real_icp_ledger;
    let icrc1_ledger_factory = create_real_icrc1_ledger;

    swap_mut()
        .finalize(
            &mut sns_governance_client,
            icp_ledger_factory,
            icrc1_ledger_factory,
        )
        .await
}

#[export_name = "canister_update error_refund_icp"]
fn error_refund_icp() {
    over_async(candid_one, error_refund_icp_)
}

#[candid_method(update, rename = "error_refund_icp")]
async fn error_refund_icp_(arg: ErrorRefundIcpRequest) -> ErrorRefundIcpResponse {
    swap()
        .error_refund_icp(
            caller(),
            Tokens::from_e8s(arg.icp_e8s),
            if arg.fee_override_e8s > 0 {
                Tokens::from_e8s(arg.fee_override_e8s)
            } else {
                DEFAULT_TRANSFER_FEE
            },
            &create_real_icp_ledger,
        )
        .await;
    ErrorRefundIcpResponse {}
}

/// A trait that wraps calls to the IC's Management Canister. More details on the management
/// canister can be found in the InternetComputer spec:
///
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister
#[async_trait]
trait ManagementCanister {
    async fn canister_status(&self, canister_id: &CanisterId) -> CanisterStatusResultV2;
}

struct ProdManagementCanister {}

impl ProdManagementCanister {
    fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ManagementCanister for ProdManagementCanister {
    async fn canister_status(&self, canister_id: &CanisterId) -> CanisterStatusResultV2 {
        let result = ic_nervous_system_common::get_canister_status(canister_id.get()).await;
        result.unwrap_or_else(|err| {
            panic!(
                "Couldn't get canister_status of {}. Err: {:#?}",
                canister_id, err
            )
        })
    }
}

#[export_name = "canister_update get_canister_status"]
fn get_canister_status() {
    over_async(candid_one, get_canister_status_)
}

#[candid_method(update, rename = "get_canister_status")]
async fn get_canister_status_(_request: GetCanisterStatusRequest) -> CanisterStatusResultV2 {
    do_get_canister_status(&id(), &ProdManagementCanister::new()).await
}

async fn do_get_canister_status(
    canister_id: &CanisterId,
    management_canister: &impl ManagementCanister,
) -> CanisterStatusResultV2 {
    management_canister.canister_status(canister_id).await
}

/// Returns the total amount of ICP deposited by participants in the swap.
#[export_name = "canister_update get_buyers_total"]
fn get_buyers_total() {
    over_async(candid_one, get_buyers_total_)
}

/// Returns the total amount of ICP deposited by participants in the swap.
#[candid_method(update, rename = "get_buyers_total")]
async fn get_buyers_total_(_request: GetBuyersTotalRequest) -> GetBuyersTotalResponse {
    swap().get_buyers_total()
}

// =============================================================================
// ===               Canister helper & boilerplate methods                   ===
// =============================================================================

/// Advances the swap. I.e. tries to move it into a more advanced phase in its
/// Lifecycle.
#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let now = now_seconds();

    // Try to open the swap.
    if swap_mut().state().lifecycle() == Lifecycle::Pending {
        let result = swap_mut().open(now);

        // Log result.
        match result {
            Ok(()) => {
                println!("The swap has been successfully opened.");
            }
            Err(err) => {
                let squelch = err.contains("start time");
                if !squelch {
                    println!(
                        "{}WARNING: Tried to open automatically, but failed: {}",
                        LOG_PREFIX, err
                    );
                }
            }
        }
    }

    if swap_mut().try_commit_or_abort(now) {
        println!("{}Swap committed/aborted at timestamp {}", LOG_PREFIX, now);
    }
}

fn now_seconds() -> u64 {
    now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Returns a function that (when passed the canister ID of a presumptive
/// Ledger) returns a Ledger implementation suitable for use in
/// production. I.e. calls out to another canister.
///
/// This function is a "Ledger factory" in that you call this, and a Ledger
/// object is returned. What distinguishes this from other possible Ledger
/// factories is that this produces objects that are suitable for use in
/// production.
fn create_real_icp_ledger(id: CanisterId) -> Box<dyn Ledger> {
    Box::new(ic_nervous_system_common::ledger::LedgerCanister::new(id))
}

/// Returns a function that (when passed the canister ID of a presumptive
/// Ledger) returns a Ledger implementation suitable for use in
/// production. I.e. calls out to another canister.
///
/// This function is a "Ledger factory" in that you call this, and a Ledger
/// object is returned. What distinguishes this from other possible Ledger
/// factories is that this produces objects that are suitable for use in
/// production.
fn create_real_icrc1_ledger(id: CanisterId) -> Box<dyn Ledger> {
    Box::new(LedgerCanister::new(id))
}

#[export_name = "canister_init"]
fn canister_init() {
    over_init(|CandidOne(arg)| canister_init_(arg))
}

/// In contrast to canister_init(), this method does not do deserialization.
#[candid_method(init)]
fn canister_init_(init_payload: Init) {
    dfn_core::printer::hook();
    let swap = Swap::new(init_payload);
    unsafe {
        assert!(
            SWAP.is_none(),
            "{}Trying to initialize an already initialized canister!",
            LOG_PREFIX
        );
        SWAP = Some(swap);
    }
    println!("{}Initialized", LOG_PREFIX);
}

/// Serialize and write the state to stable memory so that it is
/// preserved during the upgrade and can be deserialised again in
/// `canister_post_upgrade`.
#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);
    let mut writer = BufferedStableMemWriter::new(STABLE_MEM_BUFFER_SIZE);
    swap()
        .encode(&mut writer)
        .expect("Error. Couldn't serialize canister pre-upgrade.");
    writer.flush();
}

/// Deserialise what has been written to stable memory in
/// canister_pre_upgrade and initialising the state with it.
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", LOG_PREFIX);
    let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);
    match Swap::decode(reader) {
        Err(err) => {
            panic!(
                "{}Error deserializing canister state post-upgrade. \
		 CANISTER HAS BROKEN STATE!!!!. Error: {:?}",
                LOG_PREFIX, err
            );
        }
        Ok(proto) => unsafe {
            assert!(
                SWAP.is_none(),
                "{}Trying to post-upgrade an already initialized canister!",
                LOG_PREFIX
            );
            SWAP = Some(proto);
        },
    }
}

/// When run on native, this prints the candid service definition of this
/// canister, from the methods annotated with `candid_method` above.
///
/// Note that `cargo test` calls `main`, and `export_service` (which defines
/// `__export_service` in the current scope) needs to be called exactly once. So
/// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
/// to avoid calling `export_service` in tests.
#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    std::print!("{}", __export_service());
}

/// Empty main for test target.
#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_ic00_types::CanisterStatusType;

    /// A test that fails if the API was updated but the candid definition was not.
    #[test]
    fn check_swap_candid_file() {
        let governance_did =
            String::from_utf8(std::fs::read("canister/swap.did").unwrap()).unwrap();

        // See comments in main above
        candid::export_service!();
        let expected = __export_service();

        if governance_did != expected {
            panic!(
                "Generated candid definition does not match canister/swap.did. \
                 Run `cargo run --bin sns-swap-canister > canister/swap.did` in \
                 rs/sns/swap to update canister/swap.did."
            )
        }
    }

    fn basic_canister_status() -> CanisterStatusResultV2 {
        CanisterStatusResultV2::new(
            CanisterStatusType::Running,
            None,
            Default::default(),
            vec![],
            Default::default(),
            0,
            0,
            None,
            0,
            0,
        )
    }

    struct StubManagementCanister {}

    #[async_trait]
    impl ManagementCanister for StubManagementCanister {
        async fn canister_status(&self, _canister_id: &CanisterId) -> CanisterStatusResultV2 {
            basic_canister_status()
        }
    }

    #[tokio::test]
    async fn test_get_canister_status() {
        let response =
            do_get_canister_status(&CanisterId::from_u64(1), &StubManagementCanister {}).await;
        assert_eq!(response, basic_canister_status(),);
    }
}
