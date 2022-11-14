use async_trait::async_trait;
use candid::candid_method;
use dfn_candid::{candid_one, CandidOne};
use dfn_core::CanisterId;
use dfn_core::{
    api::{caller, id, now},
    over, over_async, over_init, println,
};
use ic_base_types::PrincipalId;
use ic_ic00_types::CanisterStatusResultV2;
use ic_nervous_system_common::stable_mem_utils::{
    BufferedStableMemReader, BufferedStableMemWriter,
};
use ic_sns_governance::ledger::LedgerCanister;
use ic_sns_governance::pb::v1::{
    ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, ManageNeuron, ManageNeuronResponse, SetMode,
    SetModeResponse,
};

// TODO(NNS1-1589): Unhack.
// use ic_sns_root::pb::v1::{SetDappControllersRequest, SetDappControllersResponse};
use ic_sns_swap::pb::v1::{
    GovernanceError, RestoreDappControllersRequest, RestoreDappControllersResponse,
    SetDappControllersRequest, SetDappControllersResponse, SettleCommunityFundParticipation,
};

use ic_sns_swap::pb::v1::{
    CanisterCallError, ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapRequest,
    FinalizeSwapResponse, GetBuyerStateRequest, GetBuyerStateResponse, GetBuyersTotalRequest,
    GetBuyersTotalResponse, GetCanisterStatusRequest, GetStateRequest, GetStateResponse, Init,
    OpenRequest, OpenResponse, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse, Swap,
};
use ic_sns_swap::swap::{NnsGovernanceClient, SnsGovernanceClient, SnsRootClient, LOG_PREFIX};
use prost::Message;
use std::str::FromStr;
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

/// Try to open the swap.
///
/// See Swap.open.
#[export_name = "canister_update open"]
fn open() {
    over_async(candid_one, open_)
}

/// See `open`.
#[candid_method(update, rename = "open")]
async fn open_(req: OpenRequest) -> OpenResponse {
    println!("{}open", LOG_PREFIX);
    // Require authorization.
    let allowed_canister = swap().init().nns_governance();
    if caller() != PrincipalId::from(allowed_canister) {
        panic!(
            "This method can only be called by canister {}",
            allowed_canister
        );
    }
    let sns_ledger = create_real_icrc1_ledger(swap().init().sns_ledger());
    match swap_mut().open(id(), &sns_ledger, now_seconds(), req).await {
        Ok(res) => res,
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
    let icp_ledger = create_real_icp_ledger(swap().init().icp_ledger());
    match swap_mut()
        .refresh_buyer_token_e8s(p, id(), &icp_ledger)
        .await
    {
        Ok(r) => r,
        Err(msg) => panic!("{}", msg),
    }
}

struct RealSnsRootClient {
    canister_id: CanisterId,
}

impl RealSnsRootClient {
    fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl SnsRootClient for RealSnsRootClient {
    async fn set_dapp_controllers(
        &mut self,
        request: SetDappControllersRequest,
    ) -> Result<SetDappControllersResponse, CanisterCallError> {
        dfn_core::api::call(
            self.canister_id,
            "set_dapp_controllers",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
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

    async fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
    ) -> Result<ClaimSwapNeuronsResponse, CanisterCallError> {
        dfn_core::api::call(
            self.canister_id,
            "claim_swap_neurons",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }
}

struct RealNnsGovernanceClient {
    canister_id: CanisterId,
}

impl RealNnsGovernanceClient {
    fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl NnsGovernanceClient for RealNnsGovernanceClient {
    async fn settle_community_fund_participation(
        &mut self,
        request: SettleCommunityFundParticipation,
    ) -> Result<Result<(), GovernanceError>, CanisterCallError> {
        dfn_core::api::call(
            self.canister_id,
            "settle_community_fund_participation",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }
}

fn now_fn(_: bool) -> u64 {
    now_seconds()
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
    let mut sns_root_client = RealSnsRootClient::new(swap().init().sns_root());
    let mut sns_governance_client = RealSnsGovernanceClient::new(swap().init().sns_governance());
    let icp_ledger = create_real_icp_ledger(swap().init().icp_ledger());
    let sns_ledger = create_real_icrc1_ledger(swap().init().sns_ledger());
    let mut nns_governance_client = RealNnsGovernanceClient::new(swap().init().nns_governance());
    swap_mut()
        .finalize(
            now_fn,
            &mut sns_root_client,
            &mut sns_governance_client,
            &icp_ledger,
            &sns_ledger,
            &mut nns_governance_client,
        )
        .await
}

#[export_name = "canister_update error_refund_icp"]
fn error_refund_icp() {
    over_async(candid_one, error_refund_icp_)
}

#[candid_method(update, rename = "error_refund_icp")]
async fn error_refund_icp_(request: ErrorRefundIcpRequest) -> ErrorRefundIcpResponse {
    let icp_ledger = create_real_icp_ledger(swap().init().icp_ledger());
    swap().error_refund_icp(id(), &request, &icp_ledger).await
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

#[export_name = "canister_update restore_dapp_controllers"]
fn restore_dapp_controllers() {
    over_async(candid_one, restore_dapp_controllers_)
}

#[candid_method(update, rename = "restore_dapp_controllers")]
async fn restore_dapp_controllers_(
    _request: RestoreDappControllersRequest,
) -> RestoreDappControllersResponse {
    println!("{}retore_dapp_controllers", LOG_PREFIX);
    // Require authorization.
    let allowed_canister = swap().init().nns_governance();
    if caller() != PrincipalId::from(allowed_canister) {
        panic!(
            "This method can only be called by canister {}",
            allowed_canister
        );
    }
    let mut sns_root_client = RealSnsRootClient::new(swap().init().sns_root());
    swap_mut()
        .restore_dapp_controllers(&mut sns_root_client)
        .await
        .into()
}

// =============================================================================
// ===               Canister helper & boilerplate methods                   ===
// =============================================================================

/// Tries to commit or abort the swap if the parameters have been satisfied.
#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let now = now_seconds();
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

/// Returns a real ledger stub that communicates with the specified
/// canister, which is assumed to be the ICP production ledger or a
/// canister that implements that same interface.
fn create_real_icp_ledger(id: CanisterId) -> ic_nervous_system_common::ledger::IcpLedgerCanister {
    ic_nervous_system_common::ledger::IcpLedgerCanister::new(id)
}

/// Returns a real ledger stub that communicates with the specified
/// canister, which is assumed to be a canister that implements the
/// ICRC1 interface.
fn create_real_icrc1_ledger(id: CanisterId) -> LedgerCanister {
    LedgerCanister::new(id)
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

/// Deserialize what has been written to stable memory in
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
        let did_path = format!(
            "{}/canister/swap.did",
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
        );
        let did_contents = String::from_utf8(std::fs::read(did_path).unwrap()).unwrap();

        // See comments in main above
        candid::export_service!();
        let expected = __export_service();

        if did_contents != expected {
            panic!(
                "Generated candid definition does not match canister/swap.did. \
                 Run `bazel run :generate_did > canister/swap.did` (no nix and/or direnv) or \
                 `cargo run --bin sns-swap-canister > canister/swap.did` in \
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
