use candid::candid_method;
use dfn_candid::{candid_one, CandidOne};
use dfn_core::{
    api::{caller, id, now},
    over, over_async, over_init, CanisterId,
};
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_clients::ledger_client::LedgerCanister;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::CanisterStatusResultV2,
    management_canister_client::{ManagementCanisterClient, ManagementCanisterClientImpl},
};
use ic_nervous_system_common::{
    dfn_core_stable_mem_utils::BufferedStableMemReader, serve_logs, serve_logs_v2, serve_metrics,
};
use ic_nervous_system_runtime::DfnRuntime;
use ic_sns_swap::{
    clients::RealSnsRootClient,
    logs::{ERROR, INFO},
    memory::UPGRADES_MEMORY,
    pb::v1::{
        ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapRequest, FinalizeSwapResponse,
        GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse, GetBuyerStateRequest,
        GetBuyerStateResponse, GetBuyersTotalRequest, GetBuyersTotalResponse,
        GetCanisterStatusRequest, GetDerivedStateRequest, GetDerivedStateResponse, GetInitRequest,
        GetInitResponse, GetLifecycleRequest, GetLifecycleResponse, GetOpenTicketRequest,
        GetOpenTicketResponse, GetSaleParametersRequest, GetSaleParametersResponse,
        GetStateRequest, GetStateResponse, Init, ListCommunityFundParticipantsRequest,
        ListCommunityFundParticipantsResponse, ListDirectParticipantsRequest,
        ListDirectParticipantsResponse, ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse,
        NewSaleTicketRequest, NewSaleTicketResponse, NotifyPaymentFailureRequest,
        NotifyPaymentFailureResponse, OpenRequest, OpenResponse, RefreshBuyerTokensRequest,
        RefreshBuyerTokensResponse, RestoreDappControllersRequest, RestoreDappControllersResponse,
        Swap,
    },
};
use ic_stable_structures::{writer::Writer, Memory};
use prost::Message;
use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};

// TODO(NNS1-1589): Unhack.
// use ic_sns_root::pb::v1::{SetDappControllersRequest, SetDappControllersResponse};

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
    swap().get_state()
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
    log!(INFO, "get_buyer_state");
    swap().get_buyer_state(&request)
}

/// Get Params.
#[export_name = "canister_query get_sale_parameters"]
fn get_sale_parameters() {
    over(candid_one, get_sale_parameters_)
}

/// Get Params.
#[candid_method(query, rename = "get_sale_parameters")]
fn get_sale_parameters_(request: GetSaleParametersRequest) -> GetSaleParametersResponse {
    swap().get_sale_parameters(&request)
}

/// List Community Fund participants.
#[export_name = "canister_query list_community_fund_participants"]
fn list_community_fund_participants() {
    over(candid_one, list_community_fund_participants_);
}

/// List Community Fund participants.
#[candid_method(query, rename = "list_community_fund_participants")]
fn list_community_fund_participants_(
    request: ListCommunityFundParticipantsRequest,
) -> ListCommunityFundParticipantsResponse {
    log!(INFO, "list_community_fund_participants");
    swap().list_community_fund_participants(&request)
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
    log!(INFO, "open");
    // Require authorization.
    let allowed_canister = swap().init_or_panic().nns_governance_or_panic();
    if caller() != PrincipalId::from(allowed_canister) {
        panic!(
            "This method can only be called by canister {}",
            allowed_canister
        );
    }
    let sns_ledger = create_real_icrc1_ledger(swap().init_or_panic().sns_ledger_or_panic());
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
    log!(INFO, "refresh_buyer_tokens");
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
    };
    let icp_ledger = create_real_icp_ledger(swap().init_or_panic().icp_ledger_or_panic());
    match swap_mut()
        .refresh_buyer_token_e8s(p, arg.confirmation_text, id(), &icp_ledger)
        .await
    {
        Ok(r) => r,
        Err(msg) => panic!("{}", msg),
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
    log!(INFO, "finalize_swap");
    let mut clients = swap()
        .init_or_panic()
        .environment()
        .expect("unable to create canister clients");

    swap_mut().finalize(now_fn, &mut clients).await
}

#[export_name = "canister_update error_refund_icp"]
fn error_refund_icp() {
    over_async(candid_one, error_refund_icp_)
}

#[candid_method(update, rename = "error_refund_icp")]
async fn error_refund_icp_(request: ErrorRefundIcpRequest) -> ErrorRefundIcpResponse {
    let icp_ledger = create_real_icp_ledger(swap().init_or_panic().icp_ledger_or_panic());
    swap().error_refund_icp(id(), &request, &icp_ledger).await
}

#[export_name = "canister_update get_canister_status"]
fn get_canister_status() {
    over_async(candid_one, get_canister_status_)
}

#[candid_method(update, rename = "get_canister_status")]
async fn get_canister_status_(_request: GetCanisterStatusRequest) -> CanisterStatusResultV2 {
    do_get_canister_status(id(), &ManagementCanisterClientImpl::<DfnRuntime>::new(None)).await
}

async fn do_get_canister_status(
    canister_id: CanisterId,
    management_canister: &impl ManagementCanisterClient,
) -> CanisterStatusResultV2 {
    management_canister
        .canister_status(CanisterIdRecord::from(canister_id))
        .await
        .map(CanisterStatusResultV2::from)
        .unwrap_or_else(|err| {
            panic!(
                "Couldn't get canister_status of {}. Err: {:#?}",
                canister_id, err
            )
        })
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

/// Restores all dapp canisters to the fallback controllers as specified
/// in the SNS initialization process, marking the Swap as aborted in the
/// process. `restore_dapp_controllers` is only callable by NNS Governance.
#[export_name = "canister_update restore_dapp_controllers"]
fn restore_dapp_controllers() {
    over_async(candid_one, restore_dapp_controllers_)
}

/// Restores all dapp canisters to the fallback controllers as specified
/// in the SNS initialization process, marking the Swap as aborted in the
/// process. `restore_dapp_controllers` is only callable by NNS Governance.
#[candid_method(update, rename = "restore_dapp_controllers")]
async fn restore_dapp_controllers_(
    _request: RestoreDappControllersRequest,
) -> RestoreDappControllersResponse {
    log!(INFO, "restore_dapp_controllers");
    let mut sns_root_client = RealSnsRootClient::new(swap().init_or_panic().sns_root_or_panic());
    swap_mut()
        .restore_dapp_controllers(&mut sns_root_client, caller())
        .await
}

/// Return the current lifecycle stage (e.g. Open, Committed, etc)
#[export_name = "canister_query get_lifecycle"]
fn get_lifecycle() {
    over(candid_one, get_lifecycle_)
}

#[candid_method(query, rename = "get_lifecycle")]
fn get_lifecycle_(request: GetLifecycleRequest) -> GetLifecycleResponse {
    log!(INFO, "get_lifecycle");
    swap().get_lifecycle(&request)
}

/// Return the status of auto-finalization
#[export_name = "canister_query get_auto_finalization_status"]
fn get_auto_finalization_status() {
    over(candid_one, get_auto_finalization_status_)
}

#[candid_method(query, rename = "get_auto_finalization_status")]
fn get_auto_finalization_status_(
    request: GetAutoFinalizationStatusRequest,
) -> GetAutoFinalizationStatusResponse {
    log!(INFO, "get_auto_finalization_status");
    swap().get_auto_finalization_status(&request)
}

/// Returns the initialization data of the canister
#[export_name = "canister_query get_init"]
fn get_init() {
    over_async(candid_one, get_init_)
}

/// Returns the initialization data of the canister
#[candid_method(query, rename = "get_init")]
async fn get_init_(request: GetInitRequest) -> GetInitResponse {
    log!(INFO, "get_init");
    swap().get_init(&request)
}

/// Return the current derived state of the Swap
#[export_name = "canister_query get_derived_state"]
fn get_derived_state() {
    over_async(candid_one, get_derived_state_)
}

/// Return the current derived state of the Swap
#[candid_method(query, rename = "get_derived_state")]
async fn get_derived_state_(_request: GetDerivedStateRequest) -> GetDerivedStateResponse {
    log!(INFO, "get_derived_state");
    swap().derived_state().into()
}

#[export_name = "canister_query get_open_ticket"]
fn get_open_ticket() {
    over_async(candid_one, get_open_ticket_)
}

#[candid_method(query, rename = "get_open_ticket")]
async fn get_open_ticket_(request: GetOpenTicketRequest) -> GetOpenTicketResponse {
    log!(INFO, "get_open_ticket");
    swap().get_open_ticket(&request, caller())
}

#[export_name = "canister_update new_sale_ticket"]
fn new_sale_ticket() {
    over_async(candid_one, new_sale_ticket_)
}

#[candid_method(update, rename = "new_sale_ticket")]
async fn new_sale_ticket_(request: NewSaleTicketRequest) -> NewSaleTicketResponse {
    log!(INFO, "new_sale_ticket");
    swap_mut().new_sale_ticket(&request, caller(), dfn_core::api::time_nanos())
}

/// Lists direct participants in the Swap.
#[export_name = "canister_query list_direct_participants"]
fn list_direct_participants() {
    over_async(candid_one, list_direct_participants_)
}

/// Lists direct participants in the Swap.
#[candid_method(query, rename = "list_direct_participants")]
async fn list_direct_participants_(
    request: ListDirectParticipantsRequest,
) -> ListDirectParticipantsResponse {
    log!(INFO, "list_direct_participants");
    swap().list_direct_participants(request)
}

#[export_name = "canister_query list_sns_neuron_recipes"]
fn list_sns_neuron_recipes() {
    over(candid_one, list_sns_neuron_recipes_)
}

#[candid_method(query, rename = "list_sns_neuron_recipes")]
fn list_sns_neuron_recipes_(request: ListSnsNeuronRecipesRequest) -> ListSnsNeuronRecipesResponse {
    log!(INFO, "list_neuron_recipes");
    swap().list_sns_neuron_recipes(request)
}

#[export_name = "canister_update notify_payment_failure"]
fn notify_payment_failure() {
    over(candid_one, notify_payment_failure_)
}

#[candid_method(update, rename = "notify_payment_failure")]
fn notify_payment_failure_(_request: NotifyPaymentFailureRequest) -> NotifyPaymentFailureResponse {
    log!(INFO, "notify_payment_failure");
    swap_mut().notify_payment_failure(&caller())
}

// =============================================================================
// ===               Canister helper & boilerplate methods                   ===
// =============================================================================

/// Tries to commit or abort the swap if the parameters have been satisfied.
#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let future = swap_mut().heartbeat(now_fn);

    // The canister_heartbeat must be synchronous, so we cannot .await the future.
    dfn_core::api::futures::spawn(future);
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
            "Trying to initialize an already initialized canister!",
        );
        SWAP = Some(swap);
    }
    log!(INFO, "Initialized");
}

/// Serialize and write the state to stable memory so that it is
/// preserved during the upgrade and can be deserialized again in
/// `canister_post_upgrade`.
#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    log!(INFO, "Executing pre upgrade");

    // serialize the state
    let mut state_bytes = vec![];
    swap()
        .encode(&mut state_bytes)
        .expect("Error. Couldn't serialize canister pre-upgrade.");

    // Write the length of the serialized bytes to memory, followed by the
    // by the bytes themselves.
    UPGRADES_MEMORY.with(|um| {
        let mut um = um.borrow_mut().to_owned();
        let mut writer = Writer::new(&mut um, 0);
        writer
            .write(&(state_bytes.len() as u32).to_le_bytes())
            .expect("Error. Couldn't write to stable memory");
        writer
            .write(&state_bytes)
            .expect("Error. Couldn't write to stable memory");
    })
}

/// Deserialize what has been written to stable memory in
/// canister_pre_upgrade and initialising the state with it.
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    fn set_state(proto: Swap) {
        unsafe {
            assert!(
                SWAP.is_none(),
                "Trying to post-upgrade an already initialized canister!",
            );
            SWAP = Some(proto);
        }
    }

    log!(INFO, "Executing post upgrade");

    // This post_upgrade is done in two steps because of NNS1-2014:
    //   1. First try to read the state as it was stored before NNS1-2014
    //   2. If that fails then we try to read the state as it is stored since NNS1-2014

    // First try to read the state using the same approach used before NNS1-2014

    const STABLE_MEM_BUFFER_SIZE: u32 = 1024 * 1024; // 1MiB
    let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);
    match Swap::decode(reader) {
        // if reading was successful then this canister was pre NNS1-2014,
        // nothing else to do
        Ok(proto) => set_state(proto),

        // otherwise try to read the state using the approach implemented in NNS1-2014
        Err(_) => {
            // Read the length of the state bytes.
            let serialized_swap_message_len = UPGRADES_MEMORY.with(|um| {
                let mut serialized_swap_message_len_bytes = [0; std::mem::size_of::<u32>()];
                um.borrow()
                    .read(/* offset */ 0, &mut serialized_swap_message_len_bytes);
                u32::from_le_bytes(serialized_swap_message_len_bytes) as usize
            });

            // Read the state bytes.
            let decode_swap_result = UPGRADES_MEMORY.with(|um| {
                let mut swap_bytes = vec![0; serialized_swap_message_len];
                um.borrow().read(
                    /* offset */ std::mem::size_of::<u32>() as u64,
                    &mut swap_bytes,
                );
                Swap::decode(&swap_bytes[..])
            });

            // Deserialize and set the state
            match decode_swap_result {
                Err(err) => {
                    panic!(
                        "Error deserializing canister state post-upgrade. \
                 CANISTER HAS BROKEN STATE!!!!. Error: {:?}",
                        err
                    );
                }
                Ok(proto) => set_state(proto),
            }
        }
    }

    // Rebuild the indexes if needed. If the rebuilding process fails, panic so the upgrade
    // rolls back.
    swap().rebuild_indexes().unwrap_or_else(|err| {
        panic!(
            "Error rebuilding the Swap canister indexes. The stable memory has been exhausted: {}",
            err
        )
    });
}

/// Resources to serve for a given http_request
#[export_name = "canister_query http_request"]
fn http_request() {
    over(candid_one, serve_http)
}

/// Serve an HttpRequest made to this canister
pub fn serve_http(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        "/logs" => serve_logs_v2(request, &INFO, &ERROR),

        // These are obsolete.
        "/log/info" => serve_logs(&INFO),
        "/log/error" => serve_logs(&ERROR),

        _ => HttpResponseBuilder::not_found().build(),
    }
}

/// Encode the metrics in a format that can be understood by Prometheus.
fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "sale_stable_memory_pages",
        ic_nervous_system_common::stable_memory_num_pages() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "sale_stable_memory_bytes",
        ic_nervous_system_common::stable_memory_size_bytes() as f64,
        "Size of the stable memory allocated by this canister.",
    )?;
    w.encode_gauge(
        "sale_cycle_balance",
        dfn_core::api::canister_cycle_balance() as f64,
        "Cycle balance on the sale canister.",
    )?;
    w.encode_gauge(
        "sale_open_tickets_count",
        ic_sns_swap::memory::OPEN_TICKETS_MEMORY.with(|ts| ts.borrow().len()) as f64,
        "The number of open tickets on the sale canister.",
    )?;
    w.encode_gauge(
        "sale_buyer_count",
        ic_sns_swap::memory::BUYERS_LIST_INDEX.with(|bs| bs.borrow().len()) as f64,
        "The number of buyers on the sale canister.",
    )?;
    w.encode_gauge(
        "sale_cf_participants_count",
        swap().cf_participants.len() as f64,
        "The number of Community Fund participants in the sale",
    )?;
    w.encode_gauge(
        "sale_cf_neurons_count",
        swap().cf_neuron_count() as f64,
        "The number of Community Fund NNS Neurons in the sale",
    )?;
    w.encode_gauge(
        "sale_neuron_recipes_count",
        swap().neuron_recipes.len() as f64,
        "The current number of Neuron Recipes created by the sale",
    )?;
    w.encode_gauge(
        "sale_participant_total_icp_e8s",
        swap().current_total_participation_e8s() as f64,
        "The total amount of ICP contributed by direct investors and the Community Fund",
    )?;
    w.encode_gauge(
        "sale_direct_investor_total_icp_e8s",
        swap().current_direct_participation_e8s() as f64,
        "The total amount of ICP contributed by direct investors",
    )?;
    w.encode_gauge(
        "sale_cf_total_icp_e8s",
        swap().current_neurons_fund_participation_e8s() as f64,
        "The total amount of ICP contributed by the Community Fund",
    )?;

    Ok(())
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
    use ic_nervous_system_clients::{
        canister_status::{
            CanisterStatusResultFromManagementCanister, CanisterStatusResultV2, CanisterStatusType,
            DefiniteCanisterSettingsArgs, DefiniteCanisterSettingsFromManagementCanister,
        },
        management_canister_client::{
            MockManagementCanisterClient, MockManagementCanisterClientReply,
        },
    };

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

    #[tokio::test]
    async fn test_get_canister_status() {
        let expected_canister_status_result = CanisterStatusResultV2 {
            status: CanisterStatusType::Running,
            module_hash: Some(vec![0_u8]),
            settings: DefiniteCanisterSettingsArgs {
                controllers: vec![PrincipalId::new_user_test_id(0)],
                compute_allocation: candid::Nat::from(0_u32),
                memory_allocation: candid::Nat::from(0_u32),
                freezing_threshold: candid::Nat::from(0_u32),
            },
            memory_size: candid::Nat::from(0_u32),
            cycles: candid::Nat::from(0_u32),
            idle_cycles_burned_per_day: candid::Nat::from(0_u32),
        };

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister {
                    status: CanisterStatusType::Running,
                    module_hash: Some(vec![0_u8]),
                    memory_size: candid::Nat::from(0_u32),
                    settings: DefiniteCanisterSettingsFromManagementCanister {
                        controllers: vec![PrincipalId::new_user_test_id(0_u64)],
                        compute_allocation: candid::Nat::from(0_u32),
                        memory_allocation: candid::Nat::from(0_u32),
                        freezing_threshold: candid::Nat::from(0_u32),
                        reserved_cycles_limit: candid::Nat::from(0_u32),
                    },
                    cycles: candid::Nat::from(0_u32),
                    idle_cycles_burned_per_day: candid::Nat::from(0_u32),
                    reserved_cycles: candid::Nat::from(0_u32),
                },
            )),
        ]);

        let actual_canister_status_result =
            do_get_canister_status(CanisterId::from_u64(1), &management_canister_client).await;
        assert_eq!(
            actual_canister_status_result,
            expected_canister_status_result
        );
    }
}
