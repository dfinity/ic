// TODO: Jira ticket NNS1-3556
#![allow(static_mut_refs)]
#![allow(deprecated)]

use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_cdk::{api::time, caller, id, init, post_upgrade, pre_upgrade, query, update};
use ic_cdk_timers::TimerId;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_canisters::ledger::IcpLedgerCanister;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::CanisterStatusResultV2,
    management_canister_client::{ManagementCanisterClient, ManagementCanisterClientImpl},
};
use ic_nervous_system_common::{serve_logs, serve_logs_v2, serve_metrics};
use ic_nervous_system_proto::pb::v1::{
    GetTimersRequest, GetTimersResponse, ResetTimersRequest, ResetTimersResponse, Timers,
};
use ic_nervous_system_runtime::CdkRuntime;
use ic_sns_swap::{
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
        NotifyPaymentFailureResponse, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse, Swap,
    },
};
use ic_stable_structures::{Memory, writer::Writer};
use prost::Message;
use std::{
    cell::RefCell,
    str::FromStr,
    time::{Duration, SystemTime},
};

const RUN_PERIODIC_TASKS_INTERVAL: Duration = Duration::from_secs(60);

/// This guarantees that timers cannot be restarted more often than once every 10 intervals.
const RESET_TIMERS_COOL_DOWN_INTERVAL: Duration = Duration::from_secs(600);

// TODO(NNS1-1589): Unhack.
// use ic_sns_root::pb::v1::{SetDappControllersRequest, SetDappControllersResponse};

// =============================================================================
// ===               Global state of the canister                            ===
// =============================================================================

/// The global state of the this canister.
static mut SWAP: Option<Swap> = None;

thread_local! {
    static TIMER_ID: RefCell<Option<TimerId>> = RefCell::new(Default::default());
}

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

/// Returns caller as PrincipalId
fn caller_principal_id() -> PrincipalId {
    PrincipalId::from(caller())
}

/// This canister id
fn this_canister_id() -> CanisterId {
    // We know the CanisterId is always valid.
    CanisterId::unchecked_from_principal(PrincipalId::from(id()))
}

// =============================================================================
// ===               Canister's public interface                             ===
// =============================================================================

/// See `GetStateResponse`.
#[query]
fn get_state(_arg: GetStateRequest) -> GetStateResponse {
    swap().get_state()
}

/// Get the state of a buyer. This will return a `GetBuyerStateResponse`
/// with an optional `BuyerState` struct if the Swap Canister has
/// been successfully notified of a buyer's ICP transfer.
#[query]
fn get_buyer_state(request: GetBuyerStateRequest) -> GetBuyerStateResponse {
    log!(INFO, "get_buyer_state");
    swap().get_buyer_state(&request)
}

/// Get Params.
#[query]
fn get_sale_parameters(request: GetSaleParametersRequest) -> GetSaleParametersResponse {
    swap().get_sale_parameters(&request)
}

/// List Community Fund participants.
#[query]
fn list_community_fund_participants(
    request: ListCommunityFundParticipantsRequest,
) -> ListCommunityFundParticipantsResponse {
    log!(INFO, "list_community_fund_participants");
    swap().list_community_fund_participants(&request)
}

/// See `Swap.refresh_buyer_token_e8`.
#[update]
async fn refresh_buyer_tokens(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    log!(INFO, "refresh_buyer_tokens");
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller_principal_id()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
    };
    let icp_ledger = create_real_icp_ledger(swap().init_or_panic().icp_ledger_or_panic());
    match swap_mut()
        .refresh_buyer_token_e8s(p, arg.confirmation_text, this_canister_id(), &icp_ledger)
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
#[update]
async fn finalize_swap(_arg: FinalizeSwapRequest) -> FinalizeSwapResponse {
    log!(INFO, "finalize_swap");
    let mut clients = swap()
        .init_or_panic()
        .environment()
        .expect("unable to create canister clients");

    swap_mut().finalize(now_fn, &mut clients).await
}

#[update]
async fn error_refund_icp(request: ErrorRefundIcpRequest) -> ErrorRefundIcpResponse {
    let icp_ledger = create_real_icp_ledger(swap().init_or_panic().icp_ledger_or_panic());
    swap()
        .error_refund_icp(this_canister_id(), &request, &icp_ledger)
        .await
}

#[update]
async fn get_canister_status(_request: GetCanisterStatusRequest) -> CanisterStatusResultV2 {
    do_get_canister_status(
        this_canister_id(),
        &ManagementCanisterClientImpl::<CdkRuntime>::new(None),
    )
    .await
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
            panic!("Couldn't get canister_status of {canister_id}. Err: {err:#?}")
        })
}

/// Returns the total amount of ICP deposited by participants in the swap.
#[update]
async fn get_buyers_total(_request: GetBuyersTotalRequest) -> GetBuyersTotalResponse {
    swap().get_buyers_total()
}

#[query]
fn get_lifecycle(request: GetLifecycleRequest) -> GetLifecycleResponse {
    log!(INFO, "get_lifecycle");
    swap().get_lifecycle(&request)
}

#[query]
fn get_auto_finalization_status(
    request: GetAutoFinalizationStatusRequest,
) -> GetAutoFinalizationStatusResponse {
    log!(INFO, "get_auto_finalization_status");
    swap().get_auto_finalization_status(&request)
}

/// Returns the initialization data of the canister
#[query]
async fn get_init(request: GetInitRequest) -> GetInitResponse {
    log!(INFO, "get_init");
    swap().get_init(&request)
}

/// Return the current derived state of the Swap
#[query]
async fn get_derived_state(_request: GetDerivedStateRequest) -> GetDerivedStateResponse {
    log!(INFO, "get_derived_state");
    swap().derived_state().into()
}

#[query]
async fn get_open_ticket(request: GetOpenTicketRequest) -> GetOpenTicketResponse {
    log!(INFO, "get_open_ticket");
    swap().get_open_ticket(&request, caller_principal_id())
}

#[update]
async fn new_sale_ticket(request: NewSaleTicketRequest) -> NewSaleTicketResponse {
    log!(INFO, "new_sale_ticket");
    swap_mut().new_sale_ticket(&request, caller_principal_id(), time())
}

/// Lists direct participants in the Swap.
#[query]
async fn list_direct_participants(
    request: ListDirectParticipantsRequest,
) -> ListDirectParticipantsResponse {
    log!(INFO, "list_direct_participants");
    swap().list_direct_participants(request)
}

#[query]
fn list_sns_neuron_recipes(request: ListSnsNeuronRecipesRequest) -> ListSnsNeuronRecipesResponse {
    log!(INFO, "list_neuron_recipes");
    swap().list_sns_neuron_recipes(request)
}

#[update]
fn notify_payment_failure(_request: NotifyPaymentFailureRequest) -> NotifyPaymentFailureResponse {
    log!(INFO, "notify_payment_failure");
    swap_mut().notify_payment_failure(&caller_principal_id())
}

// =============================================================================
// ===               Canister helper & boilerplate methods                   ===
// =============================================================================

fn now_nanoseconds() -> u64 {
    if cfg!(target_arch = "wasm32") {
        time()
    } else {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get time since epoch")
            .as_nanos()
            .try_into()
            .expect("Failed to convert time to u64")
    }
}

fn now_seconds() -> u64 {
    Duration::from_nanos(now_nanoseconds()).as_secs()
}

/// Returns a real ledger stub that communicates with the specified
/// canister, which is assumed to be the ICP production ledger or a
/// canister that implements that same interface.
fn create_real_icp_ledger(id: CanisterId) -> IcpLedgerCanister<CdkRuntime> {
    IcpLedgerCanister::<CdkRuntime>::new(id)
}

async fn run_periodic_tasks() {
    if let Some(ref mut timers) = swap_mut().timers {
        timers.last_spawned_timestamp_seconds.replace(now_seconds());
    };

    swap_mut().run_periodic_tasks(now_fn).await;

    if !swap().requires_periodic_tasks() {
        if let Some(ref mut timers) = swap_mut().timers {
            timers.requires_periodic_tasks.replace(false);
        };
        TIMER_ID.with(|saved_timer_id| {
            let saved_timer_id = saved_timer_id.borrow();
            if let Some(saved_timer_id) = *saved_timer_id {
                ic_cdk_timers::clear_timer(saved_timer_id);
            }
        });
        log!(
            INFO,
            "All work that needs to be done in Swap's periodic tasks has been completed. \
             Stop scheduling new periodic tasks."
        );
    }
}

#[query]
fn get_timers(arg: GetTimersRequest) -> GetTimersResponse {
    let GetTimersRequest {} = arg;
    let timers = swap().timers;
    GetTimersResponse { timers }
}

fn init_timers() {
    let last_reset_timestamp_seconds = Some(now_seconds());
    let requires_periodic_tasks = swap().requires_periodic_tasks();

    swap_mut().timers.replace(Timers {
        requires_periodic_tasks: Some(requires_periodic_tasks),
        last_reset_timestamp_seconds,
        ..Default::default()
    });

    if requires_periodic_tasks {
        let new_timer_id = ic_cdk_timers::set_timer_interval(RUN_PERIODIC_TASKS_INTERVAL, || {
            ic_cdk::spawn(run_periodic_tasks())
        });
        TIMER_ID.with(|saved_timer_id| {
            let mut saved_timer_id = saved_timer_id.borrow_mut();
            if let Some(saved_timer_id) = *saved_timer_id {
                ic_cdk_timers::clear_timer(saved_timer_id);
            }
            saved_timer_id.replace(new_timer_id);
        });
    } else {
        log!(
            INFO,
            "Periodic tasks are not required for this Swap anymore."
        );
    }
}

#[update]
fn reset_timers(_request: ResetTimersRequest) -> ResetTimersResponse {
    let reset_timers_cool_down_interval_seconds = RESET_TIMERS_COOL_DOWN_INTERVAL.as_secs();

    if let Some(timers) = swap_mut().timers
        && let Some(last_reset_timestamp_seconds) = timers.last_reset_timestamp_seconds
        && now_seconds().saturating_sub(last_reset_timestamp_seconds)
            < reset_timers_cool_down_interval_seconds
    {
        panic!(
            "Reset has already been called within the past {reset_timers_cool_down_interval_seconds:?} seconds"
        );
    }

    init_timers();

    ResetTimersResponse {}
}

/// In contrast to canister_init(), this method does not do deserialization.
#[init]
fn canister_init(init_payload: Init) {
    let swap = Swap::new(init_payload);
    unsafe {
        assert!(
            SWAP.is_none(),
            "Trying to initialize an already initialized canister!",
        );
        SWAP = Some(swap);
    }
    init_timers();
    log!(INFO, "Initialized");
}

/// Serialize and write the state to stable memory so that it is
/// preserved during the upgrade and can be deserialized again in
/// `canister_post_upgrade`.
#[pre_upgrade]
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
#[post_upgrade]
fn canister_post_upgrade() {
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
                CANISTER HAS BROKEN STATE!!!!. Error: {err:?}"
            );
        }
        Ok(proto) => set_state(proto),
    }

    // Rebuild the indexes if needed. If the rebuilding process fails, panic so the upgrade
    // rolls back.
    swap().rebuild_indexes().unwrap_or_else(|err| {
        panic!(
            "Error rebuilding the Swap canister indexes. The stable memory has been exhausted: {err}"
        )
    });

    init_timers();
}

/// Serve an HttpRequest made to this canister
#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
pub fn http_request(request: HttpRequest) -> HttpResponse {
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
        ic_cdk::api::canister_balance() as f64,
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
    w.encode_gauge(
        "swap_auto_finalization_failed",
        if swap().has_auto_finalization_failed() {
            1.0
        } else {
            0.0
        },
        "Whether the auto-finalization has failed (1.0 if failed, 0.0 if succeeded or not attempted)",
    )?;

    Ok(())
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
