use std::collections::{btree_map::Entry, BTreeMap};
use std::convert::TryInto;
use std::sync::RwLock;
use std::time::{Duration, UNIX_EPOCH};

use candid::{candid_method, CandidType, Encode};
use cycles_minting_canister::*;
use dfn_candid::{candid_one, CandidOne};
use dfn_core::{
    api::{call_with_cleanup, caller, set_certified_data},
    over, over_async, over_init, stable, BytesS,
};
use dfn_protobuf::protobuf;
use ic_crypto_tree_hash::{
    flatmap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, WitnessGenerator,
    WitnessGeneratorImpl,
};
use ic_ic00_types::{CanisterIdRecord, CanisterSettingsArgs, CreateCanisterArgs, Method, IC_00};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
use ledger_canister::{
    AccountIdentifier, Block, BlockHeight, BlockRes, CyclesResponse, Memo, Operation, SendArgs,
    Subaccount, Tokens, TransactionNotification, DEFAULT_TRANSFER_FEE,
};
use on_wire::{FromWire, IntoWire, NewType};

use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use lazy_static::lazy_static;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::{Deserialize, Serialize};

// Makes expose_build_metadata! available.
#[macro_use]
extern crate ic_nervous_system_common;

mod limiter;

/// The past 30 days are used for the average ICP/XDR rate.
const NUM_DAYS_FOR_ICP_XDR_AVERAGE: usize = 30;
pub const LABEL_ICP_XDR_CONVERSION_RATE: &[u8] = b"ICP_XDR_CONVERSION_RATE";
pub const LABEL_AVERAGE_ICP_XDR_CONVERSION_RATE: &[u8] = b"AVERAGE_ICP_XDR_CONVERSION_RATE";

/// The maximum number of notification statuses to store.
const MAX_NOTIFY_HISTORY: usize = 1_000_000;
/// The maximum number of old notification statuses we purge in one go.
const MAX_NOTIFY_PURGE: usize = 100_000;

#[derive(Serialize, Deserialize, Clone, Debug, CandidType, Eq, PartialEq)]
enum NotificationStatus {
    /// We are waiting for a reply from ledger to complete the notification processing.
    Processing,
    /// The cached result of a completed canister top up.
    NotifiedTopUp(Result<Cycles, NotifyError>),
    /// The cached result of a completed canister creation.
    NotifiedCreateCanister(Result<CanisterId, NotifyError>),
}

#[derive(Serialize, Deserialize, Clone, CandidType, Eq, PartialEq, Debug)]
struct State {
    ledger_canister_id: CanisterId,

    governance_canister_id: CanisterId,

    /// Account used to burn funds.
    minting_account_id: Option<AccountIdentifier>,

    authorized_subnets: BTreeMap<PrincipalId, Vec<SubnetId>>,

    default_subnets: Vec<SubnetId>,

    /// How many XDR 1 ICP is worth, along with a timestamp.
    icp_xdr_conversion_rate: Option<IcpXdrConversionRate>,

    /// The average ICP/XDR rate over `NUM_DAYS_FOR_ICP_XDR_AVERAGE` days. The
    /// timestamp is the UNIX epoch time in seconds at the start of the last
    /// considered day, which should correspond to midnight of the current
    /// day.
    average_icp_xdr_conversion_rate: Option<IcpXdrConversionRate>,

    /// The recent ICP/XDR rates used to compute the average rate.
    recent_icp_xdr_rates: Option<Vec<IcpXdrConversionRate>>,

    /// How many cycles 1 XDR is worth.
    cycles_per_xdr: Cycles,

    /// How many cycles are allowed to be minted in an hour.
    cycles_limit: Cycles,

    /// Maintain a count of how many cycles have been minted in the last hour.
    limiter: limiter::Limiter,

    total_cycles_minted: Cycles,

    blocks_notified: Option<BTreeMap<BlockHeight, NotificationStatus>>,
    last_purged_notification: Option<BlockHeight>,
}

impl State {
    fn default() -> Self {
        let resolution = Duration::from_secs(60);
        let max_age = Duration::from_secs(60 * 60);

        Self {
            ledger_canister_id: CanisterId::ic_00(),
            governance_canister_id: CanisterId::ic_00(),
            minting_account_id: None,
            authorized_subnets: BTreeMap::new(),
            default_subnets: vec![],
            icp_xdr_conversion_rate: None,
            average_icp_xdr_conversion_rate: None,
            recent_icp_xdr_rates: Some(vec![
                IcpXdrConversionRate::default();
                NUM_DAYS_FOR_ICP_XDR_AVERAGE
            ]),
            cycles_per_xdr: DEFAULT_CYCLES_PER_XDR.into(),
            cycles_limit: 50_000_000_000_000_000u128.into(), // == 50 Pcycles/hour
            limiter: limiter::Limiter::new(resolution, max_age),
            total_cycles_minted: 0.into(),
            blocks_notified: Some(BTreeMap::new()),
            last_purged_notification: Some(0),
        }
    }

    fn encode(&self) -> Vec<u8> {
        candid::encode_one(&self).unwrap()
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        candid::decode_one(bytes)
            .map_err(|err| format!("Decoding cycles minting canister state failed: {}", err))
    }

    // Keep the size of blocks_notified map not larger than max_history.
    // Purges at most MAX_NOTIFY_PURGE entries.
    fn purge_old_notifications(&mut self, max_history: usize) {
        let mut last_purged = 0;
        let mut cnt = 0;
        // Remove elements from the beginning of self.blocks_notified until either
        // it is small enough, or MAX_NOTIFY_PURGE entries have been removed.
        while self.blocks_notified.as_ref().unwrap().len() > max_history && cnt < MAX_NOTIFY_PURGE {
            // pop_first is nightly only
            let block_height = *self
                .blocks_notified
                .as_ref()
                .unwrap()
                .iter()
                .next()
                .unwrap()
                .0;
            self.blocks_notified.as_mut().unwrap().remove(&block_height);
            last_purged = block_height;
            cnt += 1;
        }
        // make sure this grows monotonically (a delayed callback might have added older status)
        last_purged = last_purged.max(self.last_purged_notification.unwrap());
        self.last_purged_notification = Some(last_purged);
    }
}

lazy_static! {
    static ref STATE: RwLock<State> = RwLock::new(State::default());
}

// Helper to print messages in yellow
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::yellow(s).to_string());
}

#[export_name = "canister_init"]
fn main() {
    over_init(|CandidOne(args)| init(args))
}

fn init(args: CyclesCanisterInitPayload) {
    print(format!(
        "[cycles] init() with ledger canister {}, governance canister {} and minting account {}",
        args.ledger_canister_id,
        args.governance_canister_id,
        args.minting_account_id
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<none>".to_string())
    ));

    let mut state = STATE.write().unwrap();

    state.ledger_canister_id = args.ledger_canister_id;
    state.governance_canister_id = args.governance_canister_id;
    state.minting_account_id = args.minting_account_id;
    state.last_purged_notification = args.last_purged_notification;
}

expose_build_metadata! {}

#[export_name = "canister_update set_authorized_subnetwork_list"]
fn set_authorized_subnetwork_list_() {
    over(
        candid_one,
        |SetAuthorizedSubnetworkListArgs { who, subnets }| {
            set_authorized_subnetwork_list(who, subnets)
        },
    )
}

/// Set the list of subnets in which a principal is allowed to create
/// canisters. If `subnets` is empty, remove the mapping for a
/// principal. If `who` is None, set the default list of subnets.
fn set_authorized_subnetwork_list(who: Option<PrincipalId>, subnets: Vec<SubnetId>) {
    let mut state = STATE.write().unwrap();

    let governance_canister_id = state.governance_canister_id;

    if CanisterId::new(caller()) != Ok(governance_canister_id) {
        panic!("Only the governance canister can set authorized subnetwork lists.");
    }

    if let Some(who) = who {
        if subnets.is_empty() {
            print(format!("[cycles] removing subnet list for {}", who));
            state.authorized_subnets.remove(&who);
        } else {
            print(format!("[cycles] setting subnet list for {}", who));
            state.authorized_subnets.insert(who, subnets);
        }
    } else {
        print("[cycles] setting default subnet list");
        state.default_subnets = subnets;
    }
}

/// Constructs a hash tree that can be used to certify requests for the
/// conversion rate (both the current and the average, if they are set).
///
/// Tree structure:
///
/// ```text
/// *
/// |
/// +-- ICP_XDR_CONVERSION_RATE -- [ Candid encoded IcpXdrConversionRate ]
/// |
/// `-- AVERAGE_ICP_XDR_CONVERSION_RATE -- [ Candid encoded IcpXdrConversionRate ]
/// ```
fn convert_data_to_mixed_hash_tree(state: &State) -> WitnessGeneratorImpl {
    let mut b = HashTreeBuilderImpl::new();
    b.start_subtree();

    if let Some(icp_xdr_conversion_rate) = state.icp_xdr_conversion_rate.as_ref() {
        let icp_xdr_conversion_rate_buf = Encode!(icp_xdr_conversion_rate).unwrap();
        b.new_edge(Label::from(LABEL_ICP_XDR_CONVERSION_RATE));
        b.start_leaf();
        b.write_leaf(icp_xdr_conversion_rate_buf);
        b.finish_leaf();
    }

    if let Some(average_icp_xdr_conversion_rate) = state.average_icp_xdr_conversion_rate.as_ref() {
        let average_icp_xdr_conversion_rate_buf = Encode!(average_icp_xdr_conversion_rate).unwrap();
        b.new_edge(Label::from(LABEL_AVERAGE_ICP_XDR_CONVERSION_RATE));
        b.start_leaf();
        b.write_leaf(average_icp_xdr_conversion_rate_buf);
        b.finish_leaf();
    }

    b.finish_subtree();

    b.witness_generator()
        .expect("impossible: constructed unbalanced hash tree")
}

/// Returns a CBOR-encoded witness hashtree containing a single leaf with a
/// Candid-encoded IcpXdrConversionRate
fn convert_conversion_rate_to_payload(
    conversion_rate: &IcpXdrConversionRate,
    witness_generator: WitnessGeneratorImpl,
) -> Vec<u8> {
    let icp_xdr_conversion_rate_buf = Encode!(&conversion_rate).unwrap();

    let mixed_hash_tree = witness_generator
        .mixed_hash_tree(&LabeledTree::SubTree(flatmap!{
            Label::from(LABEL_ICP_XDR_CONVERSION_RATE) => LabeledTree::Leaf(icp_xdr_conversion_rate_buf)
        }))
        .expect("failed to produce a hash tree");

    let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
    serializer.self_describe().unwrap();
    mixed_hash_tree
        .serialize(&mut serializer)
        .unwrap_or_else(|e| {
            dfn_core::api::trap_with(&format!("failed to serialize a hash tree: {}", e))
        });

    serializer.into_inner()
}

/// Retrieves the current `xdr_permyriad_per_icp` as a certified response.
#[export_name = "canister_query get_icp_xdr_conversion_rate"]
fn get_icp_xdr_conversion_rate_() {
    let state = STATE.read().unwrap();

    let witness_generator = convert_data_to_mixed_hash_tree(&state);
    let icp_xdr_conversion_rate = state
        .icp_xdr_conversion_rate
        .as_ref()
        .expect("icp_xdr_conversion_rate is not set");

    let payload = convert_conversion_rate_to_payload(icp_xdr_conversion_rate, witness_generator);

    over(
        candid_one,
        |_: ()| -> IcpXdrConversionRateCertifiedResponse {
            IcpXdrConversionRateCertifiedResponse {
                data: icp_xdr_conversion_rate.clone(),
                hash_tree: payload,
                certificate: dfn_core::api::data_certificate().unwrap_or_default(),
            }
        },
    )
}

#[export_name = "canister_update set_icp_xdr_conversion_rate"]
fn set_icp_xdr_conversion_rate_() {
    let caller = caller();

    assert_eq!(
        caller,
        GOVERNANCE_CANISTER_ID.into(),
        "{} is not authorized to call this method: {}",
        caller,
        "set_icp_xdr_conversion_rate"
    );

    let mut state = STATE.write().unwrap();
    over(
        candid_one,
        |proposed_conversion_rate: UpdateIcpXdrConversionRatePayload| -> Result<(), String> {
            let rate: IcpXdrConversionRate = proposed_conversion_rate.into();
            update_recent_icp_xdr_rates(&rate, &mut state);
            set_icp_xdr_conversion_rate(rate, &mut state)
        },
    );
}

#[export_name = "canister_query get_average_icp_xdr_conversion_rate"]
fn get_average_icp_xdr_conversion_rate_() {
    let state = STATE.read().unwrap();

    let witness_generator = convert_data_to_mixed_hash_tree(&state);
    let average_icp_xdr_conversion_rate = state
        .average_icp_xdr_conversion_rate
        .as_ref()
        .expect("average_icp_xdr_conversion_rate is not set");

    let payload =
        convert_conversion_rate_to_payload(average_icp_xdr_conversion_rate, witness_generator);

    over(
        candid_one,
        |_: ()| -> IcpXdrConversionRateCertifiedResponse {
            IcpXdrConversionRateCertifiedResponse {
                data: average_icp_xdr_conversion_rate.clone(),
                hash_tree: payload,
                certificate: dfn_core::api::data_certificate().unwrap_or_default(),
            }
        },
    )
}

/// The function updates the vector of recent rates, which are used to compute
/// the average rate over `NUM_ICP_XDR_RATES_FOR_AVERAGE` days.
/// The first received rate for each day is stored, ideally with a timestamp
/// exactly at the start of the day.
fn update_recent_icp_xdr_rates(new_rate: &IcpXdrConversionRate, state: &mut State) {
    let day = new_rate.timestamp_seconds / 86_400;
    // The index is the day modulo `NUM_ICP_XDR_RATES_FOR_AVERAGE`.
    let index = (day as usize) % NUM_DAYS_FOR_ICP_XDR_AVERAGE;

    let recent_rates = state.recent_icp_xdr_rates.get_or_insert(vec![
        IcpXdrConversionRate::default(
        );
        NUM_DAYS_FOR_ICP_XDR_AVERAGE
    ]);
    // The record is updated if it is the first entry of a new day or an earlier
    // entry of the same day.
    let day_at_index = recent_rates[index].timestamp_seconds / 86_400;
    if day_at_index < day
        || (day_at_index == day
            && recent_rates[index].timestamp_seconds > new_rate.timestamp_seconds)
    {
        recent_rates[index] = new_rate.clone();
        // Update the average ICP/XDR rate.
        if let Ok(time) = dfn_core::api::now().duration_since(UNIX_EPOCH) {
            state.average_icp_xdr_conversion_rate =
                compute_average_icp_xdr_rate_at_time(recent_rates, time.as_secs());
        }
    }
}

/// The function returns the average ICP/XDR price over the past
/// NUM_ICP_XDR_RATES_FOR_AVERAGE` days. If there are no valid data points for
/// the time between the given UNIX epoch timestamp and
/// `NUM_DAYS_FOR_ICP_XDR_AVERAGE` in the past, 'None' is returned.
fn compute_average_icp_xdr_rate_at_time(
    recent_rates: &[IcpXdrConversionRate],
    time_s: u64,
) -> Option<IcpXdrConversionRate> {
    let day = time_s / 86_400;
    // Filter the rates based on valid days, i.e., days not before day
    // `current_day - NUM_ICP_XDR_RATES_FOR_AVERAGE` since the start of the epoch.
    let filtered_rates: Vec<u64> = recent_rates
        .iter()
        .filter(|rate| {
            (rate.timestamp_seconds / 86_400) > day - (NUM_DAYS_FOR_ICP_XDR_AVERAGE as u64)
        })
        .map(|rate| rate.xdr_permyriad_per_icp)
        .collect();
    let size = filtered_rates.len() as u64;
    // If there are rates that meet the age requirement, compute the sum and compute
    // the average.
    if size > 0 {
        let sum: u64 = filtered_rates.into_iter().sum();
        Some(IcpXdrConversionRate {
            timestamp_seconds: day * 86_400,   // Start of the current day.
            xdr_permyriad_per_icp: sum / size, // The average of the valid data points.
        })
    } else {
        None
    }
}

/// Validates the proposed conversion rate, sets it in state, and sets the
/// canister's certified data
fn set_icp_xdr_conversion_rate(
    proposed_conversion_rate: IcpXdrConversionRate,
    state: &mut State,
) -> Result<(), String> {
    print(format!(
        "[cycles] conversion rate update: {:?}",
        proposed_conversion_rate
    ));

    if proposed_conversion_rate.xdr_permyriad_per_icp == 0 {
        return Err("Proposed conversion rate must be greater than 0".to_string());
    }

    if let Some(current_conversion_rate) = state.icp_xdr_conversion_rate.as_ref() {
        if proposed_conversion_rate.timestamp_seconds <= current_conversion_rate.timestamp_seconds {
            return Err(
                "Proposed conversion rate must have greater timestamp than current one".to_string(),
            );
        }
    }

    state.icp_xdr_conversion_rate = Some(proposed_conversion_rate);

    let witness_generator = convert_data_to_mixed_hash_tree(state);
    set_certified_data(&witness_generator.hash_tree().digest().0[..]);

    Ok(())
}

#[export_name = "canister_update remove_subnet_from_authorized_subnet_list"]
fn remove_subnet_from_authorized_subnet_list_() {
    let caller = caller();
    assert_eq!(
        caller,
        REGISTRY_CANISTER_ID.into(),
        "{} is not authorized to call this method: {}",
        caller,
        "remove_subnet_from_authorized_subnet_list"
    );
    over(
        candid_one,
        |RemoveSubnetFromAuthorizedSubnetListArgs { subnet }| {
            remove_subnet_from_authorized_subnet_list(subnet)
        },
    )
}

fn remove_subnet_from_authorized_subnet_list(subnet_to_remove: SubnetId) {
    let mut state = STATE.write().unwrap();
    state
        .authorized_subnets
        .values_mut()
        .into_iter()
        .for_each(|subnet_list| subnet_list.retain(|subnet| *subnet != subnet_to_remove));
}

/// Wrapper around over_async_may_reject that requires the future to
/// be Send. Prevents us from holding a lock across .awaits.
pub fn over_async_may_reject<In, Out, F, Witness, Fut>(w: Witness, f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In::Inner) -> Fut + 'static,
    Fut: core::future::Future<Output = Result<Out::Inner, String>> + Send + 'static,
    Witness: FnOnce(Out, In::Inner) -> (Out::Inner, In),
{
    dfn_core::over_async_may_reject(w, f)
}

#[export_name = "canister_update transaction_notification_pb"]
fn transaction_notification_pb_() {
    over_async_may_reject(protobuf, transaction_notification)
}

#[export_name = "canister_update transaction_notification"]
fn transaction_notification_() {
    over_async_may_reject(candid_one, transaction_notification)
}

#[export_name = "canister_update notify_top_up"]
fn notify_top_up_() {
    over_async(candid_one, notify_top_up)
}

#[export_name = "canister_update notify_create_canister"]
fn notify_create_canister_() {
    over_async(candid_one, notify_create_canister)
}

fn is_transient_error<T>(result: &Result<T, NotifyError>) -> bool {
    if let Err(e) = result {
        return e.is_retriable();
    }
    false
}

/// Notify about top up
///
/// # Arguments
///
/// * `block_height` -  The height of the block you would like to send a
///   notification about.
/// * `canister_id` - Canister to be topped up.
#[candid_method(update, rename = "notify_top_up")]
async fn notify_top_up(
    NotifyTopUp {
        block_index,
        canister_id,
    }: NotifyTopUp,
) -> Result<Cycles, NotifyError> {
    let cmc_id = dfn_core::api::id();
    let sub = Subaccount::from(&canister_id);
    let expected_to = AccountIdentifier::new(cmc_id.get(), Some(sub));

    let (amount, from) = fetch_transaction(block_index, expected_to, MEMO_TOP_UP_CANISTER).await?;
    {
        let state: &mut State = &mut STATE.write().unwrap();
        state.purge_old_notifications(MAX_NOTIFY_HISTORY);

        if block_index <= state.last_purged_notification.unwrap() {
            return Err(NotifyError::TransactionTooOld(
                state.last_purged_notification.unwrap() + 1,
            ));
        }

        match state.blocks_notified.as_mut().unwrap().entry(block_index) {
            Entry::Occupied(entry) => match entry.get() {
                NotificationStatus::Processing => return Err(NotifyError::Processing),
                NotificationStatus::NotifiedTopUp(result) => return result.clone(),
                NotificationStatus::NotifiedCreateCanister(_) => {
                    return Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as create canister request".into(),
                    ));
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(NotificationStatus::Processing);
            }
        }
    }

    let result = process_top_up(canister_id, from, amount).await;

    let notified: &mut Option<BTreeMap<_, _>> = &mut STATE.write().unwrap().blocks_notified;
    notified.as_mut().unwrap().insert(
        block_index,
        NotificationStatus::NotifiedTopUp(result.clone()),
    );
    if is_transient_error(&result) {
        notified.as_mut().unwrap().remove(&block_index);
    }
    result
}

/// Notify about create canister transaction
///
/// # Arguments
///
/// * `block_height` -  The height of the block you would like to send a
///   notification about.
/// * `controller` - PrincipalId of the canister controller.
#[candid_method(update, rename = "notify_create_canister")]
async fn notify_create_canister(
    NotifyCreateCanister {
        block_index,
        controller,
    }: NotifyCreateCanister,
) -> Result<CanisterId, NotifyError> {
    let cmc_id = dfn_core::api::id();
    let sub = Subaccount::from(&controller);
    let expected_to = AccountIdentifier::new(cmc_id.get(), Some(sub));

    let (amount, from) = fetch_transaction(block_index, expected_to, MEMO_CREATE_CANISTER).await?;

    {
        let state: &mut State = &mut STATE.write().unwrap();
        state.purge_old_notifications(MAX_NOTIFY_HISTORY);

        if block_index <= state.last_purged_notification.unwrap() {
            return Err(NotifyError::TransactionTooOld(
                state.last_purged_notification.unwrap() + 1,
            ));
        }

        match state.blocks_notified.as_mut().unwrap().entry(block_index) {
            Entry::Occupied(entry) => match entry.get() {
                NotificationStatus::Processing => return Err(NotifyError::Processing),
                NotificationStatus::NotifiedCreateCanister(resp) => return resp.clone(),
                NotificationStatus::NotifiedTopUp(_) => {
                    return Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as a top up request.".into(),
                    ))
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(NotificationStatus::Processing);
            }
        }
    }

    let result = process_create_canister(controller, from, amount).await;

    let notified: &mut Option<BTreeMap<_, _>> = &mut STATE.write().unwrap().blocks_notified;
    notified.as_mut().unwrap().insert(
        block_index,
        NotificationStatus::NotifiedCreateCanister(result.clone()),
    );
    if is_transient_error(&result) {
        notified.as_mut().unwrap().remove(&block_index);
    }

    result
}

async fn query_block(
    block_index: BlockHeight,
    ledger_id: CanisterId,
) -> Result<Block, NotifyError> {
    fn failed_to_fetch_block(error_message: String) -> NotifyError {
        NotifyError::Other {
            error_code: NotifyErrorCode::FailedToFetchBlock as u64,
            error_message,
        }
    }
    let BlockRes(b) = call_with_cleanup(ledger_id, "block_pb", protobuf, block_index)
        .await
        .map_err(|e| failed_to_fetch_block(format!("Failed to fetch block: {}", e.1)))?;

    match b {
        None => {
            return Err(NotifyError::InvalidTransaction(format!(
                "Block {} not found",
                block_index
            )))
        }
        Some(Ok(block)) => block,
        Some(Err(canister_id)) => {
            let BlockRes(b) = call_with_cleanup(canister_id, "get_block_pb", protobuf, block_index)
                .await
                .map_err(|e| {
                    failed_to_fetch_block(format!(
                        "Failed to fetch block from {}: {}",
                        canister_id, e.1
                    ))
                })?;
            b.ok_or_else(|| {
                failed_to_fetch_block(format!(
                    "Block {} not found in archive {}",
                    block_index, canister_id
                ))
            })?
            .map_err(|redirect_canister_id| {
                failed_to_fetch_block(format!(
                    "Unexpected response from archive (redirected to {})",
                    redirect_canister_id
                ))
            })?
        }
    }
    .decode()
    .map_err(|e| failed_to_fetch_block(format!("Failed to decode block: {}", e)))
}

fn memo_to_intent_str(memo: Memo) -> String {
    match memo {
        MEMO_CREATE_CANISTER => "CreateCanister".into(),
        MEMO_TOP_UP_CANISTER => "TopUp".into(),
        _ => "unrecognized".into(),
    }
}

async fn fetch_transaction(
    block_height: BlockHeight,
    expected_to: AccountIdentifier,
    expected_memo: Memo,
) -> Result<(Tokens, AccountIdentifier), NotifyError> {
    let ledger_id = STATE.read().unwrap().ledger_canister_id;

    let block = query_block(block_height, ledger_id).await?;

    let (from, to, amount) = match block.transaction().operation {
        Operation::Transfer {
            from, to, amount, ..
        } => (from, to, amount),
        _ => {
            return Err(NotifyError::InvalidTransaction(
                "Notification transaction must be of type Transfer".into(),
            ))
        }
    };
    if to != expected_to {
        return Err(NotifyError::InvalidTransaction(format!(
            "Destination account in the block ({}) different than in the notification ({})",
            to, expected_to
        )));
    }
    let memo = block.transaction().memo;
    if memo != expected_memo {
        return Err(NotifyError::InvalidTransaction(format!(
            "Intent in the block ({} == {}) different than in the notification ({} == {})",
            memo.0,
            memo_to_intent_str(memo),
            expected_memo.0,
            memo_to_intent_str(expected_memo),
        )));
    }

    Ok((amount, from))
}

/// Processes a legacy notification from the Ledger canister.
async fn transaction_notification(tn: TransactionNotification) -> Result<CyclesResponse, String> {
    let caller = caller();

    print(format!(
        "[cycles] notified about transaction {:?} by {}",
        tn, caller
    ));

    let ledger_canister_id = STATE.read().unwrap().ledger_canister_id;

    if CanisterId::new(caller) != Ok(ledger_canister_id) {
        return Err(format!(
            "This canister can only be notified by the ledger canister ({}), not by {}.",
            ledger_canister_id, caller
        ));
    }

    // We need this check if MAX_NOTIFY_HISTORY is smaller than max number of transactions
    // the ledger can process within 24h
    if tn.block_height <= STATE.read().unwrap().last_purged_notification.unwrap() {
        return Err(NotifyError::TransactionTooOld(
            STATE.read().unwrap().last_purged_notification.unwrap() + 1,
        )
        .to_string());
    }

    let block_height = tn.block_height;
    match STATE
        .write()
        .unwrap()
        .blocks_notified
        .as_mut()
        .unwrap()
        .entry(block_height)
    {
        Entry::Occupied(entry) => match entry.get() {
            NotificationStatus::Processing => {
                return Err("Another notification is in progress".into())
            }
            NotificationStatus::NotifiedTopUp(resp) => {
                return Err(format!("Already notified: {:?}", resp))
            }
            NotificationStatus::NotifiedCreateCanister(resp) => {
                return Err(format!("Already notified: {:?}", resp))
            }
        },
        Entry::Vacant(entry) => {
            entry.insert(NotificationStatus::Processing);
        }
    }

    let from = AccountIdentifier::new(tn.from, tn.from_subaccount);

    let (cycles_response, notification_status) = if tn.memo == MEMO_CREATE_CANISTER {
        let controller = (&tn
            .to_subaccount
            .ok_or_else(|| "Reserving requires a principal.".to_string())?)
            .try_into()
            .map_err(|err| format!("Cannot parse subaccount: {}", err))?;
        match process_create_canister(controller, from, tn.amount).await {
            Ok(canister_id) => (
                Ok(CyclesResponse::CanisterCreated(canister_id)),
                Some(NotificationStatus::NotifiedCreateCanister(Ok(canister_id))),
            ),
            Err(NotifyError::Refunded {
                reason,
                block_index,
            }) => (
                Ok(CyclesResponse::Refunded(reason.clone(), block_index)),
                Some(NotificationStatus::NotifiedCreateCanister(Err(
                    NotifyError::Refunded {
                        reason,
                        block_index,
                    },
                ))),
            ),
            Err(e) => (Err(e), None),
        }
    } else if tn.memo == MEMO_TOP_UP_CANISTER {
        let canister_id = (&tn
            .to_subaccount
            .ok_or_else(|| "Topping up requires a subaccount.".to_string())?)
            .try_into()
            .map_err(|err| format!("Cannot parse subaccount: {}", err))?;
        match process_top_up(canister_id, from, tn.amount).await {
            Ok(cycles) => (
                Ok(CyclesResponse::ToppedUp(())),
                Some(NotificationStatus::NotifiedTopUp(Ok(cycles))),
            ),
            Err(NotifyError::Refunded {
                reason,
                block_index,
            }) => (
                Ok(CyclesResponse::Refunded(reason.clone(), block_index)),
                Some(NotificationStatus::NotifiedTopUp(Err(
                    NotifyError::Refunded {
                        reason,
                        block_index,
                    },
                ))),
            ),
            Err(e) => (Err(e), None),
        }
    } else {
        let err = NotifyError::InvalidTransaction(format!(
            "Do not know what to do with transaction with memo {}.",
            tn.memo.0
        ));
        (Err(err), None)
    };

    let notified: &mut Option<BTreeMap<_, _>> = &mut STATE.write().unwrap().blocks_notified;

    if let Some(status) = notification_status {
        notified.as_mut().unwrap().insert(block_height, status);
    }
    if is_transient_error(&cycles_response) {
        notified.as_mut().unwrap().remove(&block_height);
    }

    cycles_response.map_err(|e| e.to_string())
}

// If conversion fails, log and return an error
fn tokens_to_cycles(amount: Tokens) -> Result<Cycles, NotifyError> {
    let state = STATE.read().unwrap();
    let xdr_permyriad_per_icp = state
        .icp_xdr_conversion_rate
        .as_ref()
        .map(|rate| rate.xdr_permyriad_per_icp);
    match xdr_permyriad_per_icp {
        Some(xdr_permyriad_per_icp) => Ok(TokensToCycles {
            xdr_permyriad_per_icp,
            cycles_per_xdr: state.cycles_per_xdr,
        }
        .to_cycles(amount)),
        None => {
            let error_message = "No conversion rate found in CMC, notification aborted".to_string();
            print(&error_message);
            Err(NotifyError::Other {
                error_code: NotifyErrorCode::Internal as u64,
                error_message,
            })
        }
    }
}

async fn process_create_canister(
    controller: PrincipalId,
    from: AccountIdentifier,
    amount: Tokens,
) -> Result<CanisterId, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;

    let sub = Subaccount::from(&controller);

    print(format!(
        "Creating canister with controller {} with {} cycles.",
        controller, cycles,
    ));

    // Create the canister. If this fails, refund. Either way,
    // return a result so that the notification cannot be retried.
    // If refund fails, we allow to retry.
    match create_canister(controller, cycles).await {
        Ok(canister_id) => {
            burn_and_log(sub, amount).await;
            Ok(canister_id)
        }
        Err(err) => {
            let refund_block = refund(sub, from, amount, CREATE_CANISTER_REFUND_FEE).await?;
            Err(NotifyError::Refunded {
                reason: err,
                block_index: refund_block,
            })
        }
    }
}

async fn process_top_up(
    canister_id: CanisterId,
    from: AccountIdentifier,
    amount: Tokens,
) -> Result<Cycles, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;

    let sub = Subaccount::from(&canister_id);

    print(format!(
        "Topping up canister {} by {} cycles.",
        canister_id, cycles
    ));

    match deposit_cycles(canister_id, cycles).await {
        Ok(()) => {
            burn_and_log(sub, amount).await;
            Ok(cycles)
        }
        Err(err) => {
            let refund_block = refund(sub, from, amount, TOP_UP_CANISTER_REFUND_FEE).await?;
            Err(NotifyError::Refunded {
                reason: err.to_string(),
                block_index: refund_block,
            })
        }
    }
}

/// Attempt to burn the funds.
/// Burning doesn't return errors - we don't want to reject the transaction
/// notification because then it could be retried.
async fn burn_and_log(from_subaccount: Subaccount, amount: Tokens) {
    let msg = format!(
        "Burning of {} ICPTs from subaccount {}",
        amount, from_subaccount
    );
    let minting_account_id = STATE.read().unwrap().minting_account_id;
    if minting_account_id.is_none() {
        print(format!("{} failed: minting_account_id not set", msg));
        return;
    }
    let minting_account_id = minting_account_id.unwrap();
    let ledger_canister_id = STATE.read().unwrap().ledger_canister_id;

    if amount < DEFAULT_TRANSFER_FEE {
        print(format!("{}: amount too small ({})", msg, amount));
        return;
    }

    let send_args = SendArgs {
        memo: Memo::default(),
        amount,
        fee: Tokens::ZERO,
        from_subaccount: Some(from_subaccount),
        to: minting_account_id,
        created_at_time: None,
    };
    let res: Result<BlockHeight, (Option<i32>, String)> =
        call_with_cleanup(ledger_canister_id, "send_pb", protobuf, send_args).await;

    match res {
        Ok(block) => print(format!("{} done in block {}.", msg, block)),
        Err((code, err)) => {
            let code = code.unwrap_or_default();
            print(format!("{} failed with code {}: {:?}", msg, code, err))
        }
    }
}

/// Send the funds for canister creation or top up back to the sender,
/// minus the transaction fee (which is gone) and the fee for the
/// action (which is burned). Returns the index of the block in which
/// the refund was done.
async fn refund(
    from_subaccount: Subaccount,
    to: AccountIdentifier,
    amount: Tokens,
    extra_fee: Tokens,
) -> Result<Option<BlockHeight>, NotifyError> {
    let ledger_canister_id = STATE.read().unwrap().ledger_canister_id;
    let mut refund_block_index = None;

    let mut burned = amount;
    let mut refunded = Tokens::ZERO;
    if let Ok(to_refund) = (amount - DEFAULT_TRANSFER_FEE).and_then(|x| x - extra_fee) {
        if to_refund > Tokens::ZERO {
            burned = extra_fee;
            refunded = to_refund;
        }
    }

    if refunded > Tokens::ZERO {
        let send_args = SendArgs {
            memo: Memo::default(),
            amount: refunded,
            fee: DEFAULT_TRANSFER_FEE,
            from_subaccount: Some(from_subaccount),
            to,
            created_at_time: None,
        };
        let send_res: Result<BlockHeight, (Option<i32>, String)> =
            call_with_cleanup(ledger_canister_id, "send_pb", protobuf, send_args).await;
        let block = send_res.map_err(|(code, err)| {
            let code = code.unwrap_or_default();
            NotifyError::Other {
                error_code: NotifyErrorCode::RefundFailed as u64,
                error_message: format!("Refund to {} failed with code {}: {}", to, code, err),
            }
        })?;

        print(format!("Refund to {} done in block {}.", to, block));

        refund_block_index = Some(block);
    }

    if burned > Tokens::ZERO {
        burn_and_log(from_subaccount, burned).await;
    }

    Ok(refund_block_index)
}

async fn deposit_cycles(canister_id: CanisterId, cycles: Cycles) -> Result<(), String> {
    ensure_balance(cycles)?;

    let res: Result<(), (Option<i32>, String)> = dfn_core::api::call_with_funds_and_cleanup(
        IC_00,
        &Method::DepositCycles.to_string(),
        dfn_candid::candid_multi_arity,
        (CanisterIdRecord::from(canister_id),),
        dfn_core::api::Funds::new(cycles.into()),
    )
    .await;

    res.map_err(|(code, msg)| {
        format!(
            "Depositing cycles failed with code {}: {:?}",
            code.unwrap_or_default(),
            msg
        )
    })?;

    Ok(())
}

async fn create_canister(controller_id: PrincipalId, cycles: Cycles) -> Result<CanisterId, String> {
    let subnets = get_permuted_subnets_for(&controller_id).await?;

    let mut last_err = None;

    if !subnets.is_empty() {
        // TODO(NNS1-503): If CreateCanister fails, then we still have minted
        // these cycles.
        ensure_balance(cycles)?;
    }

    for subnet_id in subnets {
        let result: Result<CanisterIdRecord, _> = dfn_core::api::call_with_funds_and_cleanup(
            subnet_id.into(),
            &Method::CreateCanister.to_string(),
            dfn_candid::candid_one,
            CreateCanisterArgs {
                settings: Some(CanisterSettingsArgs {
                    controller: Some(controller_id),
                    ..CanisterSettingsArgs::default()
                }),
            },
            dfn_core::api::Funds::new(cycles.get().try_into().unwrap()),
        )
        .await;

        let canister_id = match result {
            Ok(canister_id) => canister_id.get_canister_id(),
            Err((code, msg)) => {
                let err = format!(
                    "Creating canister in subnet {} failed with code {}: {}",
                    subnet_id,
                    code.unwrap_or_default(),
                    msg
                );
                print(format!("[cycles] {}", err));
                last_err = Some(err);
                continue;
            }
        };

        print(format!(
            "[cycles] created canister {} in subnet {}",
            canister_id, subnet_id
        ));

        return Ok(canister_id);
    }

    Err(last_err.unwrap_or_else(|| "No subnets in which to create a canister.".to_owned()))
}

fn ensure_balance(cycles: Cycles) -> Result<(), String> {
    let now = dfn_core::api::now();

    {
        let mut state = STATE.write().unwrap();
        state.limiter.purge_old(now);
        let count = state.limiter.get_count();
        if count + cycles > state.cycles_limit {
            return Err(format!(
                "More than {} cycles have been minted in the last {} seconds, please try again later.",
                state.cycles_limit,
                state.limiter.get_max_age().as_secs(),
            ));
        }
        state.limiter.add(now, cycles);
        state.total_cycles_minted += cycles;
    }

    dfn_core::api::mint_cycles(
        cycles
            .get()
            .try_into()
            .map_err(|_| "Cycles u64 overflow".to_owned())?,
    );
    assert!(u128::from(dfn_core::api::canister_cycle_balance()) >= cycles.get());
    Ok(())
}

#[export_name = "canister_query total_cycles_minted"]
fn total_supply_() {
    over(protobuf, |_: ()| -> u64 {
        STATE
            .read()
            .unwrap()
            .total_cycles_minted
            .get()
            .try_into()
            .unwrap()
    })
}

/// Return the list of subnets in which this controller is allowed to create
/// canisters
async fn get_permuted_subnets_for(controller_id: &PrincipalId) -> Result<Vec<SubnetId>, String> {
    let mut subnets = {
        let state = STATE.read().unwrap();
        if let Some(subnets) = state.authorized_subnets.get(controller_id) {
            subnets.clone()
        } else {
            state.default_subnets.clone()
        }
    };

    let mut rng = get_rng().await?;
    subnets.shuffle(&mut rng);

    Ok(subnets)
}

async fn get_rng() -> Result<StdRng, String> {
    let res: Result<Vec<u8>, (Option<i32>, String)> = dfn_core::api::call_with_cleanup(
        IC_00,
        &Method::RawRand.to_string(),
        dfn_candid::candid_one,
        (),
    )
    .await;

    let bytes = res.map_err(|(code, msg)| {
        format!(
            "Getting random bytes failed with code {}: {:?}",
            code.unwrap_or_default(),
            msg
        )
    })?;

    Ok(StdRng::from_seed(bytes[0..32].try_into().unwrap()))
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    let bytes = &STATE
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .encode();
    print(format!(
        "[cycles] serialized state prior to upgrade ({} bytes)",
        bytes.len(),
    ));
    stable::set(bytes);
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let bytes = stable::get();
        print(format!(
            "[cycles] deserializing state after upgrade ({} bytes)",
            bytes.len(),
        ));

        *STATE.write().unwrap() = State::decode(&bytes).unwrap();
    })
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let state = STATE.read().unwrap();
    w.encode_gauge(
        "cmc_last_purged_notification",
        state.last_purged_notification.unwrap() as f64,
        "Block index of the last purged notification.",
    )?;
    w.encode_gauge(
        "cmc_blocks_notified_count",
        state.blocks_notified.as_ref().unwrap().len() as f64,
        "Number of notifications stored in the cache.",
    )?;
    w.encode_gauge(
        "cmc_icp_xdr_conversion_rate",
        state
            .icp_xdr_conversion_rate
            .as_ref()
            .unwrap()
            .xdr_permyriad_per_icp as f64
            / 10_000f64,
        "Amount of XDR corresponding to 1 ICP.",
    )?;
    w.encode_gauge(
        "cmc_cycles_per_xdr",
        state.cycles_per_xdr.get() as f64,
        "Number of cycles corresponding to 1 XDR.",
    )?;
    w.encode_counter(
        "cmc_cycles_minted_total",
        state.total_cycles_minted.get() as f64,
        "Number of cycles minted since the Genesis.",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_state_encode() {
        let mut state = State::default();
        state.minting_account_id = Some(AccountIdentifier::new(
            PrincipalId::new_user_test_id(1),
            None,
        ));
        state.authorized_subnets.insert(
            PrincipalId::new_user_test_id(2),
            vec![SubnetId::from(PrincipalId::new_subnet_test_id(3))],
        );
        state.default_subnets = vec![SubnetId::from(PrincipalId::new_subnet_test_id(123))];
        state.total_cycles_minted = 1234.into();
        state.last_purged_notification = Some(33);
        let mut blocks_notified = BTreeMap::new();
        for i in 50..60 {
            blocks_notified.insert(
                i,
                NotificationStatus::NotifiedTopUp(Ok(Cycles::new(i as u128))),
            );
        }
        blocks_notified.insert(
            60,
            NotificationStatus::NotifiedCreateCanister(Ok(CanisterId::new(
                PrincipalId::new_user_test_id(4),
            )
            .unwrap())),
        );
        state.blocks_notified = Some(blocks_notified);

        let bytes = state.encode();

        let state2 = State::decode(&bytes).unwrap();

        assert_eq!(state, state2);
    }

    #[test]
    fn test_purge_notifications() {
        fn block_index_to_cycles(block_index: BlockHeight) -> Cycles {
            Cycles::new(block_index as u128)
        }
        let mut state = State::default();
        state.last_purged_notification = Some(0);
        let initial_number_of_notifications = 100;
        let mut blocks_notified = BTreeMap::new();
        for i in 0..initial_number_of_notifications {
            blocks_notified.insert(
                i,
                NotificationStatus::NotifiedTopUp(Ok(block_index_to_cycles(i))),
            );
        }
        state.blocks_notified = Some(blocks_notified);

        let target_history_len = 30;
        state.purge_old_notifications(target_history_len);
        let most_recent_transaction_index = initial_number_of_notifications - 1;
        let expected_oldest_transaction_index =
            initial_number_of_notifications - target_history_len as u64;
        let expected_last_purged = expected_oldest_transaction_index - 1;
        assert_eq!(state.last_purged_notification, Some(expected_last_purged));
        assert_eq!(
            state
                .blocks_notified
                .as_ref()
                .unwrap()
                .get(&expected_last_purged),
            None
        );
        assert_eq!(
            state
                .blocks_notified
                .as_ref()
                .unwrap()
                .get(&expected_oldest_transaction_index),
            Some(&NotificationStatus::NotifiedTopUp(Ok(
                block_index_to_cycles(expected_oldest_transaction_index)
            )))
        );
        assert_eq!(
            state
                .blocks_notified
                .as_ref()
                .unwrap()
                .get(&most_recent_transaction_index),
            Some(&NotificationStatus::NotifiedTopUp(Ok(
                block_index_to_cycles(most_recent_transaction_index)
            )))
        );
    }

    #[test]
    // The function tests if the average ICP/XDR price is computed correctly.
    fn test_average_icp_xdr_price() {
        let mut state = State::default();
        // Set a timestamp.
        let timestamp: u64 = 1_632_728_342;
        // Define some rates that will be used in the test.
        let rates = vec![
            IcpXdrConversionRate {
                timestamp_seconds: timestamp, // The record at this time should be ignored
                xdr_permyriad_per_icp: 1_010_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: 1_632_700_800, // Midnight
                xdr_permyriad_per_icp: 1_000_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: 1_632_614_400, // Midnight, previous day
                xdr_permyriad_per_icp: 1_110_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: 1_632_614_399, /* One minute before midnight, previous day
                                                   * (ignored) */
                xdr_permyriad_per_icp: 1_510_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: 1_632_528_060, // 1 minute after midnight, two days before
                xdr_permyriad_per_icp: 1_520_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: 1_632_355_200, // Midnight, four days before.
                xdr_permyriad_per_icp: 880_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: (1_632_700_800 - (NUM_DAYS_FOR_ICP_XDR_AVERAGE - 1) * 86_400)
                    as u64,
                xdr_permyriad_per_icp: 1_090_000,
            },
            IcpXdrConversionRate {
                // This record is too old and should be ignored.
                timestamp_seconds: (1_632_700_800 - NUM_DAYS_FOR_ICP_XDR_AVERAGE * 86_400) as u64,
                xdr_permyriad_per_icp: 1_500_000,
            },
        ];
        // The average of the chosen rates.
        let chosen_rates_sum: u64 = 1_000_000 + 1_110_000 + 1_520_000 + 880_000 + 1_090_000;
        let average_rate = IcpXdrConversionRate {
            timestamp_seconds: 1_632_700_800,
            xdr_permyriad_per_icp: chosen_rates_sum / 5,
        };
        // The state is updated with all rates in reverse order (oldest to newest).
        for rate in rates.iter().rev() {
            update_recent_icp_xdr_rates(rate, &mut state);
        }
        let recent_rates = state.recent_icp_xdr_rates.unwrap_or_default();
        let computed_average_rate =
            compute_average_icp_xdr_rate_at_time(&recent_rates, timestamp).unwrap();
        // Assert that the rates are identical.
        assert_eq!(average_rate, computed_average_rate);
    }

    #[test]
    // The function tests if the average ICP/XDR price is computed correctly for
    // random input.
    fn test_random_average_icp_xdr_price() {
        let mut state = State::default();
        // Set a timestamp.
        let timestamp: u64 = 1_632_728_342;
        // Get a random number generator.
        let mut rng = rand::thread_rng();
        // The sum of all the valid rates, i.e., the rates at midnight.
        let mut valid_rates_sum = 0;
        // Iterate over two intervals (half of which should be ignored), from the oldest
        // to the latest rate.
        for day in (0..2 * NUM_DAYS_FOR_ICP_XDR_AVERAGE).rev() {
            // Generate a valid rate, i.e., the ICP/XDR rate at midnight.
            let valid_rate: u64 = rng.gen_range(1_000_000, 10_000_000);
            // The rate is only counted if it is not older than
            // `NUM_DAYS_FOR_ICP_XDR_AVERAGE` days.
            if day < NUM_DAYS_FOR_ICP_XDR_AVERAGE {
                valid_rates_sum += valid_rate;
            }
            // Add a rate one second before midnight (this rate will be ignored).
            update_recent_icp_xdr_rates(
                &IcpXdrConversionRate {
                    timestamp_seconds: ((1_632_700_800 - day * 86_400) - 1) as u64,
                    xdr_permyriad_per_icp: rng.gen_range(1_000_000, 10_000_000),
                },
                &mut state,
            );
            // Add a rate at midnight.
            update_recent_icp_xdr_rates(
                &IcpXdrConversionRate {
                    timestamp_seconds: (1_632_700_800 - day * 86_400) as u64,
                    xdr_permyriad_per_icp: valid_rate,
                },
                &mut state,
            );
            // Add a rate one second after midnight (this rate will be ignored).
            update_recent_icp_xdr_rates(
                &IcpXdrConversionRate {
                    timestamp_seconds: ((1_632_700_800 - day * 86_400) + 1) as u64,
                    xdr_permyriad_per_icp: rng.gen_range(1_000_000, 10_000_000),
                },
                &mut state,
            );
        }
        // Get the average of the valid ICP/XDR rates in the last
        // `NUM_DAYS_FOR_ICP_XDR_AVERAGE` days.
        let average_rate = IcpXdrConversionRate {
            timestamp_seconds: (timestamp / 86_400) * 86_400,
            xdr_permyriad_per_icp: valid_rates_sum / (NUM_DAYS_FOR_ICP_XDR_AVERAGE as u64),
        };
        let recent_rates = state.recent_icp_xdr_rates.unwrap_or_default();
        let computed_average_rate =
            compute_average_icp_xdr_rate_at_time(&recent_rates, timestamp).unwrap();
        // Assert that the rates are identical.
        assert_eq!(average_rate, computed_average_rate);
    }

    #[test]
    fn test_candid_interface_compatibility() {
        use candid::utils::{service_compatible, CandidSource};
        use std::path::PathBuf;

        candid::export_service!();
        let new_interface = __export_service();

        let old_interface =
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("cmc.did");

        service_compatible(
            CandidSource::Text(&new_interface),
            CandidSource::File(old_interface.as_path()),
        )
        .expect("The CMC canister interface is not compatible with the cmc.did file");
    }
}
