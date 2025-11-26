#![allow(deprecated)]
use candid::{CandidType, Encode, Nat};
use core::cmp::Ordering;
use cycles_minting_canister::*;
use environment::Environment;
use exchange_rate_canister::{
    RealExchangeRateCanisterClient, UpdateExchangeRateError, UpdateExchangeRateState,
};
use ic_cdk::{
    api::call::{CallResult, ManualReply},
    heartbeat, init, post_upgrade, pre_upgrade, println, query, update,
};
use ic_crypto_tree_hash::{
    HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, WitnessGenerator,
    WitnessGeneratorImpl, flatmap,
};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_ledger_core::{block::BlockType, tokens::CheckedSub};
use ic_management_canister_types_private::{
    BoundedVec, CanisterIdRecord, CanisterSettingsArgs, CanisterSettingsArgsBuilder,
    CreateCanisterArgs, IC_00, Method,
};
use ic_nervous_system_common::{
    NNS_DAPP_BACKEND_CANISTER_ID, ONE_HOUR_SECONDS, ONE_MONTH_SECONDS, serve_metrics,
};
use ic_nervous_system_governance::maturity_modulation::{
    MAX_MATURITY_MODULATION_PERMYRIAD, MIN_MATURITY_MODULATION_PERMYRIAD,
};
use ic_nervous_system_time_helpers::now_seconds;
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, ICP_LEDGER_ARCHIVE_1_CANISTER_ID, REGISTRY_CANISTER_ID,
    SUBNET_RENTAL_CANISTER_ID,
};
use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
use icp_ledger::{
    AccountIdentifier, Block, BlockIndex, BlockRes, DEFAULT_TRANSFER_FEE, Memo, Operation,
    SendArgs, Subaccount, Tokens, Transaction,
};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    convert::TryInto,
    thread::LocalKey,
    time::{Duration, SystemTime},
};

mod environment;
mod exchange_rate_canister;
mod limiter;
mod stable_utils;

/// The past 30 days are used for the average ICP/XDR rate.
const NUM_DAYS_FOR_ICP_XDR_AVERAGE: usize = 30;
/// The ICP/XDR start-of-day conversion rate of the past 60 days is cached.
const ICP_XDR_CONVERSION_RATE_CACHE_SIZE: usize = 60;
pub const LABEL_ICP_XDR_CONVERSION_RATE: &[u8] = b"ICP_XDR_CONVERSION_RATE";
pub const LABEL_AVERAGE_ICP_XDR_CONVERSION_RATE: &[u8] = b"AVERAGE_ICP_XDR_CONVERSION_RATE";

const ONE_MINUTE_SECONDS: u64 = 60;

/// The maximum number of notification statuses to store.
const MAX_NOTIFY_HISTORY: usize = 1_000_000;
/// The maximum number of old notification statuses we purge in one go.
const MAX_NOTIFY_PURGE: usize = 100_000;
/// The maximum memo length.
const MAX_MEMO_LENGTH: usize = 32;

/// Calls to create_canister get rejected outright if they have obviously too few cycles attached.
/// This is the minimum amount needed for creating a canister as of October 2023.
const CREATE_CANISTER_MIN_CYCLES: u64 = 100_000_000_000;

/// Prior to 2024-12-10, we used 50e15, but legitimate users started running
/// into this. At that time, prices had recently gone up, so we resolved to
/// increase this by 3x.
const DEFAULT_CYCLES_LIMIT: u128 = 150e15 as u128;

/// The limit for the number of cycles that can be minted by the Subnet Rental Canister in a month.
const SUBNET_RENTAL_DEFAULT_CYCLES_LIMIT: u128 = 500e15 as u128;

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static LIMITER_REJECT_COUNT: Cell<u64> = const { Cell::new(0_u64) };
}

fn with_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|cell| f(cell.borrow().as_ref().expect("cmc state not initialized")))
}

fn with_state_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|cell| {
        f(cell
            .borrow_mut()
            .as_mut()
            .expect("cmc state not initialized"))
    })
}

fn read_state<R>(
    safe_state: &'static LocalKey<RefCell<Option<State>>>,
    f: impl FnOnce(&State) -> R,
) -> R {
    safe_state.with(|cell| f(cell.borrow().as_ref().expect("cmc state not initialized")))
}

fn mutate_state<R>(
    safe_state: &'static LocalKey<RefCell<Option<State>>>,
    f: impl FnOnce(&mut State) -> R,
) -> R {
    safe_state.with(|cell| {
        f(cell
            .borrow_mut()
            .as_mut()
            .expect("cmc state not initialized"))
    })
}

pub struct CanisterEnvironment;

impl Environment for CanisterEnvironment {
    fn now_timestamp_seconds(&self) -> u64 {
        now_seconds()
    }

    fn set_certified_data(&self, data: &[u8]) {
        ic_cdk::api::set_certified_data(data)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum NotificationStatus {
    /// We are waiting for a reply from ledger to complete the notification processing.
    Processing,
    /// The cached result of a completed canister top up.
    NotifiedTopUp(Result<Cycles, NotifyError>),
    /// The cached result of a completed canister creation.
    NotifiedCreateCanister(Result<CanisterId, NotifyError>),
    /// The cached result of a completed cycles mint.
    NotifiedMint(NotifyMintCyclesResult),
    /// The transaction did not have a supported memo (or icrc1_memo).
    /// Therefore, we decided to send the ICP back to its source (minus fee).
    NotMeaningfulMemo(NotMeaningfulMemo),
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct NotMeaningfulMemo {
    refund_block_index: Option<BlockIndex>,
}

/// Version of the State type.
///
/// Each generation of the State type has an associated version.
/// The version of the State type currently stored in stable storage
/// is also stored in stable storage as a candid encoded number
/// just before the candid encoded State value itself.
///
/// Let
///   v         = version of the current (expected) State
///   State     = current State type
///   StateVn   = State type of version n
///   v_s       = version stored in stable storage, the next argument in stable storage
///               should then contain the candid encoded StateVv_s
///
/// If v = v_s + 1 then decode the stable storage as StateVv_s and migrate it to State
/// If v = v_s     then decode the stable storage as State
/// If v = v_s - 1 then it means a rollback probably happened because the stored version
///                is one bigger than the expected version.
///                To be safe we don't support this and will panic.
///                Instead a hotfix should be performed.
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, CandidType, Deserialize, Serialize,
)]
struct StateVersion(u64);

/// Current state type.
///
/// IMPORTANT: when changing the state type in a backwards incompatible way make sure to:
///
/// * Introduce a new StateV(n+1) type where n is the version of the current State type.
///
/// * Set the State type alias to StateV(n+1).
///
/// * Introduce a migration function from StateVn -> StateV(n+1).
///
/// * Perform this migration in State::decode(...).
///
/// * Optionally remove older State types (StateVm where m < n)
///   because they are no longer needed.
type State = StateV2;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct StateV2 {
    pub ledger_canister_id: CanisterId,

    pub governance_canister_id: CanisterId,

    /// An ID that provides an interface to a canister that provides exchange
    /// rate information such as the [XRC](https://github.com/dfinity/exchange-rate-canister).
    pub exchange_rate_canister_id: Option<CanisterId>,

    pub cycles_ledger_canister_id: Option<CanisterId>,

    /// Account used to burn funds.
    pub minting_account_id: Option<AccountIdentifier>,

    pub authorized_subnets: BTreeMap<PrincipalId, Vec<SubnetId>>,

    pub default_subnets: Vec<SubnetId>,

    /// How many XDR 1 ICP is worth, along with a timestamp.
    pub icp_xdr_conversion_rate: Option<IcpXdrConversionRate>,

    /// The average ICP/XDR rate over `NUM_DAYS_FOR_ICP_XDR_AVERAGE` days. The
    /// timestamp is the UNIX epoch time in seconds at the start of the last
    /// considered day, which should correspond to midnight of the current
    /// day.
    pub average_icp_xdr_conversion_rate: Option<IcpXdrConversionRate>,

    /// The recent ICP/XDR rates used to compute the average rate.
    pub recent_icp_xdr_rates: Option<Vec<IcpXdrConversionRate>>,

    /// How many cycles 1 XDR is worth.
    pub cycles_per_xdr: Cycles,

    /// How many cycles are allowed to be minted in an hour.
    pub base_cycles_limit: Cycles,

    /// How many cycles are allowed to be minted by the Subnet Rental Canister in a month.
    pub subnet_rental_cycles_limit: Cycles,

    /// Maintain a count of how many cycles have been minted in the last hour.
    pub base_limiter: limiter::Limiter,

    /// Maintain a count of how many cycles have been minted by the Subnet Rental Canister
    /// in the last month.
    pub subnet_rental_canister_limiter: limiter::Limiter,

    pub total_cycles_minted: Cycles,

    // We use this for synchronization.
    //
    // Because our operations (e.g. minting cycles) require calling other
    // canister(s), in particular ledger, it is possible for duplicate requests
    // to interleave. In such cases, we want subsequent operations to see that
    // an operation is already in flight. Therefore, before making any canister
    // calls, we check that the block does not already have a status. If it
    // already has a status, do not proceed. If it dos not already have a
    // status, set it to Processing. Then, we can proceed with calling the other
    // canister (i.e. ledger). Once that comes back, we update the block's
    // status. This avoids using the same ICP to perform multiple operations.
    pub blocks_notified: BTreeMap<BlockIndex, NotificationStatus>,
    // The status of blocks not new than this is ambiguous. This is because we
    // must bound how much memory we use; in particular, blocks_notified must
    // not grow without bound.
    pub last_purged_notification: BlockIndex,

    /// The current maturity modulation in basis points (permyriad), i.e.,
    /// a value of 123 corresponds to 1.23%.
    pub maturity_modulation_permyriad: Option<i32>,

    /// Maintains the mapping of subnet types to subnet ids. Users can choose to
    /// deploy their canisters on subnets with specific characteristics by
    /// selecting one of these types.
    ///
    ///
    /// These user facing subnet types capture common useful characteristics of
    /// the subnets and should not be confused with the existing concept of
    /// subnet types that exists in the registry (system/verified/application).
    /// The idea is that these types provide an easy way for users to set their
    /// preferences during canister creation. If no subnet type is provided
    /// during canister creation, a subnet without a special type will be picked
    /// at random as no special requirements were provided.
    ///
    /// Each subnet can be assigned to at most one type and cannot be a default
    /// or an authorized subnet.
    pub subnet_types_to_subnets: Option<BTreeMap<String, BTreeSet<SubnetId>>>,

    /// This is used to ensure that only one exchange rate update is being performed at a time from heartbeat.
    pub update_exchange_rate_canister_state: Option<UpdateExchangeRateState>,
}

impl StateV2 {
    fn state_version() -> StateVersion {
        StateVersion(2)
    }
}

impl State {
    fn encode(&self) -> Vec<u8> {
        Encode!(&Self::state_version(), &self).unwrap()
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut deserializer = candid::de::IDLDeserialize::new(bytes).unwrap();
        let stored_state_version: StateVersion =
            deserializer.get_value().expect("state version is missing");
        let current_state_version: StateVersion = Self::state_version();

        match stored_state_version.cmp(&current_state_version) {
            Ordering::Greater => {
                return Err(format!(
                    "[cycles] ERROR: stored state version {stored_state_version:?} is greater than the current state \
                     version {current_state_version:?}!  This likely means a rollback happened. This is not supported. \
                     Please upgrade to a hotfix instead."
                ));
            }
            Ordering::Less => {
                // This is where you would put a function to do the migration, which would look something like this:
                // if stored_state_version == StateVersion(*last_state_version*) {
                //   let state = deserializer.get_value::<StateVLast>().unwrap();
                //   deserializer.done().unwrap();
                //   return Ok(migrate_last_to_current(state));
                // }
                // Migrations should be deleted after execution to keep the codebase tidy.
                return Err(format!(
                    "[cycles] ERROR: stored state version {stored_state_version:?} is lesser than the current state \
                     version {current_state_version:?}! Did you forget to migrate the old to the current type?"
                ));
            }
            Ordering::Equal => print(format!(
                "[cycles] INFO: stored state version {stored_state_version:?} equals the current state version {current_state_version:?}. \
                Continuing to decode the stable storage ... ",
            )),
        };
        let state = deserializer.get_value::<State>().unwrap();
        deserializer.done().unwrap();
        Ok(state)
    }

    // Keep the size of blocks_notified map not larger than max_history.
    // Purges at most MAX_NOTIFY_PURGE entries.
    fn purge_old_notifications(&mut self, max_history: usize) {
        let mut last_purged = 0;
        let mut cnt = 0;
        // Remove elements from the beginning of self.blocks_notified until either
        // it is small enough, or MAX_NOTIFY_PURGE entries have been removed.
        while self.blocks_notified.len() > max_history && cnt < MAX_NOTIFY_PURGE {
            // pop_first is nightly only
            let block_height = *self.blocks_notified.iter().next().unwrap().0;
            self.blocks_notified.remove(&block_height);
            last_purged = block_height;
            cnt += 1;
        }
        // make sure this grows monotonically (a delayed callback might have added older status)
        self.last_purged_notification = last_purged.max(self.last_purged_notification);
    }
}

impl Default for State {
    fn default() -> Self {
        let resolution = Duration::from_secs(60);
        let max_age = Duration::from_secs(60 * 60);
        let initial_icp_xdr_conversion_rate = IcpXdrConversionRate {
            timestamp_seconds: DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS,
            xdr_permyriad_per_icp: DEFAULT_XDR_PERMYRIAD_PER_ICP_CONVERSION_RATE,
        };

        Self {
            ledger_canister_id: CanisterId::ic_00(),
            governance_canister_id: CanisterId::ic_00(),
            exchange_rate_canister_id: None,
            cycles_ledger_canister_id: None,
            minting_account_id: None,
            authorized_subnets: BTreeMap::new(),
            default_subnets: vec![],
            icp_xdr_conversion_rate: Some(initial_icp_xdr_conversion_rate.clone()),
            average_icp_xdr_conversion_rate: Some(initial_icp_xdr_conversion_rate.clone()),
            recent_icp_xdr_rates: Some(vec![
                IcpXdrConversionRate::default();
                ICP_XDR_CONVERSION_RATE_CACHE_SIZE
            ]),
            cycles_per_xdr: DEFAULT_CYCLES_PER_XDR.into(),
            base_cycles_limit: Cycles::from(DEFAULT_CYCLES_LIMIT),
            subnet_rental_cycles_limit: Cycles::from(SUBNET_RENTAL_DEFAULT_CYCLES_LIMIT),
            base_limiter: limiter::Limiter::new(resolution, max_age),
            subnet_rental_canister_limiter: limiter::Limiter::new(
                Duration::from_secs(ONE_HOUR_SECONDS),
                Duration::from_secs(ONE_MONTH_SECONDS),
            ),
            total_cycles_minted: Cycles::zero(),
            blocks_notified: BTreeMap::new(),
            last_purged_notification: 0,
            maturity_modulation_permyriad: Some(0),
            subnet_types_to_subnets: Some(BTreeMap::new()),
            update_exchange_rate_canister_state: Some(UpdateExchangeRateState::default()),
        }
    }
}

enum CyclesMintingLimiterSelector {
    BaseLimit,
    SubnetRentalLimit,
}

impl CyclesMintingLimiterSelector {
    fn check_and_add_cycles(
        &self,
        state: &mut State,
        now: SystemTime,
        cycles_to_mint: Cycles,
    ) -> Result<(), String> {
        match self {
            CyclesMintingLimiterSelector::BaseLimit => state.base_limiter.check_and_add_cycles(
                now,
                cycles_to_mint,
                state.base_cycles_limit,
            ),
            CyclesMintingLimiterSelector::SubnetRentalLimit => state
                .subnet_rental_canister_limiter
                .check_and_add_cycles(now, cycles_to_mint, state.subnet_rental_cycles_limit),
        }
    }
}

// Helper to print messages in yellow
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    #[cfg(target_arch = "wasm32")]
    ic_cdk::api::print(yansi::Paint::yellow(s).to_string());

    #[cfg(not(target_arch = "wasm32"))]
    println!("{}", yansi::Paint::yellow(s).to_string());
}

fn main() {}

#[init]
fn init(maybe_args: Option<CyclesCanisterInitPayload>) {
    let args =
        maybe_args.expect("Payload is expected to initialization the cycles minting canister.");
    print(format!(
        "[cycles] init() with ledger canister {}, governance canister {}, exchange rate canister {}, minting account {}, and cycles ledger canister {}",
        args.ledger_canister_id
            .as_ref()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        args.governance_canister_id
            .as_ref()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        args.exchange_rate_canister
            .as_ref()
            .map(|x| match x {
                ExchangeRateCanister::Set(id) => id.to_string(),
                ExchangeRateCanister::Unset => "<unset>".to_string(),
            })
            .unwrap_or_else(|| "<none>".to_string()),
        args.minting_account_id
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        args.cycles_ledger_canister_id
            .as_ref()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
    ));

    STATE.with(|state| state.replace(Some(State::default())));
    with_state_mut(|state| {
        state.ledger_canister_id = args
            .ledger_canister_id
            .expect("Ledger canister ID must be set!");
        state.governance_canister_id = args
            .governance_canister_id
            .expect("Governance canister ID must be set!");
        state.minting_account_id = args.minting_account_id;
        if let Some(last_purged_notification) = args.last_purged_notification {
            state.last_purged_notification = last_purged_notification;
        }
        if let Some(xrc_flag) = args.exchange_rate_canister {
            state.exchange_rate_canister_id = xrc_flag.extract_exchange_rate_canister_id();
        }
        if args.cycles_ledger_canister_id.is_some() {
            state.cycles_ledger_canister_id = args.cycles_ledger_canister_id;
        }
    });
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

/// Set the list of subnets in which a principal is allowed to create
/// canisters. If `subnets` is empty, remove the mapping for a
/// principal. If `who` is None, set the default list of subnets.
#[update]
fn set_authorized_subnetwork_list(arg: SetAuthorizedSubnetworkListArgs) {
    let SetAuthorizedSubnetworkListArgs { who, subnets } = arg;
    with_state_mut(|state| {
        let governance_canister_id = state.governance_canister_id;
        let caller_id = CanisterId::unchecked_from_principal(caller());

        if caller_id != governance_canister_id && caller_id != SUBNET_RENTAL_CANISTER_ID {
            panic!(
                "Only the governance canister and subnet rental canister can set authorized subnetwork lists."
            );
        }

        let assigned_to_types: BTreeSet<&SubnetId> = state
            .subnet_types_to_subnets
            .as_ref()
            .expect("subnet types to subnets mapping is not `None`")
            .values()
            .flatten()
            .collect();
        let mut already_assigned = vec![];
        for subnet in subnets.iter() {
            if assigned_to_types.contains(subnet) {
                already_assigned.push(*subnet);
            }
        }
        if !already_assigned.is_empty() {
            panic!(
                "Subnets {already_assigned:?} are already assigned to a type and cannot be authorized."
            );
        }

        if let Some(who) = who {
            if subnets.is_empty() {
                print(format!("[cycles] removing subnet list for {who}"));
                state.authorized_subnets.remove(&who);
            } else {
                print(format!("[cycles] setting subnet list for {who}"));
                state.authorized_subnets.insert(who, subnets);
            }
        } else {
            print("[cycles] setting default subnet list");
            state.default_subnets = subnets;
        }
    });
}

#[update(manual_reply = true)]
fn update_subnet_type(args: UpdateSubnetTypeArgs) {
    match do_update_subnet_type(args) {
        Ok(response) => ManualReply::<()>::one(response),
        Err(err) => ManualReply::reject(err.to_string()),
    };
}

/// Updates the set of available subnet types.
///
/// Preconditions:
//   * Only the governance canister can call this method
//   * Add: type does not already exist
//   * Remove: type exists and no assigned subnets to this type exist
fn do_update_subnet_type(args: UpdateSubnetTypeArgs) -> UpdateSubnetTypeResult {
    let governance_canister_id = with_state(|state| state.governance_canister_id);

    if CanisterId::unchecked_from_principal(caller()) != governance_canister_id {
        panic!("Only the governance canister can update the available subnet types.");
    }

    match args {
        UpdateSubnetTypeArgs::Add(subnet_type) => add_subnet_type(subnet_type),
        UpdateSubnetTypeArgs::Remove(subnet_type) => remove_subnet_type(subnet_type),
    }
}

fn add_subnet_type(subnet_type: String) -> UpdateSubnetTypeResult {
    with_state_mut(|state| {
        let subnet_types_to_subnets = &mut state
            .subnet_types_to_subnets
            .as_mut()
            .expect("subnet types to subnets mapping is not `None`");

        match subnet_types_to_subnets.entry(subnet_type.clone()) {
            Entry::Vacant(entry) => {
                print(format!("[cycles] Adding new subnet type: {subnet_type}"));
                entry.insert(BTreeSet::new());
                Ok(())
            }
            Entry::Occupied(_) => Err(UpdateSubnetTypeError::Duplicate(subnet_type)),
        }
    })
}

fn remove_subnet_type(subnet_type: String) -> UpdateSubnetTypeResult {
    with_state_mut(|state| {
        let subnet_types_to_subnets = &mut state
            .subnet_types_to_subnets
            .as_mut()
            .expect("subnet types to subnets mapping is not `None`");

        match subnet_types_to_subnets.get(&subnet_type) {
            Some(subnets) => {
                if !subnets.is_empty() {
                    Err(UpdateSubnetTypeError::TypeHasAssignedSubnets((
                        subnet_type,
                        subnets.iter().copied().collect(),
                    )))
                } else {
                    print(format!("[cycles] Removing subnet type: {subnet_type}"));
                    // Type does not have any assigned subnets, so it can be removed.
                    subnet_types_to_subnets.remove(&subnet_type);
                    Ok(())
                }
            }
            None => Err(UpdateSubnetTypeError::TypeDoesNotExist(subnet_type)),
        }
    })
}

#[update(manual_reply = true)]
fn change_subnet_type_assignment(args: ChangeSubnetTypeAssignmentArgs) {
    match do_change_subnet_type_assignment(args) {
        Ok(response) => ManualReply::<()>::one(response),
        Err(err) => ManualReply::reject(err.to_string()),
    };
}

/// Changes the assignment of provided subnets to subnet types.
///
/// Preconditions:
///  * Only the governance canister can call this method
///  * Add: type exists and all subnet ids should be currently unassigned and not part of the authorized subnets
///  * Remove: type exists and all subnet ids are currently assigned to this type
fn do_change_subnet_type_assignment(
    args: ChangeSubnetTypeAssignmentArgs,
) -> ChangeSubnetTypeAssignmentResult {
    let governance_canister_id = with_state(|state| state.governance_canister_id);

    if CanisterId::unchecked_from_principal(caller()) != governance_canister_id {
        panic!(
            "Only the governance canister can change the assignment of subnets to subnet types."
        );
    }

    match args {
        ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
            subnets,
            subnet_type,
        }) => add_subnets_to_type(subnets, subnet_type),
        ChangeSubnetTypeAssignmentArgs::Remove(SubnetListWithType {
            subnets,
            subnet_type,
        }) => remove_subnets_from_type(subnets, subnet_type),
    }
}

fn add_subnets_to_type(
    subnets: Vec<SubnetId>,
    subnet_type: String,
) -> ChangeSubnetTypeAssignmentResult {
    with_state_mut(|state| {
        let subnet_types_to_subnets = &mut state
            .subnet_types_to_subnets
            .as_mut()
            .expect("subnet types to subnets mapping is not `None`");

        // Check that the subnets we are trying to assign to `subnet_type` are
        // not already assigned to another type.
        let mut assigned_subnets = vec![];
        for (subnet_type_tmp, subnets_tmp) in subnet_types_to_subnets.iter() {
            let mut tmp = vec![];
            for subnet in subnets.iter() {
                if subnets_tmp.contains(subnet) {
                    tmp.push(*subnet);
                }
            }
            if !tmp.is_empty() {
                assigned_subnets.push(SubnetListWithType {
                    subnets: tmp,
                    subnet_type: subnet_type_tmp.clone(),
                });
            }
        }

        if !assigned_subnets.is_empty() {
            return Err(ChangeSubnetTypeAssignmentError::SubnetsAreAssigned(
                assigned_subnets,
            ));
        }

        // Check that the subnets we are trying to assign to `subnet_type` are
        // not already in the authorized or default subnet list.
        let mut authorized_and_default_subnets: BTreeSet<&SubnetId> =
            state.default_subnets.iter().collect();
        let tmp: BTreeSet<&SubnetId> = state.authorized_subnets.values().flatten().collect();
        authorized_and_default_subnets.extend(tmp);
        let mut already_authorized_subnets = vec![];
        for subnet in subnets.iter() {
            if authorized_and_default_subnets.contains(subnet) {
                already_authorized_subnets.push(*subnet);
            }
        }
        if !already_authorized_subnets.is_empty() {
            return Err(ChangeSubnetTypeAssignmentError::SubnetsAreAuthorized(
                already_authorized_subnets,
            ));
        }

        // We can now safely assign the subnets.
        match subnet_types_to_subnets.entry(subnet_type.clone()) {
            Entry::Occupied(mut entry) => {
                print(format!(
                    "[cycles] Adding subnets {subnets:?} to type: {subnet_type}"
                ));
                let existing_subnets = entry.get_mut();
                existing_subnets.extend(subnets);
                Ok(())
            }
            Entry::Vacant(_) => Err(ChangeSubnetTypeAssignmentError::TypeDoesNotExist(
                subnet_type,
            )),
        }
    })
}

fn remove_subnets_from_type(
    subnets: Vec<SubnetId>,
    subnet_type: String,
) -> ChangeSubnetTypeAssignmentResult {
    with_state_mut(|state| {
        let subnet_types_to_subnets = &mut state
            .subnet_types_to_subnets
            .as_mut()
            .expect("subnet types to subnets mapping is not `None`");

        match subnet_types_to_subnets.entry(subnet_type.clone()) {
            Entry::Occupied(mut entry) => {
                // Check that the provided subnets are assigned to the type
                // that we're trying to remove them from.
                let mut not_assigned_subnets = vec![];
                for subnet in subnets.iter() {
                    if !entry.get().contains(subnet) {
                        not_assigned_subnets.push(*subnet);
                    }
                }

                if !not_assigned_subnets.is_empty() {
                    return Err(ChangeSubnetTypeAssignmentError::SubnetsAreNotAssigned(
                        SubnetListWithType {
                            subnets: not_assigned_subnets,
                            subnet_type,
                        },
                    ));
                }

                // Subnets can now safely be removed from the type.
                print(format!(
                    "[cycles] Removing subnets {subnets:?} from type: {subnet_type}"
                ));
                let existing_subnets = entry.get_mut();
                for subnet in subnets.iter() {
                    existing_subnets.remove(subnet);
                }
                Ok(())
            }
            // Type not found.
            Entry::Vacant(_) => Err(ChangeSubnetTypeAssignmentError::TypeDoesNotExist(
                subnet_type,
            )),
        }
    })
}

/// Retrieves the current mapping of subnet types to subnets.
#[query]
fn get_subnet_types_to_subnets() -> SubnetTypesToSubnetsResponse {
    with_state(|state: &State| {
        let data: Vec<(String, Vec<SubnetId>)> = state
            .subnet_types_to_subnets
            .as_ref()
            .expect("subnet types to subnets mapping is not `None`")
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
            .collect();
        SubnetTypesToSubnetsResponse { data }
    })
}

/// Returns the current mapping of authorized principals to subnets.
#[query]
fn get_principals_authorized_to_create_canisters_to_subnets() -> AuthorizedSubnetsResponse {
    with_state(|state| {
        let data = state
            .authorized_subnets
            .iter()
            .map(|(k, v)| (*k, v.to_vec()))
            .collect();
        AuthorizedSubnetsResponse { data }
    })
}

/// Returns the list of default subnets to which anyone can deploy canisters to.
#[query]
fn get_default_subnets() -> Vec<PrincipalId> {
    with_state(|state| {
        state
            .default_subnets
            .clone()
            .iter()
            .map(|s| s.get())
            .collect()
    })
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
    label: Label,
    witness_generator: WitnessGeneratorImpl,
) -> Vec<u8> {
    let icp_xdr_conversion_rate_buf = Encode!(&conversion_rate).unwrap();

    let mixed_hash_tree = witness_generator
        .mixed_hash_tree(&LabeledTree::SubTree(flatmap! {
            label => LabeledTree::Leaf(icp_xdr_conversion_rate_buf)
        }))
        .expect("failed to produce a hash tree");

    let mut serializer = serde_cbor::ser::Serializer::new(vec![]);
    serializer.self_describe().unwrap();
    mixed_hash_tree
        .serialize(&mut serializer)
        .unwrap_or_else(|e| ic_cdk::trap(format!("failed to serialize a hash tree: {e}")));

    serializer.into_inner()
}

/// Retrieves the current `xdr_permyriad_per_icp` as a certified response.
#[query]
fn get_icp_xdr_conversion_rate() -> IcpXdrConversionRateCertifiedResponse {
    with_state(|state| {
        let witness_generator = convert_data_to_mixed_hash_tree(state);
        let icp_xdr_conversion_rate = state
            .icp_xdr_conversion_rate
            .as_ref()
            .expect("icp_xdr_conversion_rate is not set");

        let payload = convert_conversion_rate_to_payload(
            icp_xdr_conversion_rate,
            Label::from(LABEL_ICP_XDR_CONVERSION_RATE),
            witness_generator,
        );

        IcpXdrConversionRateCertifiedResponse {
            data: icp_xdr_conversion_rate.clone(),
            hash_tree: payload,
            certificate: ic_cdk::api::data_certificate().unwrap_or_default(),
        }
    })
}

#[query(hidden = true)]
fn get_average_icp_xdr_conversion_rate(_: ()) -> IcpXdrConversionRateCertifiedResponse {
    with_state(|state| {
        let witness_generator = convert_data_to_mixed_hash_tree(state);
        let average_icp_xdr_conversion_rate = state
            .average_icp_xdr_conversion_rate
            .as_ref()
            .expect("average_icp_xdr_conversion_rate is not set");

        let payload = convert_conversion_rate_to_payload(
            average_icp_xdr_conversion_rate,
            Label::from(LABEL_AVERAGE_ICP_XDR_CONVERSION_RATE),
            witness_generator,
        );

        IcpXdrConversionRateCertifiedResponse {
            data: average_icp_xdr_conversion_rate.clone(),
            hash_tree: payload,
            certificate: ic_cdk::api::data_certificate().unwrap_or_default(),
        }
    })
}

/// The function updates the vector of recent rates, which are used to compute
/// the average rate over `NUM_ICP_XDR_RATES_FOR_AVERAGE` days.
/// The first received rate for each day is stored, ideally with a timestamp
/// exactly at the start of the day.
fn update_recent_icp_xdr_rates(state: &mut State, new_rate: &IcpXdrConversionRate) {
    let day = new_rate.timestamp_seconds / 86_400;
    // The index is the day modulo `ICP_XDR_CONVERSION_RATE_CACHE_SIZE`.
    let index = (day as usize) % ICP_XDR_CONVERSION_RATE_CACHE_SIZE;

    let recent_rates = state.recent_icp_xdr_rates.get_or_insert(vec![
        IcpXdrConversionRate::default();
        ICP_XDR_CONVERSION_RATE_CACHE_SIZE
    ]);

    // The record is updated if it is the first entry of a new day or an earlier
    // entry of the same day.
    let day_at_index = recent_rates[index].timestamp_seconds / 86_400;
    if day_at_index < day
        || (day_at_index == day
            && recent_rates[index].timestamp_seconds > new_rate.timestamp_seconds)
    {
        recent_rates[index] = new_rate.clone();
        // Update the average ICP/XDR rate and the maturity modulation.
        let time = now_seconds();
        state.average_icp_xdr_conversion_rate =
            compute_average_icp_xdr_rate_at_time(recent_rates, time);
        state.maturity_modulation_permyriad = Some(compute_maturity_modulation(recent_rates, time));
    }
}

/// The function returns the average ICP/XDR price over the past
/// NUM_ICP_XDR_RATES_FOR_AVERAGE` days ending on the day at the provided timestamp in seconds.
/// If there are no valid data points for
/// the time between the given UNIX epoch timestamp and
/// `NUM_DAYS_FOR_ICP_XDR_AVERAGE` in the past, 'None' is returned.
fn compute_average_icp_xdr_rate_at_time(
    recent_rates: &[IcpXdrConversionRate],
    time_s: u64,
) -> Option<IcpXdrConversionRate> {
    let day = time_s / 86_400;
    // Filter the rates based on valid days, i.e., days not before day
    // `day - NUM_ICP_XDR_RATES_FOR_AVERAGE` and not later than the given day.
    let filtered_rates: Vec<u64> = recent_rates
        .iter()
        .filter(|rate| {
            (rate.timestamp_seconds / 86_400) > day - (NUM_DAYS_FOR_ICP_XDR_AVERAGE as u64)
                && (rate.timestamp_seconds / 86_400) <= day
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

#[update(hidden = true)]
fn set_icp_xdr_conversion_rate(
    proposed_conversion_rate: UpdateIcpXdrConversionRatePayload,
) -> Result<(), String> {
    let caller = caller();

    assert_eq!(
        caller,
        GOVERNANCE_CANISTER_ID.into(),
        "{} is not authorized to call this method: {}",
        caller,
        "set_icp_xdr_conversion_rate"
    );

    let env = CanisterEnvironment;
    let rate = IcpXdrConversionRate::from(&proposed_conversion_rate);
    let rate_timestamp_seconds = rate.timestamp_seconds;
    let result = do_set_icp_xdr_conversion_rate(&STATE, &env, rate);
    if result.is_ok() && with_state(|state| state.exchange_rate_canister_id.is_some()) {
        exchange_rate_canister::set_update_exchange_rate_state(
            &STATE,
            &proposed_conversion_rate.reason,
            rate_timestamp_seconds,
        );
    }

    result
}

/// Validates the proposed conversion rate, sets it in state, and sets the
/// canister's certified data
fn do_set_icp_xdr_conversion_rate(
    safe_state: &'static LocalKey<RefCell<Option<State>>>,
    env: &impl Environment,
    proposed_conversion_rate: IcpXdrConversionRate,
) -> Result<(), String> {
    print(format!(
        "[cycles] conversion rate update: {proposed_conversion_rate:?}"
    ));

    if proposed_conversion_rate.xdr_permyriad_per_icp == 0 {
        return Err("Proposed conversion rate must be greater than 0".to_string());
    }

    mutate_state(safe_state, |state| {
        if let Some(current_conversion_rate) = state.icp_xdr_conversion_rate.as_ref()
            && proposed_conversion_rate.timestamp_seconds
                <= current_conversion_rate.timestamp_seconds
        {
            return Err(
                "Proposed conversion rate must have greater timestamp than current one".to_string(),
            );
        }

        state.icp_xdr_conversion_rate = Some(proposed_conversion_rate.clone());
        update_recent_icp_xdr_rates(state, &proposed_conversion_rate);

        let witness_generator = convert_data_to_mixed_hash_tree(state);
        env.set_certified_data(&witness_generator.hash_tree().digest().0[..]);

        Ok(())
    })
}

/// The function returns the current maturity modulation in basis points.
#[query(hidden = true)]
fn neuron_maturity_modulation() -> Result<i32, String> {
    Ok(with_state(|state| {
        state.maturity_modulation_permyriad.unwrap_or(0)
    }))
}

/// The function computes the maturity modulation for the current time/day, based on the given
/// start-of-day conversion rates.
fn compute_maturity_modulation(rates: &[IcpXdrConversionRate], time_s: u64) -> i32 {
    let day = time_s / 86_400;
    // Get the rate for four seven-day periods.
    let rate1 = compute_capped_maturity_modulation(rates, day - 7, day);
    let rate2 = compute_capped_maturity_modulation(rates, day - 14, day - 7);
    let rate3 = compute_capped_maturity_modulation(rates, day - 21, day - 14);
    let rate4 = compute_capped_maturity_modulation(rates, day - 28, day - 21);
    // Return the average as the final maturity modulation.
    (rate1 + rate2 + rate3 + rate4) / 4
}

/// The function returns the capped relative change of the start-of-day ICP/XDR rate between the
/// given start day and end day, both in UNIX epoch time, where start day <= end day.
/// The relative change is capped so that it lies in the interval defined by
/// `MIN_MATURITY_MODULATION_PERMYRIAD` and `MAX_MATURITY_MODULATION_PERMYRIAD`.
fn compute_capped_maturity_modulation(
    rates: &[IcpXdrConversionRate],
    start_day: u64,
    end_day: u64,
) -> i32 {
    let start_index = (start_day as usize) % ICP_XDR_CONVERSION_RATE_CACHE_SIZE;
    let day_at_start_index = rates[start_index].timestamp_seconds / 86_400;

    let end_index = (end_day as usize) % ICP_XDR_CONVERSION_RATE_CACHE_SIZE;
    let day_at_end_index = rates[end_index].timestamp_seconds / 86_400;

    // A proper modulation is only possible if we have rates for both days.
    // Otherwise, no modulation happens for this interval, i.e., zero is returned.
    if start_day == day_at_start_index && end_day == day_at_end_index {
        let start_rate_result = compute_average_icp_xdr_rate_at_time(rates, start_day * 86_400);
        let end_rate_result = compute_average_icp_xdr_rate_at_time(rates, end_day * 86_400);
        if let (Some(start_rate), Some(end_rate)) = (start_rate_result, end_rate_result) {
            let start_rate_value = start_rate.xdr_permyriad_per_icp as i32;
            let end_rate_value = end_rate.xdr_permyriad_per_icp as i32;
            let difference = end_rate_value.saturating_sub(start_rate_value);
            let difference_permyriad = difference.saturating_mul(10_000);
            match difference_permyriad.checked_div(start_rate_value) {
                Some(relative_change_permyriad) => relative_change_permyriad.clamp(
                    MIN_MATURITY_MODULATION_PERMYRIAD,
                    MAX_MATURITY_MODULATION_PERMYRIAD,
                ),
                None => 0,
            }
        } else {
            0
        }
    } else {
        0
    }
}

#[update(hidden = true)]
fn remove_subnet_from_authorized_subnet_list(arg: RemoveSubnetFromAuthorizedSubnetListArgs) {
    let RemoveSubnetFromAuthorizedSubnetListArgs {
        subnet: subnet_to_remove,
    } = arg;
    let caller = caller();
    assert_eq!(
        caller,
        REGISTRY_CANISTER_ID.into(),
        "{} is not authorized to call this method: {}",
        caller,
        "remove_subnet_from_authorized_subnet_list"
    );

    with_state_mut(|state| {
        state
            .authorized_subnets
            .values_mut()
            .for_each(|subnet_list| subnet_list.retain(|subnet| *subnet != subnet_to_remove))
    });
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
#[update]
async fn notify_top_up(
    NotifyTopUp {
        block_index,
        canister_id,
    }: NotifyTopUp,
) -> Result<Cycles, NotifyError> {
    let caller = caller();

    let src_canister_principal = SUBNET_RENTAL_CANISTER_ID.get();
    let limiter_to_use =
        if caller == src_canister_principal && canister_id.get() == src_canister_principal {
            // caller and destination needs to be src_canister_principal to get alternate limiter
            CyclesMintingLimiterSelector::SubnetRentalLimit
        } else {
            CyclesMintingLimiterSelector::BaseLimit
        };

    let (amount, from) = fetch_transaction(
        block_index,
        Subaccount::from(&canister_id),
        MEMO_TOP_UP_CANISTER,
    )
    .await?;

    // Try to set the status of this block to Processing. In order for this to
    // succeed, two conditions must hold:
    //
    //     1. It must not already have a status.
    //
    //     2. The block is "sufficiently recent". More precisely, it must be
    //        more recent than last_purged_notification. (To avoid unbounded
    //        growth of the blocks_notified.)
    let maybe_early_result = with_state_mut(|state| {
        state.purge_old_notifications(MAX_NOTIFY_HISTORY);

        if block_index <= state.last_purged_notification {
            return Some(Err(NotifyError::TransactionTooOld(
                state.last_purged_notification + 1,
            )));
        }

        match state.blocks_notified.entry(block_index) {
            Entry::Occupied(entry) => match entry.get() {
                NotificationStatus::Processing => Some(Err(NotifyError::Processing)),

                // If the user makes a duplicate request, we respond as though
                // the current request is the original one.
                NotificationStatus::NotifiedTopUp(result) => Some(result.clone()),
                NotificationStatus::NotifiedCreateCanister(_) => {
                    Some(Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as create canister request".into(),
                    )))
                }
                NotificationStatus::NotifiedMint(_) => Some(Err(NotifyError::InvalidTransaction(
                    "The same payment is already processed as mint request".into(),
                ))),
                NotificationStatus::NotMeaningfulMemo(_) => {
                    Some(Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as automatic refund".into(),
                    )))
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(NotificationStatus::Processing);
                None
            }
        }
    });

    match maybe_early_result {
        Some(result) => result,
        None => {
            let result = process_top_up(canister_id, from, amount, limiter_to_use).await;

            with_state_mut(|state| {
                state.blocks_notified.insert(
                    block_index,
                    NotificationStatus::NotifiedTopUp(result.clone()),
                );
                if is_transient_error(&result) {
                    state.blocks_notified.remove(&block_index);
                }
            });

            result
        }
    }
}

/// Mints cycles from ICP and deposits the cycles into the cycles ledger
///
/// If the cycles are supposed to be deposited to a different canister use `notify_top_up` instead.
///
/// # Arguments
///
/// * `block_height` -  The height of the block you would like to send a
///   notification about.
/// * `to_subaccount` - Cycles ledger subaccount to which the cycles are minted to.
#[update]
async fn notify_mint_cycles(
    NotifyMintCyclesArg {
        block_index,
        to_subaccount,
        deposit_memo,
    }: NotifyMintCyclesArg,
) -> NotifyMintCyclesResult {
    let subaccount = Subaccount::from(&caller());
    let to_account = Account {
        owner: caller().into(),
        subaccount: to_subaccount,
    };

    let deposit_memo_len = deposit_memo.as_ref().map_or(0, |memo| memo.len());
    if deposit_memo_len > MAX_MEMO_LENGTH {
        return Err(NotifyError::Other {
            error_code: NotifyErrorCode::DepositMemoTooLong as u64,
            error_message: format!(
                "Memo length {deposit_memo_len} exceeds the maximum length of {MAX_MEMO_LENGTH}"
            ),
        });
    }

    let (amount, from) = fetch_transaction(block_index, subaccount, MEMO_MINT_CYCLES).await?;

    let maybe_early_result = with_state_mut(|state| {
        state.purge_old_notifications(MAX_NOTIFY_HISTORY);

        if block_index <= state.last_purged_notification {
            return Some(Err(NotifyError::TransactionTooOld(
                state.last_purged_notification + 1,
            )));
        }

        match state.blocks_notified.entry(block_index) {
            Entry::Occupied(entry) => match entry.get() {
                NotificationStatus::Processing => Some(Err(NotifyError::Processing)),
                NotificationStatus::NotifiedMint(resp) => Some(resp.clone()),
                NotificationStatus::NotifiedCreateCanister(_) => {
                    Some(Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as a create canister request."
                            .into(),
                    )))
                }
                NotificationStatus::NotifiedTopUp(_) => Some(Err(NotifyError::InvalidTransaction(
                    "The same payment is already processed as a top up request.".into(),
                ))),
                NotificationStatus::NotMeaningfulMemo(_) => {
                    Some(Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as an automatic refund.".into(),
                    )))
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(NotificationStatus::Processing);
                None
            }
        }
    });

    match maybe_early_result {
        Some(result) => result,
        None => {
            let result =
                process_mint_cycles(to_account, amount, deposit_memo, from, subaccount).await;

            with_state_mut(|state| {
                state.blocks_notified.insert(
                    block_index,
                    NotificationStatus::NotifiedMint(result.clone()),
                );
                if is_transient_error(&result) {
                    state.blocks_notified.remove(&block_index);
                }
            });

            result
        }
    }
}

/// Notify about create canister transaction
///
/// Calling this is the second step in a 2 step canister creation flow, which
/// goes as follows:
///
///   1. ICP is sent to a subaccount of the Cycles Minting Canister
///      corresponding to creator principal C. Note that while the sender of the
///      ICP is typically C, it makes no difference who sends the ICP. The only
///      thing that matters is the destination (sub)account.
///
///   2. C calls notify_create_canister.
///
/// # Arguments
///
/// * `block_height` -  The height of the block you would like to send a
///   notification about.
/// * `controller` - The creator of the canister. Must match caller; otherwise,
///   Err is returned. This is also used when checking that the creator is
///   authorized to create canisters in subnets where authorization is required.
///   This is also used when `settings` does not specify `controllers`.
/// * `settings` - The settings of the canister. If controllers is not
///   populated, it will be initialized with a (singleton) vec containing just
///   `controller`.
/// * `subnet_selection` - Where to create the canister.
/// * `subnet_type` - Deprecated. Use subnet_selection instead.
#[update]
#[allow(deprecated)]
async fn notify_create_canister(
    NotifyCreateCanister {
        block_index,
        controller,
        subnet_type,
        subnet_selection,
        settings,
    }: NotifyCreateCanister,
) -> Result<CanisterId, NotifyError> {
    authorize_caller_to_call_notify_create_canister_on_behalf_of_creator(caller(), controller)?;

    let subnet_selection =
        get_subnet_selection(subnet_type, subnet_selection).map_err(|error_message| {
            NotifyError::Other {
                error_code: NotifyErrorCode::BadSubnetSelection as u64,
                error_message,
            }
        })?;

    let (amount, from) = fetch_transaction(
        block_index,
        Subaccount::from(&controller),
        MEMO_CREATE_CANISTER,
    )
    .await?;

    let maybe_early_result = with_state_mut(|state| {
        state.purge_old_notifications(MAX_NOTIFY_HISTORY);

        if block_index <= state.last_purged_notification {
            return Some(Err(NotifyError::TransactionTooOld(
                state.last_purged_notification + 1,
            )));
        }

        match state.blocks_notified.entry(block_index) {
            Entry::Occupied(entry) => match entry.get() {
                NotificationStatus::Processing => Some(Err(NotifyError::Processing)),
                NotificationStatus::NotifiedCreateCanister(resp) => Some(resp.clone()),
                NotificationStatus::NotifiedTopUp(_) => Some(Err(NotifyError::InvalidTransaction(
                    "The same payment is already processed as a top up request.".into(),
                ))),
                NotificationStatus::NotifiedMint(_) => Some(Err(NotifyError::InvalidTransaction(
                    "The same payment is already processed as a mint request.".into(),
                ))),
                NotificationStatus::NotMeaningfulMemo(_) => {
                    Some(Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as an automatic refund.".into(),
                    )))
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(NotificationStatus::Processing);
                None
            }
        }
    });

    match maybe_early_result {
        Some(result) => result,
        None => {
            let result =
                process_create_canister(controller, from, amount, subnet_selection, settings).await;

            with_state_mut(|state| {
                state.blocks_notified.insert(
                    block_index,
                    NotificationStatus::NotifiedCreateCanister(result.clone()),
                );
                if is_transient_error(&result) {
                    state.blocks_notified.remove(&block_index);
                }
            });

            result
        }
    }
}

/// Returns Err if caller is not authorized to call notify_create_canister on
/// behalf of creator.
///
/// Of course, a principal can act on its own behalf. In other words, this
/// allows calls when caller == creator.
///
/// In additional to that, there is another case where calls are allowed: the
/// nns-dapp backend canister is allowed to call notify_create_canister on
/// behalf of others.
///
/// If Err is returned, the value will be NotifyError::Other with code
/// Unauthorized.
fn authorize_caller_to_call_notify_create_canister_on_behalf_of_creator(
    caller: PrincipalId,
    creator: PrincipalId,
) -> Result<(), NotifyError> {
    if caller == creator {
        return Ok(());
    }

    // This is a hack to enable testing (related features) of nns-dapp. In
    // tests, the nns-dapp backend canister happens to use ID of the production
    // ICP ledger archive 1 canister. Ideally, the test nns-dapp backend
    // canister would have the same ID as the production nns-dapp backend
    // canister. This difference should probably be considered a bug. This hack
    // can be removed after that bug is fixed.
    const TEST_NNS_DAPP_BACKEND_CANISTER_ID: CanisterId = ICP_LEDGER_ARCHIVE_1_CANISTER_ID;
    lazy_static! {
        static ref ALLOWED_CALLERS: [PrincipalId; 2] = [
            PrincipalId::from(*NNS_DAPP_BACKEND_CANISTER_ID),
            PrincipalId::from(TEST_NNS_DAPP_BACKEND_CANISTER_ID),
        ];
    }

    if ALLOWED_CALLERS.contains(&caller) {
        return Ok(());
    }

    // Other is used, because adding a Unauthorized variant to NotifyError would
    // confuse old clients.
    let err = NotifyError::Other {
        error_code: NotifyErrorCode::Unauthorized as u64,
        error_message: format!(
            "{caller} is not authorized to call notify_create_canister on behalf \
             of {creator}. (Do not retry, because the same result will occur.)",
        ),
    };

    Err(err)
}

#[update]
#[allow(deprecated)]
async fn create_canister(
    CreateCanister {
        settings,
        subnet_selection,
        subnet_type,
    }: CreateCanister,
) -> Result<CanisterId, CreateCanisterError> {
    let cycles = ic_cdk::api::call::msg_cycles_available();

    if cycles < CREATE_CANISTER_MIN_CYCLES {
        return Err(CreateCanisterError::Refunded {
            refund_amount: cycles.into(),
            create_error: "Insufficient cycles attached.".to_string(),
        });
    }
    let subnet_selection =
        get_subnet_selection(subnet_type, subnet_selection).map_err(|error_message| {
            CreateCanisterError::Refunded {
                refund_amount: cycles.into(),
                create_error: error_message,
            }
        })?;

    match do_create_canister(caller(), cycles.into(), subnet_selection, settings).await {
        Ok(canister_id) => {
            ic_cdk::api::call::msg_cycles_accept(cycles);
            Ok(canister_id)
        }
        Err(create_error) => {
            ic_cdk::api::call::msg_cycles_accept(BAD_REQUEST_CYCLES_PENALTY as u64);
            let refund_amount = ic_cdk::api::call::msg_cycles_available();
            Err(CreateCanisterError::Refunded {
                refund_amount: refund_amount.into(),
                create_error,
            })
        }
    }
}

async fn query_block(block_index: BlockIndex, ledger_id: CanisterId) -> Result<Block, NotifyError> {
    fn failed_to_fetch_block(error_message: String) -> NotifyError {
        NotifyError::Other {
            error_code: NotifyErrorCode::FailedToFetchBlock as u64,
            error_message,
        }
    }
    let BlockRes(b) = call_protobuf(ledger_id, "block_pb", block_index)
        .await
        .map_err(|e| failed_to_fetch_block(format!("Failed to fetch block: {}", e.1)))?;

    let raw_block = match b {
        None => {
            return Err(NotifyError::InvalidTransaction(format!(
                "Block {block_index} not found"
            )));
        }
        Some(Ok(block)) => block,
        Some(Err(canister_id)) => {
            let BlockRes(b) = call_protobuf(canister_id, "get_block_pb", block_index)
                .await
                .map_err(|e| {
                    failed_to_fetch_block(format!(
                        "Failed to fetch block from {}: {}",
                        canister_id, e.1
                    ))
                })?;
            b.ok_or_else(|| {
                failed_to_fetch_block(format!(
                    "Block {block_index} not found in archive {canister_id}"
                ))
            })?
            .map_err(|redirect_canister_id| {
                failed_to_fetch_block(format!(
                    "Unexpected response from archive (redirected to {redirect_canister_id})"
                ))
            })?
        }
    };
    Block::decode(raw_block)
        .map_err(|e| failed_to_fetch_block(format!("Failed to decode block: {e}")))
}

fn memo_to_intent_str(memo: Memo) -> String {
    match memo {
        MEMO_CREATE_CANISTER => "CreateCanister".into(),
        MEMO_TOP_UP_CANISTER => "TopUp".into(),
        MEMO_MINT_CYCLES => "MintCycles".into(),
        a => format!("unrecognized: {a:?}"),
    }
}

/// Returns Ok if transaction matches expected_memo.
///
/// memo and icrc1_memo are used. See get_u64_memo.
fn transaction_has_expected_memo(
    transaction: &Transaction,
    expected_memo: Memo,
) -> Result<(), NotifyError> {
    fn stringify_memo(memo: Memo) -> String {
        format!("{} ({})", memo_to_intent_str(memo), memo.0)
    }

    let observed_memo = get_u64_memo(transaction);
    if observed_memo == expected_memo {
        return Ok(());
    }

    Err(NotifyError::InvalidTransaction(format!(
        "The memo ({}) in the transaction does not match the expected memo \
         ({}) for the operation.",
        stringify_memo(observed_memo),
        stringify_memo(expected_memo),
    )))
}

/// Returns amount, and source of the transfer in (ICP) ledger.
///
/// Returns Ok if the arguments are matched. (Otherwise, returns Err).
async fn fetch_transaction(
    block_index: BlockIndex,
    expected_to_subaccount: Subaccount,
    expected_memo: Memo,
) -> Result<(Tokens, AccountIdentifier), NotifyError> {
    let ledger_id = with_state(|state| state.ledger_canister_id);

    let block = query_block(block_index, ledger_id).await?;

    let (from, to, amount) = match block.transaction().operation {
        Operation::Transfer {
            from, to, amount, ..
        } => (from, to, amount),
        _ => {
            return Err(NotifyError::InvalidTransaction(
                "Notification transaction must be of type Transfer".into(),
            ));
        }
    };

    let expected_to = AccountIdentifier::new(
        PrincipalId::from(ic_cdk::api::id()),
        Some(expected_to_subaccount),
    );
    if to != expected_to {
        return Err(NotifyError::InvalidTransaction(format!(
            "Destination account in the block ({to}) different than in the notification ({expected_to_subaccount})",
        )));
    }

    issue_automatic_refund_if_memo_not_offerred(
        block_index,
        expected_to_subaccount,
        block.transaction().as_ref(),
    )
    .await?;

    transaction_has_expected_memo(block.transaction().as_ref(), expected_memo)?;

    Ok((amount, from))
}

/// If transaction.memo is nonzero, returns that. Otherwise, falls back to
/// icrc1_memo. More precisely, if icrc1_memo is of length 8 (64 bits), then,
/// then that is returned, assuming little-endian. Otherwise, Memo(0) is
/// returned.
fn get_u64_memo(transaction: &Transaction) -> Memo {
    if transaction.memo != Memo(0) {
        return transaction.memo;
    }

    // Fall back to icrc1_memo.

    let Some(icrc1_memo) = transaction.icrc1_memo.as_ref() else {
        // icrc1_memo is absent.
        return Memo(0);
    };

    type U64Array = [u8; std::mem::size_of::<u64>()];
    let Ok(icrc1_memo) = U64Array::try_from(icrc1_memo.as_ref()) else {
        // icrc1_memo has the wrong size.
        return Memo(0);
    };

    Memo(u64::from_le_bytes(icrc1_memo))
}

/// "Normally", sets the block's status to Processing. However, if the block is
/// too old (<= last_purged_notification), or it already has a status, no
/// changes are made, and the block's current status is returned. (None
/// indicates that the block is too old to have a status.)
fn set_block_status_to_processing(
    block_index: BlockIndex,
) -> Result<(), Option<NotificationStatus>> {
    with_state_mut(|state| {
        if block_index <= state.last_purged_notification {
            return Err(None);
        }

        match state.blocks_notified.entry(block_index) {
            Entry::Occupied(entry) => Err(Some(entry.get().clone())),

            Entry::Vacant(entry) => {
                entry.insert(NotificationStatus::Processing);
                Ok(())
            }
        }
    })
}

/// If the block's status in blocks_notified is Processing, clear it. Otherwise,
/// makes no changes (and logs an error).
fn clear_block_processing_status(block_index: BlockIndex) {
    with_state_mut(|state| {
        // Fetch the block's status.
        let occupied_entry = match state.blocks_notified.entry(block_index) {
            Entry::Occupied(ok) => ok,

            Entry::Vacant(_entry) => {
                println!(
                    "[cycles] ERROR: Tried to clear the status of block {}, \
                     but it already has no status?!",
                    block_index,
                );
                return;
            }
        };

        // Make sure the block's status is currently Processing.
        if &NotificationStatus::Processing != occupied_entry.get() {
            // Otherwise, do not touch the block's status (and log).
            println!(
                "[cycles] ERROR: Tried to clear Processing status of block {} \
                 but its current status is {:?}",
                block_index,
                occupied_entry.get(),
            );
            return;
        }

        occupied_entry.remove();
    });
}

/// Ok is returned if the transaction is not eligible for an automatic refund
/// (because its memo indicates one of the supported operations). This is so
/// that the caller can use the `?` operator to return early in the case where
/// automatic refund should be issued.
///
/// Otherwise, transaction is eligible for an automatic refund. The rest of
/// these comments assume that we are in this (interesting) case.
///
/// Attempts to transfer the ICP (minus fees) back to the sender (by calling
/// ledger).
///
/// Regardless of whether that ledger call succeeds, Err is returned, but the
/// value in the Err depends on how the ledger call turns out.
///
/// If the ledger call failed, the user can retry.
///
/// Like the rest of this canister, uses blocks_notified for synchronization.
/// More precisely, before calling ledger, there are two things:
///
///     1. The block MUST have no status. If it does, this returns Err, and no
///        ledger call is attempted.
///
///     2. The block's status is set to Processing.
///
/// If the ledger call succeeds, then the block's status is updated to
/// NotMeaningfulMemo. Otherwise, if the ledger call fails, then the block's
/// status is cleared to allow the user to try again. Some reasons the call
/// might fail:
///
///     1. Ledger is unavailable. This could be cause by it being upgraded.
///
///     2. Ledger is up, but there is something wrong with our request (e.g.
///        wrong fee).
///
/// It is generally assumed that the arguments are consistent with one another.
/// E.g. we assume that fetching the block (using incoming_block_index), would
/// give us the same value as incoming_transaction.
async fn issue_automatic_refund_if_memo_not_offerred(
    incoming_block_index: BlockIndex,
    // This is needed because transaction only has an AccountIdentifier.
    // Although it is possible to go from PrincipalId + Subaccount to
    // AccountIdentifier, the reverse is not possible. The reader might find it
    // surprising that conversion in only one direction is possible, but this
    // really is how it works, for better or worse.
    incoming_to_subaccount: Subaccount,
    incoming_transaction: &Transaction,
) -> Result<(), NotifyError> {
    let memo = get_u64_memo(incoming_transaction);
    if MEANINGFUL_MEMOS.contains(&memo) {
        // Not eligible for refund.
        return Ok(());
    }

    // Extract (from incoming_transaction) where the ICP came from, and how much
    // was transferred.
    let (incoming_from, incoming_amount) = match &incoming_transaction.operation {
        Operation::Transfer {
            from,
            to,
            amount,

            fee: _,
            spender: _,
        } => {
            let incoming_to_account_identifier = AccountIdentifier::new(
                PrincipalId::from(ic_cdk::api::id()),
                Some(incoming_to_subaccount),
            );
            if to != &incoming_to_account_identifier {
                // As long as callers always pass us Transfers where the
                // destination matches incoming_to_subaccount, this code will
                // never be executed.
                println!(
                    "[cycles] WARNING: Destination in transfer ({}) passed to
                     issue_automatic_refund_if_memo_not_offerred does NOT match. \
                     This indicates that we have some kind of bug. No refund will \
                     be issued. {} (AccountIdentifier) vs. {:?} (Subaccount)",
                    incoming_block_index, to, incoming_to_subaccount,
                );
                return Ok(());
            }

            (*from, *amount)
        }

        _invalid_operation => {
            // As long as callers always pass us Transfers, this code will never
            // be executed.
            println!(
                "[cycles] WARNING: A non-transfer transaction ({}) was passed to \
                 issue_automatic_refund_if_memo_not_offerred. This indicates that \
                 we have some kind of bug. No refund will be issued.",
                incoming_block_index,
            );

            return Ok(());
        }
    };

    // Set block's status to Processing before calling ledger.
    let reason_for_refund = format!(
        "Memo ({:#08X}) in the incoming ICP transfer does not correspond to \
         any of the operations that the Cycles Minting canister offers.",
        memo.0,
    );
    if let Err(prior_block_status) = set_block_status_to_processing(incoming_block_index) {
        let Some(prior_block_status) = prior_block_status else {
            // Callers of fetch_transaction generally do this already.
            return Err(NotifyError::TransactionTooOld(with_state(|state| {
                state.last_purged_notification + 1
            })));
        };

        // Do not proceed, because block is either being processed, or was
        // finished being processed earlier.
        use NotificationStatus::{
            self as Status, NotifiedCreateCanister, NotifiedMint, NotifiedTopUp, Processing,
        };
        return match prior_block_status {
            Processing => Err(NotifyError::Processing),

            Status::NotMeaningfulMemo(NotMeaningfulMemo { refund_block_index }) => {
                Err(NotifyError::Refunded {
                    block_index: refund_block_index,
                    reason: reason_for_refund,
                })
            }

            // There is no (known) way to reach this case, since a check
            // earlier in this function ensures by this point, memo is not one
            // of the special meaningful values.
            NotifiedCreateCanister(_) | NotifiedMint(_) | NotifiedTopUp(_) => {
                Err(NotifyError::InvalidTransaction(format!(
                    "Block has already been processed: {prior_block_status:?}",
                )))
            }
        };
    }

    // Now, it is safe to call ledger to send the ICP back, so do it.
    let refund_block_index = refund_icp(
        incoming_to_subaccount,
        incoming_from,
        incoming_amount,
        Tokens::from_e8s(0), // extra_fee
    )
    .await
    .inspect_err(|_err| {
        // This allows the user to retry.
        clear_block_processing_status(incoming_block_index);
    })?;

    // Sending the ICP back succeeded. Therefore, update the block's status to
    // NotMeaningfulMemo.
    let old_entry_value = with_state_mut(|state| {
        state.blocks_notified.insert(
            incoming_block_index,
            NotificationStatus::NotMeaningfulMemo(NotMeaningfulMemo { refund_block_index }),
        )
    });
    // Log if the block's previous status somehow changed out from under us
    // while we were waiting for the ledger call to return. There is no known
    // way for this to happen (except, ofc, bugs).
    if old_entry_value != Some(NotificationStatus::Processing) {
        println!(
            "[cycles] ERROR: After issuing an automatic refund, the \
             incoming block's status was not Processing, even though \
             we checked this before calling ledger! {:?}",
            old_entry_value,
        );
    }

    Err(NotifyError::Refunded {
        reason: reason_for_refund,
        block_index: refund_block_index,
    })
}

// If conversion fails, log and return an error
fn tokens_to_cycles(amount: Tokens) -> Result<Cycles, NotifyError> {
    with_state(|state| {
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
                let error_message =
                    "No conversion rate found in CMC, notification aborted".to_string();
                print(&error_message);
                Err(NotifyError::Other {
                    error_code: NotifyErrorCode::Internal as u64,
                    error_message,
                })
            }
        }
    })
}

async fn process_create_canister(
    controller: PrincipalId,
    from: AccountIdentifier,
    amount: Tokens,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettingsArgs>,
) -> Result<CanisterId, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;

    let sub = Subaccount::from(&controller);

    print(format!(
        "Creating canister with controller {controller} with {cycles} cycles.",
    ));

    // Create the canister. If this fails, refund. Either way,
    // return a result so that the notification cannot be retried.
    // If refund fails, we allow to retry.
    match do_create_canister(controller, cycles, subnet_selection, settings).await {
        Ok(canister_id) => {
            burn_and_log(sub, amount).await;
            Ok(canister_id)
        }
        Err(err) => {
            let refund_block = refund_icp(sub, from, amount, CREATE_CANISTER_REFUND_FEE).await?;
            Err(NotifyError::Refunded {
                reason: err,
                block_index: refund_block,
            })
        }
    }
}

async fn process_mint_cycles(
    to_account: Account,
    amount: Tokens,
    deposit_memo: Option<Vec<u8>>,
    from: AccountIdentifier,
    sub: Subaccount,
) -> NotifyMintCyclesResult {
    let cycles = tokens_to_cycles(amount)?;
    match do_mint_cycles(to_account, cycles, deposit_memo).await {
        Ok(deposit_result) => {
            burn_and_log(sub, amount).await;
            Ok(NotifyMintCyclesSuccess {
                block_index: deposit_result.block_index,
                minted: cycles.into(),
                balance: deposit_result.balance,
            })
        }
        Err(err) => {
            let refund_block = refund_icp(sub, from, amount, MINT_CYCLES_REFUND_FEE).await?;
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
    limiter_to_use: CyclesMintingLimiterSelector,
) -> Result<Cycles, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;

    let sub = Subaccount::from(&canister_id);

    print(format!(
        "Topping up canister {canister_id} by {cycles} cycles."
    ));

    match deposit_cycles(canister_id, cycles, true, limiter_to_use).await {
        Ok(()) => {
            burn_and_log(sub, amount).await;
            Ok(cycles)
        }
        Err(err) => {
            let refund_block = refund_icp(sub, from, amount, TOP_UP_CANISTER_REFUND_FEE).await?;
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
    let msg = format!("Burning of {amount} ICPTs from subaccount {from_subaccount}");
    let minting_account_id = with_state(|state| state.minting_account_id);
    if minting_account_id.is_none() {
        print(format!("{msg} failed: minting_account_id not set"));
        return;
    }
    let minting_account_id = minting_account_id.unwrap();
    let ledger_canister_id = with_state(|state| state.ledger_canister_id);

    if amount < DEFAULT_TRANSFER_FEE {
        print(format!("{msg}: amount too small ({amount})"));
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
    let res: CallResult<BlockIndex> = call_protobuf(ledger_canister_id, "send_pb", send_args).await;

    match res {
        Ok(block) => print(format!("{msg} done in block {block}.")),
        Err((code, err)) => {
            let code = code as i32;
            print(format!("{msg} failed with code {code}: {err:?}"))
        }
    }
}

/// Send the funds for canister creation or top up back to the sender,
/// minus the transaction fee (which is gone) and the fee for the
/// action (which is burned). Returns the index of the block in which
/// the refund was done.
async fn refund_icp(
    from_subaccount: Subaccount,
    to: AccountIdentifier,
    amount: Tokens,
    extra_fee: Tokens,
) -> Result<Option<BlockIndex>, NotifyError> {
    let ledger_canister_id = with_state(|state| state.ledger_canister_id);
    let mut refund_block_index = None;

    let mut burned = amount;
    let mut refunded = Tokens::ZERO;
    if let Ok(to_refund) = amount
        .checked_sub(&DEFAULT_TRANSFER_FEE)
        .ok_or("Underflow in subtracting the fee from amount")
        .and_then(|x| {
            x.checked_sub(&extra_fee)
                .ok_or("Underflow in subtracting the extra fee from the amount")
        })
        && to_refund > Tokens::ZERO
    {
        burned = extra_fee;
        refunded = to_refund;
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
        let send_res: CallResult<BlockIndex> =
            call_protobuf(ledger_canister_id, "send_pb", send_args).await;
        let block = send_res.map_err(|(code, err)| {
            let code = code as i32;
            NotifyError::Other {
                error_code: NotifyErrorCode::RefundFailed as u64,
                error_message: format!("Refund to {to} failed with code {code}: {err}"),
            }
        })?;

        print(format!("Refund to {to} done in block {block}."));

        refund_block_index = Some(block);
    }

    if burned > Tokens::ZERO {
        burn_and_log(from_subaccount, burned).await;
    }

    Ok(refund_block_index)
}

async fn deposit_cycles(
    canister_id: CanisterId,
    cycles: Cycles,
    mint_cycles: bool,
    limiter_to_use: CyclesMintingLimiterSelector,
) -> Result<(), String> {
    if mint_cycles {
        ensure_balance(cycles, limiter_to_use)?;
    }

    let res: CallResult<()> = ic_cdk::api::call::call_with_payment128(
        IC_00.get().0,
        &Method::DepositCycles.to_string(),
        (CanisterIdRecord::from(canister_id),),
        u128::from(cycles),
    )
    .await;

    res.map_err(|(code, msg)| {
        format!(
            "Depositing cycles failed with code {}: {:?}",
            code as i32, msg
        )
    })?;

    Ok(())
}

async fn do_mint_cycles(
    account: Account,
    cycles: Cycles,
    deposit_memo: Option<Vec<u8>>,
) -> Result<CyclesLedgerDepositResult, String> {
    let Some(cycles_ledger_canister_id) = with_state(|state| state.cycles_ledger_canister_id)
    else {
        return Err("No cycles ledger canister id configured.".to_string());
    };
    // Always use base cycles limit for minting cycles, since the Subnet Rental Canister
    // doesn't call endpoints using this function.
    ensure_balance(cycles, CyclesMintingLimiterSelector::BaseLimit)?;

    let arg = CyclesLedgerDepositArgs {
        to: account,
        memo: deposit_memo,
    };

    let result: CallResult<(CyclesLedgerDepositResult,)> = ic_cdk::api::call::call_with_payment128(
        cycles_ledger_canister_id.get().0,
        "deposit",
        (arg,),
        u128::from(cycles),
    )
    .await;

    result.map(|r| r.0).map_err(|(code, msg)| {
        format!(
            "Cycles ledger rejected deposit call with code {}: {:?}",
            code as i32, msg
        )
    })
}

async fn do_create_canister(
    controller_id: PrincipalId,
    cycles: Cycles,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettingsArgs>,
) -> Result<CanisterId, String> {
    // Retrieve randomness from the system to use later to get a random
    // permutation of subnets. Performing the asynchronous call before
    // we retrieve the list of subnets to avoid having the list of
    // subnets change in the meantime.
    let mut rng = get_rng().await?;

    // If subnet_selection is set, then use it to determine the eligible list
    // of subnets. Otherwise, fall back to the list of subnets for the
    // provided controller id.

    let mut subnets: Vec<SubnetId> = match subnet_selection {
        Some(option) => match option {
            SubnetSelection::Filter(subnet_filter) => {
                with_state(|state| match subnet_filter.subnet_type {
                    Some(subnet_type) => {
                        let subnet_types_to_subnets = state
                            .subnet_types_to_subnets
                            .as_ref()
                            .expect("subnet types to subnets mapping is `None`");
                        subnet_types_to_subnets
                            .get(&subnet_type)
                            .map(|set| set.iter().cloned().collect())
                            .ok_or(format!("Provided subnet type {subnet_type} does not exist"))
                    }
                    None => Ok(get_subnets_for(&controller_id)),
                })
            }
            SubnetSelection::Subnet { subnet } => with_state(|state| {
                if state.default_subnets.contains(&subnet)
                    || state
                        .authorized_subnets
                        .get(&controller_id)
                        .map(|subnets| subnets.contains(&subnet))
                        .unwrap_or(false)
                    || state
                        .subnet_types_to_subnets
                        .as_ref()
                        .map(|types_to_subnets| {
                            types_to_subnets
                                .values()
                                .any(|subnets| subnets.contains(&subnet))
                        })
                        .unwrap_or(false)
                {
                    Ok(vec![subnet])
                } else {
                    Err(format!(
                        "Subnet {subnet} does not exist or {controller_id} is not authorized to deploy to that subnet."
                    ))
                }
            }),
        },
        None => Ok(get_subnets_for(&controller_id)),
    }?;

    // Perform a random permutation of the eligible list of subnets to ensure
    // that we load balance canister creations among them.
    subnets.shuffle(&mut rng);

    let mut last_err = None;

    if subnets.is_empty() {
        return Err("No subnets in which to create a canister.".to_owned());
    }

    // We have subnets available, so we can now mint the cycles and create the canister.

    // Always use base cycles limit for minting cycles, since the Subnet Rental Canister
    // doesn't call endpoints using this function.
    ensure_balance(cycles, CyclesMintingLimiterSelector::BaseLimit)?;

    let canister_settings = settings
        .map(|mut settings| {
            if settings.controllers.is_none() {
                settings.controllers = Some(BoundedVec::new(vec![controller_id]));
            }
            settings
        })
        .unwrap_or_else(|| {
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![controller_id])
                .build()
        });

    for subnet_id in subnets {
        let result: CallResult<(CanisterIdRecord,)> = ic_cdk::api::call::call_with_payment128(
            subnet_id.get().0,
            &Method::CreateCanister.to_string(),
            (CreateCanisterArgs {
                settings: Some(canister_settings.clone()),
                sender_canister_version: Some(ic_cdk::api::canister_version()),
            },),
            u128::from(cycles),
        )
        .await;

        let canister_id = match result {
            Ok(canister_id) => canister_id.0.get_canister_id(),
            Err((code, msg)) => {
                let err = format!(
                    "Creating canister in subnet {} failed with code {}: {}",
                    subnet_id, code as i32, msg
                );
                print(format!("[cycles] {err}"));
                last_err = Some(err);
                continue;
            }
        };

        print(format!(
            "[cycles] created canister {canister_id} in subnet {subnet_id}"
        ));

        return Ok(canister_id);
    }

    Err(last_err.unwrap_or_else(|| "Unknown problem attempting to create a canister.".to_owned()))
}

/// Ensure the Cycles Minting canister has at least `cycles` balance of cycles, otherwise, mint more
/// so that the balance of this canister is at least `cycles`.  If the `check_minting_limit` is true,
/// the minting limit is checked and enforced before minting, otherwise, the minting limit is ignored.
fn ensure_balance(
    cycles: Cycles,
    limiter_to_use: CyclesMintingLimiterSelector,
) -> Result<(), String> {
    let now = now_system_time();

    let current_balance = Cycles::from(ic_cdk::api::canister_balance128());
    let cycles_to_mint = cycles - current_balance;

    with_state_mut(|state| {
        limiter_to_use.check_and_add_cycles(state, now, cycles_to_mint)?;
        state.total_cycles_minted += cycles_to_mint;
        Ok::<_, String>(())
    })?;

    // unused because of check above
    let _minted_cycles = ic0_mint_cycles128(cycles_to_mint);
    assert!(ic_cdk::api::canister_balance128() >= cycles.get());
    Ok(())
}

#[query(hidden = true)]
fn total_cycles_minted() -> Nat {
    with_state(|state| state.total_cycles_minted.get().into())
}

/// Return the list of subnets in which this controller is allowed to create
/// canisters
fn get_subnets_for(controller_id: &PrincipalId) -> Vec<SubnetId> {
    with_state(|state| {
        if let Some(subnets) = state.authorized_subnets.get(controller_id) {
            subnets.clone()
        } else {
            state.default_subnets.clone()
        }
    })
}

async fn get_rng() -> Result<StdRng, String> {
    let res: CallResult<(Vec<u8>,)> =
        ic_cdk::call(IC_00.get().0, &Method::RawRand.to_string(), ()).await;

    let bytes = res
        .map_err(|(code, msg)| {
            format!(
                "Getting random bytes failed with code {}: {:?}",
                code as i32, msg
            )
        })?
        .0;

    Ok(StdRng::from_seed(bytes[0..32].try_into().unwrap()))
}

#[pre_upgrade]
fn pre_upgrade() {
    let bytes = with_state(|state| state.encode());
    print(format!(
        "[cycles] serialized state prior to upgrade ({} bytes)",
        bytes.len(),
    ));
    stable_utils::stable_set(&bytes).expect("Could not write data to stable memory");
}

#[post_upgrade]
fn post_upgrade(maybe_args: Option<CyclesCanisterInitPayload>) {
    let bytes = stable_utils::stable_get().expect("Could not read data from stable memory");
    print(format!(
        "[cycles] deserializing state after upgrade ({} bytes)",
        bytes.len(),
    ));

    let mut new_state = State::decode(&bytes).unwrap();
    if new_state.subnet_types_to_subnets.is_none() {
        new_state.subnet_types_to_subnets = Some(BTreeMap::new());
    }

    if let Some(args) = maybe_args {
        if let Some(xrc_flag) = args.exchange_rate_canister {
            new_state.exchange_rate_canister_id = xrc_flag.extract_exchange_rate_canister_id();
        }
        new_state.cycles_ledger_canister_id = args.cycles_ledger_canister_id;
    }

    STATE.with(|state| state.replace(Some(new_state)));
}

#[heartbeat]
async fn canister_heartbeat() {
    if with_state(|state| state.exchange_rate_canister_id.is_some()) {
        update_exchange_rate().await
    }
}

async fn update_exchange_rate() {
    let xrc_client = match with_state(|state| state.exchange_rate_canister_id) {
        Some(exchange_rate_canister_id) => {
            RealExchangeRateCanisterClient::new(exchange_rate_canister_id)
        }
        None => {
            print("[cycles] Exchange rate canister ID must be set to call the XRC");
            return;
        }
    };
    let env = CanisterEnvironment;
    let periodic_result =
        exchange_rate_canister::update_exchange_rate(&STATE, &env, &xrc_client).await;
    if let Err(ref error) = periodic_result {
        match error {
            UpdateExchangeRateError::InvalidRate(_)
            | UpdateExchangeRateError::FailedToRetrieveRate(_)
            | UpdateExchangeRateError::FailedToSetRate(_) => {
                print(format!("[cycles] {error}"));
            }
            UpdateExchangeRateError::Disabled
            | UpdateExchangeRateError::NotReadyToGetRate(_)
            | UpdateExchangeRateError::UpdateAlreadyInProgress => {}
        }
    }
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    with_state(|state| {
        w.encode_gauge(
            "cmc_last_purged_notification",
            state.last_purged_notification as f64,
            "Block index of the last purged notification.",
        )?;
        w.encode_gauge(
            "cmc_blocks_notified_count",
            state.blocks_notified.len() as f64,
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
        w.encode_gauge(
            "cmc_avg_icp_xdr_conversion_rate",
            state
                .average_icp_xdr_conversion_rate
                .as_ref()
                .unwrap()
                .xdr_permyriad_per_icp as f64
                / 10_000f64,
            "Average amount of XDR corresponding to 1 ICP.",
        )?;
        w.encode_gauge(
            "cmc_avg_icp_xdr_conversion_rate_timestamp_seconds",
            state
                .average_icp_xdr_conversion_rate
                .as_ref()
                .unwrap()
                .timestamp_seconds as f64,
            "Timestamp of the last update to the Average ICP/XDR conversion rate, in seconds since the Unix epoch.",
        )?;
        w.encode_gauge(
            "cmc_icp_xdr_conversion_rate_timestamp_seconds",
            state
                .icp_xdr_conversion_rate
                .as_ref()
                .unwrap()
                .timestamp_seconds as f64,
            "Timestamp of the last ICP/XDR conversion rate, in seconds since the Unix epoch.",
        )?;
        w.encode_gauge(
            "cmc_update_exchange_rate_canister_state",
            u8::from(state.update_exchange_rate_canister_state.as_ref().unwrap()) as f64,
            "The current state of the CMC calling the exchange rate canister.",
        )?;

        w.encode_gauge(
            "cmc_limiter_reject_count",
            LIMITER_REJECT_COUNT.with(|count| count.get()) as f64,
            "The number of times that the limiter has blocked a minting request \
             (since the last upgrade of this canister, or when it was first \
             installed).",
        )?;
        w.encode_gauge(
            "cmc_limiter_cycles",
            state.base_limiter.get_count().get() as f64,
            "The amount of cycles minted in the recent past. If someone tries \
             to mint N cycles, but N + the value of this metric exceeds \
             cmc_cycles_limit, then the request will be rejected.",
        )?;
        w.encode_gauge(
            "cmc_cycles_limit",
            state.base_cycles_limit.get() as f64,
            "The maximum amount of cycles that can be minted in the recent past. \
             More precisely, if someone tries to mint N cycles, and \
             N + cmc_limiter_cycles > cmc_cycles_limit, then the request will \
             be rejected.",
        )?;
        w.encode_gauge(
            "cmc_subnet_rental_limiter_cycles",
            state.subnet_rental_canister_limiter.get_count().get() as f64,
            "The amount of cycles minted in the recent past for the Subnet Rental Canister. \
             If someone tries to mint N cycles, but N + the value of this metric exceeds \
             cmc_subnet_rental_cycles_limit, then the request will be rejected.",
        )?;
        w.encode_gauge(
            "cmc_subnet_rental_cycles_limit",
            state.subnet_rental_cycles_limit.get() as f64,
            "The maximum amount of cycles that can be minted in the recent past for the Subnet \
             Rental Canister. 1GMore precisely, if someone tries to mint N cycles, and \
             N + cmc_limiter_cycles > cmc_subnet_rental_cycles_limit, then the request will \
             be rejected.",
        )?;

        Ok(())
    })
}

fn get_subnet_selection(
    subnet_type: Option<String>,
    subnet_selection: Option<SubnetSelection>,
) -> Result<Option<SubnetSelection>, String> {
    if subnet_type.is_some() && subnet_selection.is_some() {
        Err("Cannot specify subnet_type and subnet_selection at the same time.".to_string())
    } else if let Some(subnet_type) = subnet_type {
        Ok(Some(SubnetSelection::Filter(SubnetFilter {
            subnet_type: Some(subnet_type),
        })))
    } else {
        Ok(subnet_selection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types_test_utils::ids::{subnet_test_id, user_test_id};
    use maplit::btreemap;
    use rand::Rng;
    use serde_bytes::ByteBuf;
    use std::str::FromStr;

    pub(crate) fn init_test_state() {
        init(Some(CyclesCanisterInitPayload {
            ledger_canister_id: Some(CanisterId::ic_00()),
            governance_canister_id: Some(CanisterId::ic_00()),
            exchange_rate_canister: None,
            minting_account_id: None,
            cycles_ledger_canister_id: None,
            last_purged_notification: Some(0),
        }))
    }

    #[test]
    fn test_state_encode() {
        let mut state = State {
            minting_account_id: Some(AccountIdentifier::new(
                PrincipalId::new_user_test_id(1),
                None,
            )),
            default_subnets: vec![SubnetId::from(PrincipalId::new_subnet_test_id(123))],
            total_cycles_minted: Cycles::new(1234),
            last_purged_notification: 33,
            ..Default::default()
        };
        state.authorized_subnets.insert(
            PrincipalId::new_user_test_id(2),
            vec![SubnetId::from(PrincipalId::new_subnet_test_id(3))],
        );
        let mut blocks_notified = BTreeMap::new();
        for i in 50..60 {
            blocks_notified.insert(
                i,
                NotificationStatus::NotifiedTopUp(Ok(Cycles::new(i as u128))),
            );
        }
        blocks_notified.insert(
            60,
            NotificationStatus::NotifiedCreateCanister(Ok(CanisterId::unchecked_from_principal(
                PrincipalId::new_user_test_id(4),
            ))),
        );
        state.blocks_notified = blocks_notified;

        let bytes = state.encode();

        let state2 = State::decode(&bytes).unwrap();

        assert_eq!(state, state2);
    }

    #[test]
    fn test_authorize_caller_to_call_notify_create_canister_on_behalf_of_creator() {
        let creator = PrincipalId::new_user_test_id(519_167_122);
        let authorize = |caller| {
            authorize_caller_to_call_notify_create_canister_on_behalf_of_creator(caller, creator)
        };

        let on_behalf_of_self_result = authorize(creator);
        assert!(
            on_behalf_of_self_result.is_ok(),
            "{on_behalf_of_self_result:#?}",
        );

        let eve = PrincipalId::new_user_test_id(898_071_769);
        let on_behalf_of_other_result = authorize(eve);
        assert!(
            on_behalf_of_other_result.is_err(),
            "{on_behalf_of_other_result:#?}",
        );
        let err = on_behalf_of_other_result.unwrap_err();
        match &err {
            NotifyError::Other {
                error_code,
                error_message,
            } => {
                assert_eq!(
                    *error_code,
                    NotifyErrorCode::Unauthorized as u64,
                    "{err:#?}",
                );

                let error_message = error_message.to_lowercase();
                for key_word in ["authorize", "on behalf"] {
                    assert!(
                        error_message.contains(key_word),
                        "{key_word} not in {err:#?}",
                    );
                }
            }

            _ => panic!("{err:#?}"),
        }

        let caller_is_nns_dapp_result = authorize(PrincipalId::from(*NNS_DAPP_BACKEND_CANISTER_ID));
        assert!(
            caller_is_nns_dapp_result.is_ok(),
            "{caller_is_nns_dapp_result:#?}",
        );

        // Also allow nns-dapp backend canister ID used in test.
        let caller_is_nns_dapp_result =
            authorize(PrincipalId::from_str("qsgjb-riaaa-aaaaa-aaaga-cai").unwrap());
        assert!(
            caller_is_nns_dapp_result.is_ok(),
            "{caller_is_nns_dapp_result:#?}",
        );
    }

    #[test]
    fn test_purge_notifications() {
        fn block_index_to_cycles(block_index: BlockIndex) -> Cycles {
            Cycles::new(block_index as u128)
        }
        let mut state = State {
            last_purged_notification: 0,
            ..Default::default()
        };
        let initial_number_of_notifications = 100;
        let mut blocks_notified = BTreeMap::new();
        for i in 0..initial_number_of_notifications {
            blocks_notified.insert(
                i,
                NotificationStatus::NotifiedTopUp(Ok(block_index_to_cycles(i))),
            );
        }
        state.blocks_notified = blocks_notified;

        let target_history_len = 30;
        state.purge_old_notifications(target_history_len);
        let most_recent_transaction_index = initial_number_of_notifications - 1;
        let expected_oldest_transaction_index =
            initial_number_of_notifications - target_history_len as u64;
        let expected_last_purged = expected_oldest_transaction_index - 1;
        assert_eq!(state.last_purged_notification, expected_last_purged);
        assert_eq!(state.blocks_notified.get(&expected_last_purged), None);
        assert_eq!(
            state
                .blocks_notified
                .get(&expected_oldest_transaction_index),
            Some(&NotificationStatus::NotifiedTopUp(Ok(
                block_index_to_cycles(expected_oldest_transaction_index)
            )))
        );
        assert_eq!(
            state.blocks_notified.get(&most_recent_transaction_index),
            Some(&NotificationStatus::NotifiedTopUp(Ok(
                block_index_to_cycles(most_recent_transaction_index)
            )))
        );
    }

    /// The function returns sample conversion rates set for testing.
    fn get_sample_conversion_rates(timestamp: u64) -> Vec<IcpXdrConversionRate> {
        let average_rate_interval = NUM_DAYS_FOR_ICP_XDR_AVERAGE as u64;
        let maturity_modulation_interval = ICP_XDR_CONVERSION_RATE_CACHE_SIZE as u64;
        // The timestamp has to the start of a day.
        let start_of_day = (timestamp / 86_400) * 86_400;
        // Define some rates that will be used in tests.
        let rates = vec![
            IcpXdrConversionRate {
                timestamp_seconds: start_of_day + 27542, // The record at this time will not be used
                xdr_permyriad_per_icp: 1_010_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: start_of_day, // Midnight
                xdr_permyriad_per_icp: 1_000_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: start_of_day - 86_400, // Midnight, previous day
                xdr_permyriad_per_icp: 1_110_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: start_of_day - 86_401, // One minute before midnight, previous day (ignored)
                xdr_permyriad_per_icp: 1_510_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: start_of_day - 2 * 86_400 + 60, // 1 minute after midnight, two days before
                xdr_permyriad_per_icp: 1_520_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: start_of_day - 7 * 86_400, // Midnight, seven days before.
                xdr_permyriad_per_icp: 880_000,
            },
            IcpXdrConversionRate {
                timestamp_seconds: (start_of_day - (average_rate_interval - 1) * 86_400),
                xdr_permyriad_per_icp: 1_090_000,
            },
            IcpXdrConversionRate {
                // This record is too old for the average ICP/XDR rate but still used for the
                // maturity modulation.
                timestamp_seconds: (start_of_day - (maturity_modulation_interval - 1) * 86_400),
                xdr_permyriad_per_icp: 1_500_000,
            },
            IcpXdrConversionRate {
                // This record is too old and should be ignored entirely.
                timestamp_seconds: (start_of_day - maturity_modulation_interval * 86_400),
                xdr_permyriad_per_icp: 1_808_000,
            },
        ];
        rates
    }

    #[test]
    /// The function verifies that a default ICP/XDR conversion rate is set.
    fn test_default_icp_xdr_conversion_rate() {
        let expected_initial_rate = IcpXdrConversionRate {
            timestamp_seconds: DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS,
            xdr_permyriad_per_icp: DEFAULT_XDR_PERMYRIAD_PER_ICP_CONVERSION_RATE,
        };

        let state = State::default();
        assert_eq!(
            state.icp_xdr_conversion_rate,
            Some(expected_initial_rate.clone()),
        );
        assert_eq!(
            state.average_icp_xdr_conversion_rate,
            Some(expected_initial_rate),
        );
    }

    #[test]
    /// The function tests if the average ICP/XDR conversion rate is computed correctly.
    fn test_average_icp_xdr_price_with_sample_rates() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let timestamp = 1_632_700_800;
        let rates = get_sample_conversion_rates(timestamp);
        // The average of the rates in the sample rates that are used for the ICP/XDR price.
        let chosen_rates_sum: u64 = 1_000_000 + 1_110_000 + 1_520_000 + 880_000 + 1_090_000;
        let average_rate = IcpXdrConversionRate {
            timestamp_seconds: 1_632_700_800,
            xdr_permyriad_per_icp: chosen_rates_sum / 5,
        };
        // The state is updated with all rates in reverse order (oldest to newest).
        mutate_state(&STATE, |state| {
            for rate in rates.iter().rev() {
                update_recent_icp_xdr_rates(state, rate);
            }
        });
        let recent_rates = read_state(&STATE, |state| {
            state.recent_icp_xdr_rates.clone().unwrap_or_default()
        });
        let computed_average_rate =
            compute_average_icp_xdr_rate_at_time(&recent_rates, timestamp).unwrap();
        // Assert that the rates are identical.
        assert_eq!(average_rate, computed_average_rate);
    }

    #[test]
    /// The function tests if the average ICP/XDR conversion rate is computed correctly for
    /// random input.
    fn test_random_average_icp_xdr_price() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        // Set a timestamp.
        let timestamp: u64 = 1_632_728_342;
        // Get a random number generator.
        let mut rng = rand::rng();
        // The sum of all the valid rates, i.e., the rates at midnight.
        let mut valid_rates_sum = 0;
        // Iterate over two intervals (half of which should be ignored), from the oldest
        // to the latest rate.
        for day in (0..2 * NUM_DAYS_FOR_ICP_XDR_AVERAGE).rev() {
            // Generate a valid rate, i.e., the ICP/XDR rate at midnight.
            let valid_rate: u64 = rng.random_range(1_000_000..10_000_000);
            // The rate is only counted if it is not older than
            // `NUM_DAYS_FOR_ICP_XDR_AVERAGE` days.
            if day < NUM_DAYS_FOR_ICP_XDR_AVERAGE {
                valid_rates_sum += valid_rate;
            }
            mutate_state(&STATE, |state| {
                // Add a rate one second before midnight (this rate will be ignored).
                update_recent_icp_xdr_rates(
                    state,
                    &IcpXdrConversionRate {
                        timestamp_seconds: ((1_632_700_800 - day * 86_400) - 1) as u64,
                        xdr_permyriad_per_icp: rng.random_range(1_000_000..10_000_000),
                    },
                );
                // Add a rate at midnight.
                update_recent_icp_xdr_rates(
                    state,
                    &IcpXdrConversionRate {
                        timestamp_seconds: (1_632_700_800 - day * 86_400) as u64,
                        xdr_permyriad_per_icp: valid_rate,
                    },
                );
                // Add a rate one second after midnight (this rate will be ignored).
                update_recent_icp_xdr_rates(
                    state,
                    &IcpXdrConversionRate {
                        timestamp_seconds: ((1_632_700_800 - day * 86_400) + 1) as u64,
                        xdr_permyriad_per_icp: rng.random_range(1_000_000..10_000_000),
                    },
                );
            });
        }
        // Get the average of the valid ICP/XDR rates in the last
        // `NUM_DAYS_FOR_ICP_XDR_AVERAGE` days.
        let average_rate = IcpXdrConversionRate {
            timestamp_seconds: (timestamp / 86_400) * 86_400,
            xdr_permyriad_per_icp: valid_rates_sum / (NUM_DAYS_FOR_ICP_XDR_AVERAGE as u64),
        };
        let recent_rates = read_state(&STATE, |state| {
            state.recent_icp_xdr_rates.clone().unwrap_or_default()
        });
        let computed_average_rate =
            compute_average_icp_xdr_rate_at_time(&recent_rates, timestamp).unwrap();
        // Assert that the rates are identical.
        assert_eq!(average_rate, computed_average_rate);
    }

    #[test]
    /// The function tests if the maturity modulation is computed correctly using sample rates.
    fn test_maturity_modulation_with_sample_rates() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        let timestamp = 1_632_700_800;
        let rates = get_sample_conversion_rates(timestamp);
        // The state is updated with all rates in reverse order (oldest to newest).
        mutate_state(&STATE, |state| {
            for rate in rates.iter().rev() {
                update_recent_icp_xdr_rates(state, rate);
            }
        });
        let recent_rates = read_state(&STATE, |state| state.recent_icp_xdr_rates.clone().unwrap());
        let computed_maturity_modulation = compute_maturity_modulation(&recent_rates, timestamp);
        // The are only 5 rates (1_000_000 + 1_110_000 + 1_520_000 + 880_000 + 1_090_000) for the
        // average rate ending with the given timestamp, yielding an average rate of 1_120_000.
        // For the average rate seven days ago, there are only two rates (880_000 + 1_090_000), i.e.,
        // the 30-day average starting on that day is 985_000.
        // The relative change is (1_120_000 - 985_000) / 985_000 = 0.137, exceeding 5%.
        // Capping this value at 5%, the maturity modulation is 1.25% because the other three terms
        // are all zero for the sample rates.
        assert_eq!(125, computed_maturity_modulation);
    }

    #[test]
    /// The function tests if the maturity modulation is computed correctly for
    /// random input.
    fn test_random_maturity_modulation() {
        thread_local! {
            static STATE: RefCell<Option<State>> = RefCell::new(Some(State::default()));
        }

        // Create random start-of-day conversion rates.
        let mut current_rate: i32 = 100_000;
        let mut rng = rand::rng();
        let mut rates = vec![];
        let mut timestamp = 1658102400;
        for _index in 0..ICP_XDR_CONVERSION_RATE_CACHE_SIZE {
            rates.push(IcpXdrConversionRate {
                timestamp_seconds: timestamp,
                xdr_permyriad_per_icp: current_rate as u64,
            });
            current_rate += rng.random_range(0..20_000) - 10_000;
            if current_rate < 0 {
                current_rate = 100_000;
            }
            timestamp -= 86400;
        }

        // Get the maturity modulation.
        mutate_state(&STATE, |state| {
            for rate in rates.iter().rev() {
                update_recent_icp_xdr_rates(state, rate);
            }
        });
        let recent_rates = read_state(&STATE, |state| state.recent_icp_xdr_rates.clone().unwrap());
        let computed_maturity_modulation = compute_maturity_modulation(&recent_rates, 1658102400);

        // Compute maturity modulation by hand.
        let interval = NUM_DAYS_FOR_ICP_XDR_AVERAGE;
        let a0 = (rates[0..interval]
            .iter()
            .map(|rate| rate.xdr_permyriad_per_icp)
            .sum::<u64>() as i32)
            / (interval as i32);
        let a7 = (rates[7..7 + interval]
            .iter()
            .map(|rate| rate.xdr_permyriad_per_icp)
            .sum::<u64>() as i32)
            / (interval as i32);
        let a14 = (rates[14..14 + interval]
            .iter()
            .map(|rate| rate.xdr_permyriad_per_icp)
            .sum::<u64>() as i32)
            / (interval as i32);
        let a21 = (rates[21..21 + interval]
            .iter()
            .map(|rate| rate.xdr_permyriad_per_icp)
            .sum::<u64>() as i32)
            / (interval as i32);
        let a28 = (rates[28..28 + interval]
            .iter()
            .map(|rate| rate.xdr_permyriad_per_icp)
            .sum::<u64>() as i32)
            / (interval as i32);

        let term1 = (10_000 * (a0 - a7) / a7).clamp(
            MIN_MATURITY_MODULATION_PERMYRIAD,
            MAX_MATURITY_MODULATION_PERMYRIAD,
        );
        let term2 = (10_000 * (a7 - a14) / a14).clamp(
            MIN_MATURITY_MODULATION_PERMYRIAD,
            MAX_MATURITY_MODULATION_PERMYRIAD,
        );
        let term3 = (10_000 * (a14 - a21) / a21).clamp(
            MIN_MATURITY_MODULATION_PERMYRIAD,
            MAX_MATURITY_MODULATION_PERMYRIAD,
        );
        let term4 = (10_000 * (a21 - a28) / a28).clamp(
            MIN_MATURITY_MODULATION_PERMYRIAD,
            MAX_MATURITY_MODULATION_PERMYRIAD,
        );

        let maturity_modulation = (term1 + term2 + term3 + term4) / 4;

        assert_eq!(maturity_modulation, computed_maturity_modulation);
    }

    #[test]
    fn test_add_subnet_type() {
        init_test_state();

        assert_eq!(add_subnet_type("Fiduciary".to_string()), Ok(()));
        assert_eq!(add_subnet_type("Storage".to_string()), Ok(()));

        assert_eq!(
            add_subnet_type("Storage".to_string()),
            Err(UpdateSubnetTypeError::Duplicate("Storage".to_string()))
        );
    }

    #[test]
    fn test_remove_subnet_type() {
        init_test_state();

        add_subnet_type("Fiduciary".to_string()).unwrap();
        add_subnet_type("Storage".to_string()).unwrap();
        let subnet1 = subnet_test_id(0);
        let subnet2 = subnet_test_id(1);
        add_subnets_to_type(vec![subnet1, subnet2], "Fiduciary".to_string()).unwrap();

        assert_eq!(remove_subnet_type("Storage".to_string()), Ok(()));

        assert_eq!(
            remove_subnet_type("MyType".to_string()),
            Err(UpdateSubnetTypeError::TypeDoesNotExist(
                "MyType".to_string()
            ))
        );

        assert_eq!(
            remove_subnet_type("Fiduciary".to_string()),
            Err(UpdateSubnetTypeError::TypeHasAssignedSubnets((
                "Fiduciary".to_string(),
                vec![subnet1, subnet2]
            )))
        );
    }

    #[test]
    fn test_add_subnets_to_type() {
        let type1 = "Type1".to_string();
        let type2 = "Type2".to_string();
        let type3 = "Type3".to_string();

        let subnet1 = subnet_test_id(0);
        let subnet2 = subnet_test_id(1);
        let subnet3 = subnet_test_id(2);
        let subnet4 = subnet_test_id(3);
        let subnet5 = subnet_test_id(4);
        let subnet6 = subnet_test_id(5);

        let mut authorized_subnets = BTreeMap::new();
        authorized_subnets.insert(user_test_id(0).get(), vec![subnet5]);
        STATE.with(|state| {
            state.replace(Some(State {
                authorized_subnets,
                default_subnets: vec![subnet6],
                ..Default::default()
            }))
        });

        add_subnet_type(type1.clone()).unwrap();
        add_subnet_type(type2.clone()).unwrap();
        add_subnet_type(type3.clone()).unwrap();

        // Add subnet1 and subnet2 to "Type1".
        assert_eq!(
            add_subnets_to_type(vec![subnet1, subnet2], type1.clone()),
            Ok(())
        );

        // Add subnet3 to "Type2".
        assert_eq!(add_subnets_to_type(vec![subnet3], type2.clone()), Ok(()));

        // Attempt to add subnet2 and subnet3 to "Type3". Should fail because they are
        // already assigned to other types.
        assert_eq!(
            add_subnets_to_type(vec![subnet2, subnet3], type3.clone()),
            Err(ChangeSubnetTypeAssignmentError::SubnetsAreAssigned(vec![
                SubnetListWithType {
                    subnets: vec![subnet2],
                    subnet_type: type1,
                },
                SubnetListWithType {
                    subnets: vec![subnet3],
                    subnet_type: type2,
                }
            ]))
        );

        // Attempt to add subnet4 to subnet type "unknown" that does not exist.
        assert_eq!(
            add_subnets_to_type(vec![subnet4], "unknown".to_string()),
            Err(ChangeSubnetTypeAssignmentError::TypeDoesNotExist(
                "unknown".to_string()
            ))
        );

        // Attempt to add subnet5 and subnet6 to type3 but they are already
        // authorized for public access.
        assert_eq!(
            add_subnets_to_type(vec![subnet5, subnet6], type3),
            Err(ChangeSubnetTypeAssignmentError::SubnetsAreAuthorized(vec![
                subnet5, subnet6
            ]))
        );
    }

    #[test]
    fn test_remove_subnets_from_type() {
        init_test_state();

        let type1 = "Type1".to_string();
        let type2 = "Type2".to_string();
        let type3 = "Type3".to_string();

        add_subnet_type(type1.clone()).unwrap();
        add_subnet_type(type2.clone()).unwrap();
        add_subnet_type(type3.clone()).unwrap();

        let subnet1 = subnet_test_id(0);
        let subnet2 = subnet_test_id(1);
        let subnet3 = subnet_test_id(2);
        let subnet4 = subnet_test_id(3);

        // Add subnet1 and subnet2 to "Type1".
        // Add subnet3 and subnet4 to "Type2".
        add_subnets_to_type(vec![subnet1, subnet2], type1.clone()).unwrap();
        add_subnets_to_type(vec![subnet3, subnet4], type2.clone()).unwrap();

        // Remove a subnet from an existing type.
        assert_eq!(remove_subnets_from_type(vec![subnet4], type2), Ok(()));

        // Attempt to remove a subnet from an non-existing type.
        assert_eq!(
            remove_subnets_from_type(vec![subnet3], "unknown".to_string()),
            Err(ChangeSubnetTypeAssignmentError::TypeDoesNotExist(
                "unknown".to_string()
            ))
        );

        // Attempt to remove subnets from a type they do not belong to.
        assert_eq!(
            remove_subnets_from_type(vec![subnet2, subnet3], type3.clone()),
            Err(ChangeSubnetTypeAssignmentError::SubnetsAreNotAssigned(
                SubnetListWithType {
                    subnets: vec![subnet2, subnet3],
                    subnet_type: type3,
                }
            ))
        );

        // Remove multiple subnets from an existing type.
        assert_eq!(
            remove_subnets_from_type(vec![subnet1, subnet2], type1),
            Ok(())
        );
    }

    #[test]
    fn test_candid_interface_compatibility() {
        use candid_parser::utils::{CandidSource, service_equal};
        use std::path::PathBuf;

        candid::export_service!();
        let new_interface = __export_service();

        let old_interface =
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("cmc.did");

        service_equal(
            CandidSource::Text(&new_interface),
            CandidSource::File(old_interface.as_path()),
        )
        .expect("The CMC canister interface is not compatible with the cmc.did file");
    }

    #[test]
    fn test_transaction_has_expected_memo_happy() {
        // Not relevant to this test.
        let operation = Operation::Mint {
            to: AccountIdentifier::new(PrincipalId::new_user_test_id(668_857_347), None),
            amount: Tokens::from_e8s(123_456),
        };

        // Case A: Legacy memo is used.
        let transaction_with_legacy_memo = Transaction {
            memo: Memo(42),
            icrc1_memo: None,

            // Irrelevant to this test.
            operation: operation.clone(),
            created_at_time: None,
        };

        assert_eq!(
            transaction_has_expected_memo(&transaction_with_legacy_memo, Memo(42),),
            Ok(()),
        );

        // Case B: When the user uses icrc1's memo to indicate the purpose of
        // the transfer, and as a result the legacy memo field is implicitly set
        // to 0.
        let transaction_with_icrc1_memo = Transaction {
            memo: Memo(0),
            icrc1_memo: Some(ByteBuf::from(43_u64.to_le_bytes().to_vec())),

            // Irrelevant to this test.
            operation: operation.clone(),
            created_at_time: None,
        };

        assert_eq!(
            transaction_has_expected_memo(&transaction_with_icrc1_memo, Memo(43),),
            Ok(()),
        );
    }

    #[test]
    fn test_transaction_has_expected_memo_sad() {
        // Not relevant to this test.
        let operation = Operation::Mint {
            to: AccountIdentifier::new(PrincipalId::new_user_test_id(668_857_347), None),
            amount: Tokens::from_e8s(123_456),
        };

        // Case A: Legacy memo is used.
        {
            let transaction = Transaction {
                memo: Memo(77),
                icrc1_memo: None,

                // Irrelevant to this test.
                operation: operation.clone(),
                created_at_time: None,
            };
            let result = transaction_has_expected_memo(&transaction, Memo(42));

            let original_err = match result {
                Err(NotifyError::InvalidTransaction(err)) => err,
                wrong => panic!("{wrong:?}"),
            };

            let lower_err = original_err.to_lowercase();
            for key_word in ["memo", "77", "42"] {
                assert!(
                    lower_err.contains(key_word),
                    "{key_word} not in {original_err:?}"
                );
            }
        }

        // Case B: When the user uses icrc1's memo to indicate the purpose of
        // the transfer, and as a result the legacy memo field is implicitly set
        // to 0.
        {
            let transaction = Transaction {
                memo: Memo(0),
                icrc1_memo: Some(ByteBuf::from(78_u64.to_le_bytes().to_vec())),

                // Irrelevant to this test.
                operation: operation.clone(),
                created_at_time: None,
            };

            let result = transaction_has_expected_memo(&transaction, Memo(42));

            let original_err = match result {
                Err(NotifyError::InvalidTransaction(err)) => err,
                wrong => panic!("{wrong:?}"),
            };

            let lower_err = original_err.to_lowercase();
            for key_word in ["memo", "78", "42"] {
                assert!(
                    lower_err.contains(key_word),
                    "{key_word} not in {original_err:?}"
                );
            }
        }

        // Case C: icrc1's memo is used, but is not of length 8, and we
        // therefore do not consider it to contain a (little endian) u64.
        {
            let transaction = Transaction {
                memo: Memo(0),
                icrc1_memo: Some(ByteBuf::from(vec![1, 2, 3])),

                // Irrelevant to this test.
                operation: operation.clone(),
                created_at_time: None,
            };

            let result = transaction_has_expected_memo(&transaction, Memo(42));

            let original_err = match result {
                Err(NotifyError::InvalidTransaction(err)) => err,
                wrong => panic!("{wrong:?}"),
            };

            let lower_err = original_err.to_lowercase();
            for key_word in ["memo", "0", "42"] {
                assert!(
                    lower_err.contains(key_word),
                    "{key_word} not in {original_err:?}"
                );
            }
        }

        // Case D: legacy memo is 0, and ircr1_memo is None.
        {
            let transaction = Transaction {
                memo: Memo(0),
                icrc1_memo: None,

                // Irrelevant to this test.
                operation: operation.clone(),
                created_at_time: None,
            };

            let result = transaction_has_expected_memo(&transaction, Memo(42));

            let original_err = match result {
                Err(NotifyError::InvalidTransaction(err)) => err,
                wrong => panic!("{wrong:?}"),
            };

            let lower_err = original_err.to_lowercase();
            for key_word in ["memo", "0", "42"] {
                assert!(
                    lower_err.contains(key_word),
                    "{key_word} not in {original_err:?}"
                );
            }
        }
    }

    #[test]
    fn test_set_block_status_to_processing_happy() {
        let red_herring_block_index = 0xDEADBEEF;
        STATE.with(|state| {
            state.replace(Some(State {
                blocks_notified: btreemap! {
                    red_herring_block_index => NotificationStatus::Processing,
                },
                ..Default::default()
            }))
        });

        let target_block_index = 42;
        let result = set_block_status_to_processing(target_block_index);

        assert_eq!(result, Ok(()));
        assert_eq!(
            with_state(|state| state.blocks_notified.clone()),
            btreemap! {
                // Existing data untouched.
                red_herring_block_index => NotificationStatus::Processing,
                // New entry.
                target_block_index => NotificationStatus::Processing,
            },
        );
    }

    #[test]
    fn test_set_block_status_to_processing_already_has_status() {
        let target_block_index = 42;
        let red_herring_block_index = 0xDEADBEEF;
        let original_blocks_notified = btreemap! {
            red_herring_block_index => NotificationStatus::Processing,
            // Danger! Block ALREADY has status.
            target_block_index => NotificationStatus::Processing,
        };
        STATE.with(|state| {
            state.replace(Some(State {
                blocks_notified: original_blocks_notified.clone(),
                ..Default::default()
            }))
        });

        let result = set_block_status_to_processing(target_block_index);

        assert_eq!(result, Err(Some(NotificationStatus::Processing)));
        assert_eq!(
            with_state(|state| state.blocks_notified.clone()),
            original_blocks_notified,
        );
    }

    #[test]
    fn test_set_block_status_to_processing_too_old() {
        let target_block_index = 42;
        let red_herring_block_index = 0xDEADBEEF;
        let original_blocks_notified = btreemap! {
            red_herring_block_index => NotificationStatus::Processing,
        };
        STATE.with(|state| {
            state.replace(Some(State {
                blocks_notified: original_blocks_notified.clone(),
                // We only know the status of blocks that are newer than this.
                last_purged_notification: 42,
                ..Default::default()
            }))
        });

        let result = set_block_status_to_processing(target_block_index);

        assert_eq!(result, Err(None));
        assert_eq!(
            with_state(|state| state.blocks_notified.clone()),
            original_blocks_notified,
        );
    }

    #[test]
    fn test_clear_block_processing_status_happy() {
        let target_block_index = 42;
        let red_herring_block_index = 0xDEADBEEF;
        let original_blocks_notified = btreemap! {
            red_herring_block_index => NotificationStatus::Processing,
            target_block_index => NotificationStatus::Processing,
        };
        STATE.with(|state| {
            state.replace(Some(State {
                blocks_notified: original_blocks_notified.clone(),
                ..Default::default()
            }))
        });

        clear_block_processing_status(target_block_index);

        // Assert that target block was deleted.
        assert_eq!(
            with_state(|state| state.blocks_notified.clone()),
            btreemap! {
                red_herring_block_index => NotificationStatus::Processing,
                // target_block_index no longer present.
            },
        );
    }

    #[test]
    fn test_clear_block_processing_status_not_processing() {
        let target_block_index = 42;
        let red_herring_block_index = 0xDEADBEEF;
        let original_blocks_notified = btreemap! {
            red_herring_block_index => NotificationStatus::Processing,
            target_block_index => NotificationStatus::NotifiedTopUp(Ok(Cycles::new(1_000_000_000_000))),
        };
        STATE.with(|state| {
            state.replace(Some(State {
                blocks_notified: original_blocks_notified.clone(),
                ..Default::default()
            }))
        });

        clear_block_processing_status(target_block_index);

        // Assert that blocks_notified not changed.
        assert_eq!(
            with_state(|state| state.blocks_notified.clone()),
            original_blocks_notified,
        );
    }

    #[test]
    fn test_clear_block_processing_status_absent_entirely() {
        let target_block_index = 42;
        let red_herring_block_index = 0xDEADBEEF;
        let original_blocks_notified = btreemap! {
            red_herring_block_index => NotificationStatus::Processing,
        };
        STATE.with(|state| {
            state.replace(Some(State {
                blocks_notified: original_blocks_notified.clone(),
                ..Default::default()
            }))
        });

        clear_block_processing_status(target_block_index);

        // Assert that blocks_notified not changed.
        assert_eq!(
            with_state(|state| state.blocks_notified.clone()),
            original_blocks_notified,
        );
    }
}
