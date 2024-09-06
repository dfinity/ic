use candid::{candid_method, CandidType, Decode, Encode};
use core::cmp::Ordering;
use cycles_minting_canister::*;
use dfn_candid::{candid_one, CandidOne};
use dfn_core::{
    api::{call_with_cleanup, caller},
    over, over_async, over_init, over_may_reject, stable,
};
use dfn_protobuf::protobuf;
use environment::Environment;
use exchange_rate_canister::{
    RealExchangeRateCanisterClient, UpdateExchangeRateError, UpdateExchangeRateState,
};
use ic_crypto_tree_hash::{
    flatmap, HashTreeBuilder, HashTreeBuilderImpl, Label, LabeledTree, WitnessGenerator,
    WitnessGeneratorImpl,
};
use ic_ledger_core::block::BlockType;
use ic_ledger_core::tokens::CheckedSub;
// TODO(EXC-1687): remove temporary aliases `Ic00CanisterSettingsArgs` and `Ic00CanisterSettingsArgsBuilder`.
use ic_management_canister_types::{
    BoundedVec, CanisterIdRecord, CanisterSettingsArgs as Ic00CanisterSettingsArgs,
    CanisterSettingsArgsBuilder as Ic00CanisterSettingsArgsBuilder, CreateCanisterArgs, Method,
    IC_00,
};
use ic_nervous_system_common::NNS_DAPP_BACKEND_CANISTER_ID;
use ic_nervous_system_governance::maturity_modulation::{
    MAX_MATURITY_MODULATION_PERMYRIAD, MIN_MATURITY_MODULATION_PERMYRIAD,
};
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, ICP_LEDGER_ARCHIVE_1_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_types::{CanisterId, Cycles, PrincipalId, SubnetId};
use icp_ledger::{
    AccountIdentifier, Block, BlockIndex, BlockRes, CyclesResponse, Memo, Operation, SendArgs,
    Subaccount, Tokens, TransactionNotification, DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use on_wire::{FromWire, IntoWire, NewType};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    convert::TryInto,
    thread::LocalKey,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod environment;
mod exchange_rate_canister;
mod limiter;

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

/// Calls to create_canister get rejected outright if they have obviously too few cycles attached.
/// This is the minimum amount needed for creating a canister as of October 2023.
const CREATE_CANISTER_MIN_CYCLES: u64 = 100_000_000_000;

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
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
        dfn_core::api::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get the duration.")
            .as_secs()
    }

    fn set_certified_data(&self, data: &[u8]) {
        dfn_core::api::set_certified_data(data)
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
type State = StateV1;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct StateV1 {
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
    pub cycles_limit: Cycles,

    /// Maintain a count of how many cycles have been minted in the last hour.
    pub limiter: limiter::Limiter,

    pub total_cycles_minted: Cycles,

    pub blocks_notified: BTreeMap<BlockIndex, NotificationStatus>,
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

impl StateV1 {
    fn state_version() -> StateVersion {
        StateVersion(1)
    }
}

/// Old state type. The State type migrates from this type.
///
/// The difference with State is that StateV0 has Option wrappers
/// around blocks_notified and last_purged_notification.
///
/// TODO: remove this type once the CMC has upgraded to this version.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct StateV0 {
    pub ledger_canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub exchange_rate_canister_id: Option<CanisterId>,
    pub cycles_ledger_canister_id: Option<CanisterId>,
    pub minting_account_id: Option<AccountIdentifier>,
    pub authorized_subnets: BTreeMap<PrincipalId, Vec<SubnetId>>,
    pub default_subnets: Vec<SubnetId>,
    pub icp_xdr_conversion_rate: Option<IcpXdrConversionRate>,
    pub average_icp_xdr_conversion_rate: Option<IcpXdrConversionRate>,
    pub recent_icp_xdr_rates: Option<Vec<IcpXdrConversionRate>>,
    pub cycles_per_xdr: Cycles,
    pub cycles_limit: Cycles,
    pub limiter: limiter::Limiter,
    pub total_cycles_minted: Cycles,

    pub blocks_notified: Option<BTreeMap<BlockIndex, NotificationStatus>>,
    pub last_purged_notification: Option<BlockIndex>,

    pub maturity_modulation_permyriad: Option<i32>,
    pub subnet_types_to_subnets: Option<BTreeMap<String, BTreeSet<SubnetId>>>,
    pub update_exchange_rate_canister_state: Option<UpdateExchangeRateState>,
}

/// Migrate from the old state type to the current one.
fn migrate(state_v0: StateV0) -> StateV1 {
    let StateV0 {
        ledger_canister_id,
        governance_canister_id,
        exchange_rate_canister_id,
        cycles_ledger_canister_id,
        minting_account_id,
        authorized_subnets,
        default_subnets,
        icp_xdr_conversion_rate,
        average_icp_xdr_conversion_rate,
        recent_icp_xdr_rates,
        cycles_per_xdr,
        cycles_limit,
        limiter,
        total_cycles_minted,
        blocks_notified,
        last_purged_notification,
        maturity_modulation_permyriad,
        subnet_types_to_subnets,
        update_exchange_rate_canister_state,
    } = state_v0;

    let blocks_notified = blocks_notified.unwrap_or_default();
    let last_purged_notification = last_purged_notification.unwrap_or_default();

    StateV1 {
        ledger_canister_id,
        governance_canister_id,
        exchange_rate_canister_id,
        cycles_ledger_canister_id,
        minting_account_id,
        authorized_subnets,
        default_subnets,
        icp_xdr_conversion_rate,
        average_icp_xdr_conversion_rate,
        recent_icp_xdr_rates,
        cycles_per_xdr,
        cycles_limit,
        limiter,
        total_cycles_minted,
        blocks_notified,
        last_purged_notification,
        maturity_modulation_permyriad,
        subnet_types_to_subnets,
        update_exchange_rate_canister_state,
    }
}

impl State {
    fn encode(&self) -> Vec<u8> {
        Encode!(&Self::state_version(), &self).unwrap()
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut deserializer = candid::de::IDLDeserialize::new(bytes).unwrap();
        match deserializer.get_value::<StateVersion>() {
            // When stable storage contains a StateV0 encoded value
            // decoding it as a StateVersion will fail (this has been experimentally verified).
            // In this case we decode stable storage as a StateV0 and migrate it to the desired StateV1.
            Err(_) => {
                print("[cycles] state has not been migrated to the new versioned State format yet, doing that now ...");
                let state_v0: StateV0 = Decode!(bytes, StateV0)
                    .expect("stable storage needs to contain a candid-encoded StateV0 value!");
                let state_v1: StateV1 = migrate(state_v0);
                Ok(state_v1)
            }
            Ok(stored_state_version) => {
                let current_state_version: StateVersion = Self::state_version();
                match stored_state_version.cmp(&current_state_version) {
                    Ordering::Greater =>
                        return Err(format!(
                            "[cycles] ERROR: stored state version {:?} is greater than the current state version {:?}! \
                            This likely means a rollback happened. This is not supported. Please upgrade to a hotfix instead.",
                            stored_state_version, current_state_version
                        )),
                    Ordering::Less =>
                        return Err(format!(
                            "[cycles] ERROR: stored state version {:?} is lesser than the current state version {:?}! \
                            Did you forget to migrate the old to the current type?",
                            stored_state_version, current_state_version
                        )),
                    Ordering::Equal =>
                        print(format!(
                            "[cycles] INFO: stored state version {:?} equals the current state version {:?}. \
                            Continuing to decode the stable storage ... ",
                            stored_state_version, current_state_version,
                        )),
                }
                let state = deserializer.get_value::<State>().unwrap();
                deserializer.done().unwrap();
                Ok(state)
            }
        }
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
            cycles_limit: 50_000_000_000_000_000u128.into(), // == 50 Pcycles/hour
            limiter: limiter::Limiter::new(resolution, max_age),
            total_cycles_minted: Cycles::zero(),
            blocks_notified: BTreeMap::new(),
            last_purged_notification: 0,
            maturity_modulation_permyriad: Some(0),
            subnet_types_to_subnets: Some(BTreeMap::new()),
            update_exchange_rate_canister_state: Some(UpdateExchangeRateState::default()),
        }
    }
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

#[candid_method(init)]
fn init(maybe_args: Option<CyclesCanisterInitPayload>) {
    let args =
        maybe_args.expect("Payload is expected to initialization the cycles minting canister.");
    print(format!(
        "[cycles] init() with ledger canister {}, governance canister {}, exchange rate canister {}, minting account {}, and cycles ledger canister {}",
        args.ledger_canister_id.as_ref().map(|x| x.to_string()).unwrap_or_else(|| "<none>".to_string()),
        args.governance_canister_id.as_ref().map(|x| x.to_string()).unwrap_or_else(|| "<none>".to_string()),
        args.exchange_rate_canister.as_ref()
            .map(|x| match x {
                ExchangeRateCanister::Set(id) => id.to_string(),
                ExchangeRateCanister::Unset => "<unset>".to_string()
            })
            .unwrap_or_else(|| "<none>".to_string()),
        args.minting_account_id
            .map(|x| x.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        args.cycles_ledger_canister_id.as_ref()
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

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

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
    with_state_mut(|state| {
        let governance_canister_id = state.governance_canister_id;

        if CanisterId::unchecked_from_principal(caller()) != governance_canister_id {
            panic!("Only the governance canister can set authorized subnetwork lists.");
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
                "Subnets {:?} are already assigned to a type and cannot be authorized.",
                already_assigned
            );
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
    });
}

#[export_name = "canister_update update_subnet_type"]
fn update_subnet_type_() {
    over_may_reject(candid_one, |args: UpdateSubnetTypeArgs| {
        update_subnet_type(args).map_err(|err| err.to_string())
    })
}

/// Updates the set of available subnet types.
///
/// Preconditions:
//   * Only the governance canister can call this method
//   * Add: type does not already exist
//   * Remove: type exists and no assigned subnets to this type exist
fn update_subnet_type(args: UpdateSubnetTypeArgs) -> UpdateSubnetTypeResult {
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
                print(format!("[cycles] Adding new subnet type: {}", subnet_type));
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
                    print(format!("[cycles] Removing subnet type: {}", subnet_type));
                    // Type does not have any assigned subnets, so it can be removed.
                    subnet_types_to_subnets.remove(&subnet_type);
                    Ok(())
                }
            }
            None => Err(UpdateSubnetTypeError::TypeDoesNotExist(subnet_type)),
        }
    })
}

#[export_name = "canister_update change_subnet_type_assignment"]
fn change_subnet_type_assignment_() {
    over_may_reject(candid_one, |args: ChangeSubnetTypeAssignmentArgs| {
        change_subnet_type_assignment(args).map_err(|err| err.to_string())
    })
}

/// Changes the assignment of provided subnets to subnet types.
///
/// Preconditions:
///  * Only the governance canister can call this method
///  * Add: type exists and all subnet ids should be currently unassigned and not part of the authorized subnets
///  * Remove: type exists and all subnet ids are currently assigned to this type
fn change_subnet_type_assignment(
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
                    "[cycles] Adding subnets {:?} to type: {}",
                    subnets, subnet_type
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
                    "[cycles] Removing subnets {:?} from type: {}",
                    subnets, subnet_type
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

#[candid_method(query, rename = "get_subnet_types_to_subnets")]
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

/// Retrieves the current mapping of subnet types to subnets.
#[export_name = "canister_query get_subnet_types_to_subnets"]
fn get_subnet_types_to_subnets_() {
    over(candid_one, |_: ()| get_subnet_types_to_subnets())
}

#[candid_method(
    query,
    rename = "get_principals_authorized_to_create_canisters_to_subnets"
)]
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

/// Returns the current mapping of authorized principals to subnets.
#[export_name = "canister_query get_principals_authorized_to_create_canisters_to_subnets"]
fn get_principals_authorized_to_create_canisters_to_subnets_() {
    over(candid_one, |_: ()| {
        get_principals_authorized_to_create_canisters_to_subnets()
    })
}

#[candid_method(query, rename = "get_default_subnets")]
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

/// Returns the list of default subnets to which anyone can deploy canisters to.
#[export_name = "canister_query get_default_subnets"]
fn get_default_subnets_() {
    over(candid_one, |_: ()| get_default_subnets())
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

#[candid_method(query, rename = "get_icp_xdr_conversion_rate")]
fn get_icp_xdr_conversion_rate() -> IcpXdrConversionRateCertifiedResponse {
    with_state(|state| {
        let witness_generator = convert_data_to_mixed_hash_tree(state);
        let icp_xdr_conversion_rate = state
            .icp_xdr_conversion_rate
            .as_ref()
            .expect("icp_xdr_conversion_rate is not set");

        let payload =
            convert_conversion_rate_to_payload(icp_xdr_conversion_rate, witness_generator);

        IcpXdrConversionRateCertifiedResponse {
            data: icp_xdr_conversion_rate.clone(),
            hash_tree: payload,
            certificate: dfn_core::api::data_certificate().unwrap_or_default(),
        }
    })
}

/// Retrieves the current `xdr_permyriad_per_icp` as a certified response.
#[export_name = "canister_query get_icp_xdr_conversion_rate"]
fn get_icp_xdr_conversion_rate_() {
    over(candid_one, |_: ()| get_icp_xdr_conversion_rate())
}

#[export_name = "canister_query get_average_icp_xdr_conversion_rate"]
fn get_average_icp_xdr_conversion_rate_() {
    with_state(|state| {
        let witness_generator = convert_data_to_mixed_hash_tree(state);
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
        IcpXdrConversionRate::default(
        );
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
        if let Ok(time) = dfn_core::api::now().duration_since(UNIX_EPOCH) {
            state.average_icp_xdr_conversion_rate =
                compute_average_icp_xdr_rate_at_time(recent_rates, time.as_secs());
            state.maturity_modulation_permyriad =
                Some(compute_maturity_modulation(recent_rates, time.as_secs()));
        }
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

    over(
        candid_one,
        |proposed_conversion_rate: UpdateIcpXdrConversionRatePayload| -> Result<(), String> {
            let env = CanisterEnvironment;
            let rate = IcpXdrConversionRate::from(&proposed_conversion_rate);
            let rate_timestamp_seconds = rate.timestamp_seconds;
            let result = set_icp_xdr_conversion_rate(&STATE, &env, rate);
            if result.is_ok() && with_state(|state| state.exchange_rate_canister_id.is_some()) {
                exchange_rate_canister::set_update_exchange_rate_state(
                    &STATE,
                    &proposed_conversion_rate.reason,
                    rate_timestamp_seconds,
                );
            }

            result
        },
    );
}

/// Validates the proposed conversion rate, sets it in state, and sets the
/// canister's certified data
fn set_icp_xdr_conversion_rate(
    safe_state: &'static LocalKey<RefCell<Option<State>>>,
    env: &impl Environment,
    proposed_conversion_rate: IcpXdrConversionRate,
) -> Result<(), String> {
    print(format!(
        "[cycles] conversion rate update: {:?}",
        proposed_conversion_rate
    ));

    if proposed_conversion_rate.xdr_permyriad_per_icp == 0 {
        return Err("Proposed conversion rate must be greater than 0".to_string());
    }

    mutate_state(safe_state, |state| {
        if let Some(current_conversion_rate) = state.icp_xdr_conversion_rate.as_ref() {
            if proposed_conversion_rate.timestamp_seconds
                <= current_conversion_rate.timestamp_seconds
            {
                return Err(
                    "Proposed conversion rate must have greater timestamp than current one"
                        .to_string(),
                );
            }
        }

        state.icp_xdr_conversion_rate = Some(proposed_conversion_rate.clone());
        update_recent_icp_xdr_rates(state, &proposed_conversion_rate);

        let witness_generator = convert_data_to_mixed_hash_tree(state);
        env.set_certified_data(&witness_generator.hash_tree().digest().0[..]);

        Ok(())
    })
}

#[export_name = "canister_query neuron_maturity_modulation"]
fn neuron_maturity_modulation_() {
    over(candid_one, |_: ()| neuron_maturity_modulation())
}

/// The function returns the current maturity modulation in basis points.
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
    with_state_mut(|state| {
        state
            .authorized_subnets
            .values_mut()
            .for_each(|subnet_list| subnet_list.retain(|subnet| *subnet != subnet_to_remove))
    });
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

#[export_name = "canister_update create_canister"]
fn create_canister_() {
    over_async(candid_one, create_canister)
}

#[export_name = "canister_update notify_mint_cycles"]
fn notify_mint_cycles_() {
    over_async(candid_one, notify_mint_cycles)
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
    let expected_destination_account = AccountIdentifier::new(cmc_id.get(), Some(sub));

    let (amount, from) = fetch_transaction(
        block_index,
        expected_destination_account,
        MEMO_TOP_UP_CANISTER,
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
                NotificationStatus::NotifiedTopUp(result) => Some(result.clone()),
                NotificationStatus::NotifiedCreateCanister(_) => {
                    Some(Err(NotifyError::InvalidTransaction(
                        "The same payment is already processed as create canister request".into(),
                    )))
                }
                NotificationStatus::NotifiedMint(_) => Some(Err(NotifyError::InvalidTransaction(
                    "The same payment is already processed as mint request".into(),
                ))),
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
            let result = process_top_up(canister_id, from, amount).await;

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
#[candid_method(update, rename = "notify_mint_cycles")]
async fn notify_mint_cycles(
    NotifyMintCyclesArg {
        block_index,
        to_subaccount,
        deposit_memo,
    }: NotifyMintCyclesArg,
) -> NotifyMintCyclesResult {
    let cmc_id = dfn_core::api::id();
    let subaccount = Subaccount::from(&caller());
    let expected_destination_account = AccountIdentifier::new(cmc_id.get(), Some(subaccount));
    let to_account = Account {
        owner: caller().into(),
        subaccount: to_subaccount,
    };

    let (amount, from) =
        fetch_transaction(block_index, expected_destination_account, MEMO_MINT_CYCLES).await?;

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
#[candid_method(update, rename = "notify_create_canister")]
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

    let cmc_id = dfn_core::api::id();
    let sub = Subaccount::from(&controller);
    let expected_destination_account = AccountIdentifier::new(cmc_id.get(), Some(sub));
    let subnet_selection =
        get_subnet_selection(subnet_type, subnet_selection).map_err(|error_message| {
            NotifyError::Other {
                error_code: NotifyErrorCode::BadSubnetSelection as u64,
                error_message,
            }
        })?;

    let (amount, from) = fetch_transaction(
        block_index,
        expected_destination_account,
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
            "{} is not authorized to call notify_create_canister on behalf \
             of {}. (Do not retry, because the same result will occur.)",
            caller, creator,
        ),
    };

    Err(err)
}

#[candid_method(update, rename = "create_canister")]
#[allow(deprecated)]
async fn create_canister(
    CreateCanister {
        settings,
        subnet_selection,
        subnet_type,
    }: CreateCanister,
) -> Result<CanisterId, CreateCanisterError> {
    let cycles = dfn_core::api::msg_cycles_available();
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

    // will always succeed because only calls from canisters can have cycles attached
    let calling_canister = caller().try_into().unwrap();

    dfn_core::api::msg_cycles_accept(cycles);
    match do_create_canister(caller(), cycles.into(), subnet_selection, settings, false).await {
        Ok(canister_id) => Ok(canister_id),
        Err(create_error) => {
            let refund_amount = cycles.saturating_sub(BAD_REQUEST_CYCLES_PENALTY as u64);
            match deposit_cycles(calling_canister, refund_amount.into(), false).await {
                Ok(()) => Err(CreateCanisterError::Refunded {
                    refund_amount: refund_amount.into(),
                    create_error,
                }),
                Err(refund_error) => Err(CreateCanisterError::RefundFailed {
                    create_error,
                    refund_error,
                }),
            }
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
    let BlockRes(b) = call_with_cleanup(ledger_id, "block_pb", protobuf, block_index)
        .await
        .map_err(|e| failed_to_fetch_block(format!("Failed to fetch block: {}", e.1)))?;

    let raw_block = match b {
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
    };
    Block::decode(raw_block)
        .map_err(|e| failed_to_fetch_block(format!("Failed to decode block: {}", e)))
}

fn memo_to_intent_str(memo: Memo) -> String {
    match memo {
        MEMO_CREATE_CANISTER => "CreateCanister".into(),
        MEMO_TOP_UP_CANISTER => "TopUp".into(),
        MEMO_MINT_CYCLES => "MintCycles".into(),
        a => format!("unrecognized: {a:?}"),
    }
}

async fn fetch_transaction(
    block_index: BlockIndex,
    expected_destination_account: AccountIdentifier,
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
            ))
        }
    };
    if to != expected_destination_account {
        return Err(NotifyError::InvalidTransaction(format!(
            "Destination account in the block ({}) different than in the notification ({})",
            to, expected_destination_account
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

    let ledger_canister_id = with_state(|state| state.ledger_canister_id);

    if CanisterId::unchecked_from_principal(caller) != ledger_canister_id {
        return Err(format!(
            "This canister can only be notified by the ledger canister ({}), not by {}.",
            ledger_canister_id, caller
        ));
    }

    // We need this check if MAX_NOTIFY_HISTORY is smaller than max number of transactions
    // the ledger can process within 24h
    let last_purged_notification = with_state(|state| state.last_purged_notification);

    if tn.block_height <= last_purged_notification {
        return Err(NotifyError::TransactionTooOld(last_purged_notification + 1).to_string());
    }

    let block_height = tn.block_height;
    with_state_mut(|state| match state.blocks_notified.entry(block_height) {
        Entry::Occupied(entry) => match entry.get() {
            NotificationStatus::Processing => Err("Another notification is in progress".into()),
            NotificationStatus::NotifiedTopUp(resp) => Err(format!("Already notified: {:?}", resp)),
            NotificationStatus::NotifiedCreateCanister(resp) => {
                Err(format!("Already notified: {:?}", resp))
            }
            NotificationStatus::NotifiedMint(resp) => Err(format!("Already notified: {:?}", resp)),
        },
        Entry::Vacant(entry) => {
            entry.insert(NotificationStatus::Processing);
            Ok(())
        }
    })?;

    let from = AccountIdentifier::new(tn.from, tn.from_subaccount);

    let (cycles_response, notification_status) = if tn.memo == MEMO_CREATE_CANISTER {
        let controller = authorize_sender_to_create_canister_via_ledger_notify(&tn)?;
        match process_create_canister(controller, from, tn.amount, None, None).await {
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

    with_state_mut(|state| {
        if let Some(status) = notification_status {
            state.blocks_notified.insert(block_height, status);
        }
        if is_transient_error(&cycles_response) {
            state.blocks_notified.remove(&block_height);
        }
    });

    cycles_response.map_err(|e| e.to_string())
}

/// Returns Ok(controller/creator/sender) if sender == creator (aka controller).
///
/// That is, we disallow sending ICP on behalf of someone else; whereas, we used to allow it.
///
/// The reason for this restriction is that the creator might be authorized to create canisters on
/// restricted subnets.
///
/// The only fields used are
///     * from: This is taken as the sender.
///     * to_subaccount: This is used to infer the creator/controller.
///
/// It is assumed that memo == MEMO_CREATE_CANISTER. (However, behavior is the same if that
/// assumption does not hold.)
fn authorize_sender_to_create_canister_via_ledger_notify(
    transaction_notification: &TransactionNotification,
) -> Result<PrincipalId, String> {
    let sender = transaction_notification.from;

    let creator = {
        let to_subaccount = transaction_notification.to_subaccount.ok_or_else(|| {
            format!(
                "Transfer has no destination subaccount:\n{:#?}",
                transaction_notification,
            )
        })?;

        PrincipalId::try_from(&to_subaccount).map_err(|err| {
            format!(
                "Cannot determine creator principal from ICP transfer to Cycles \
                 Minting Canister destination subaccount {}: {}",
                to_subaccount, err,
            )
        })?
    };

    if sender == creator {
        return Ok(creator);
    }

    Err(format!(
        "Principal {} sent ICP to the Cycles Minting Canister on behalf of {} \
         in order to create a canister, but this is not allowed (anymore).",
        sender, creator,
    ))
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
        "Creating canister with controller {} with {} cycles.",
        controller, cycles,
    ));

    // Create the canister. If this fails, refund. Either way,
    // return a result so that the notification cannot be retried.
    // If refund fails, we allow to retry.
    match do_create_canister(controller, cycles, subnet_selection, settings, true).await {
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
) -> Result<Cycles, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;

    let sub = Subaccount::from(&canister_id);

    print(format!(
        "Topping up canister {} by {} cycles.",
        canister_id, cycles
    ));

    match deposit_cycles(canister_id, cycles, true).await {
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
    let msg = format!(
        "Burning of {} ICPTs from subaccount {}",
        amount, from_subaccount
    );
    let minting_account_id = with_state(|state| state.minting_account_id);
    if minting_account_id.is_none() {
        print(format!("{} failed: minting_account_id not set", msg));
        return;
    }
    let minting_account_id = minting_account_id.unwrap();
    let ledger_canister_id = with_state(|state| state.ledger_canister_id);

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
    let res: Result<BlockIndex, (Option<i32>, String)> =
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
    {
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
        let send_res: Result<BlockIndex, (Option<i32>, String)> =
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

async fn deposit_cycles(
    canister_id: CanisterId,
    cycles: Cycles,
    mint_cycles: bool,
) -> Result<(), String> {
    if mint_cycles {
        ensure_balance(cycles)?;
    }

    let res: Result<(), (Option<i32>, String)> = dfn_core::api::call_with_funds_and_cleanup(
        IC_00,
        &Method::DepositCycles.to_string(),
        dfn_candid::candid_multi_arity,
        (CanisterIdRecord::from(canister_id),),
        dfn_core::api::Funds::new(u128::from(cycles) as u64),
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

async fn do_mint_cycles(
    account: Account,
    cycles: Cycles,
    deposit_memo: Option<Vec<u8>>,
) -> Result<CyclesLedgerDepositResult, String> {
    let Some(cycles_ledger_canister_id) = with_state(|state| state.cycles_ledger_canister_id)
    else {
        return Err("No cycles ledger canister id configured.".to_string());
    };

    ensure_balance(cycles)?;

    let arg = CyclesLedgerDepositArgs {
        to: account,
        memo: deposit_memo,
    };
    let result: Result<(CyclesLedgerDepositResult,), (Option<i32>, String)> =
        dfn_core::api::call_with_funds_and_cleanup(
            cycles_ledger_canister_id,
            "deposit",
            dfn_candid::candid_multi_arity,
            (arg,),
            dfn_core::api::Funds::new(u128::from(cycles) as u64),
        )
        .await;

    result.map(|r| r.0).map_err(|(code, msg)| {
        format!(
            "Cycles ledger rejected deposit call with code {}: {:?}",
            code.unwrap_or_default(),
            msg
        )
    })
}

async fn do_create_canister(
    controller_id: PrincipalId,
    cycles: Cycles,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettingsArgs>,
    mint_cycles: bool,
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
                            .ok_or(format!(
                                "Provided subnet type {} does not exist",
                                subnet_type
                            ))
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
                    Err(format!("Subnet {} does not exist or {} is not authorized to deploy to that subnet.", subnet, controller_id))
                }
            }),
        },
        None => Ok(get_subnets_for(&controller_id)),
    }?;

    // Perform a random permutation of the eligible list of subnets to ensure
    // that we load balance canister creations among them.
    subnets.shuffle(&mut rng);

    let mut last_err = None;

    if mint_cycles && !subnets.is_empty() {
        // TODO(NNS1-503): If CreateCanister fails, then we still have minted
        // these cycles.
        ensure_balance(cycles)?;
    }

    let canister_settings = settings
        .map(|mut settings| {
            if settings.controllers.is_none() {
                settings.controllers = Some(BoundedVec::new(vec![controller_id]));
            }
            settings
        })
        .unwrap_or_else(|| {
            CanisterSettingsArgs::from(
                Ic00CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![controller_id])
                    .build(),
            )
        });

    for subnet_id in subnets {
        let result: Result<CanisterIdRecord, _> = dfn_core::api::call_with_funds_and_cleanup(
            subnet_id.into(),
            &Method::CreateCanister.to_string(),
            dfn_candid::candid_one,
            CreateCanisterArgs {
                settings: Some(Ic00CanisterSettingsArgs::from(canister_settings.clone())),
                sender_canister_version: Some(dfn_core::api::canister_version()),
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

    with_state_mut(|state| {
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
        Ok(())
    })?;

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
        with_state(|state| state.total_cycles_minted.get().try_into().unwrap())
    })
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
    let bytes = with_state(|state| state.encode());
    print(format!(
        "[cycles] serialized state prior to upgrade ({} bytes)",
        bytes.len(),
    ));
    stable::set(&bytes);
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade_() {
    over_init(|CandidOne(args)| post_upgrade(args))
}

fn post_upgrade(maybe_args: Option<CyclesCanisterInitPayload>) {
    let bytes = stable::get();
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

#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    if with_state(|state| state.exchange_rate_canister_id.is_some()) {
        let future = update_exchange_rate();
        dfn_core::api::futures::spawn(future);
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
                print(format!("[cycles] {}", error));
            }
            UpdateExchangeRateError::Disabled
            | UpdateExchangeRateError::NotReadyToGetRate(_)
            | UpdateExchangeRateError::UpdateAlreadyInProgress => {}
        }
    }
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
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
    use rand::Rng;
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
            "{:#?}",
            on_behalf_of_self_result,
        );

        let eve = PrincipalId::new_user_test_id(898_071_769);
        let on_behalf_of_other_result = authorize(eve);
        assert!(
            on_behalf_of_other_result.is_err(),
            "{:#?}",
            on_behalf_of_other_result,
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
                    "{:#?}",
                    err,
                );

                let error_message = error_message.to_lowercase();
                for key_word in ["authorize", "on behalf"] {
                    assert!(
                        error_message.contains(key_word),
                        "{} not in {:#?}",
                        key_word,
                        err,
                    );
                }
            }

            _ => panic!("{:#?}", err),
        }

        let caller_is_nns_dapp_result = authorize(PrincipalId::from(*NNS_DAPP_BACKEND_CANISTER_ID));
        assert!(
            caller_is_nns_dapp_result.is_ok(),
            "{:#?}",
            caller_is_nns_dapp_result,
        );

        // Also allow nns-dapp backend canister ID used in test.
        let caller_is_nns_dapp_result =
            authorize(PrincipalId::from_str("qsgjb-riaaa-aaaaa-aaaga-cai").unwrap());
        assert!(
            caller_is_nns_dapp_result.is_ok(),
            "{:#?}",
            caller_is_nns_dapp_result,
        );
    }

    #[test]
    fn test_authorize_sender_to_create_canister_via_ledger_notify() {
        // Happy case.
        let creator = PrincipalId::new_user_test_id(777);
        let ok_transaction_notification = TransactionNotification {
            from: creator,
            to_subaccount: Some(Subaccount::from(&creator)),

            // These are not used.
            memo: MEMO_CREATE_CANISTER, // Just for realism.
            from_subaccount: None,
            to: CanisterId::from_u64(111),
            block_height: 222,
            amount: Tokens::from_e8s(333),
        };

        // Evil case.
        assert_eq!(
            authorize_sender_to_create_canister_via_ledger_notify(&ok_transaction_notification,),
            Ok(creator),
        );

        let evil = PrincipalId::new_user_test_id(666);
        let evil_transaction_notification = TransactionNotification {
            from: evil,
            ..ok_transaction_notification.clone()
        };

        let evil_result =
            authorize_sender_to_create_canister_via_ledger_notify(&evil_transaction_notification);

        let evil_result = match evil_result {
            Err(err) => err.to_lowercase(),
            wrong => panic!("Evil result is supposed to be Err, but was {:?}", wrong),
        };
        for key_word in ["create", "canister", "on behalf of", "not allowed"] {
            assert!(
                evil_result.contains(key_word),
                "{} not in {:?}",
                key_word,
                evil_result
            );
        }

        // Invalid transfer case 1: no destination subaccount.
        let no_destination_subaccount_transaction_notification = TransactionNotification {
            to_subaccount: None,
            ..ok_transaction_notification.clone()
        };

        let no_destination_subaccount_result =
            authorize_sender_to_create_canister_via_ledger_notify(
                &no_destination_subaccount_transaction_notification,
            );

        let no_destination_subaccount_result = match no_destination_subaccount_result {
            Err(err) => err.to_lowercase(),
            wrong => panic!(
                "No destination subaccount result is supposed to be Err, but was {:?}",
                wrong,
            ),
        };
        for key_word in ["has no", "destination", "subaccount"] {
            assert!(
                no_destination_subaccount_result.contains(key_word),
                "{} not in {:?}",
                key_word,
                no_destination_subaccount_result,
            );
        }

        // Invalid transfer case 2: destination subaccount present, but does not map to (creator)
        // principal.
        let garbage_subaccount = [42_u8; 32];
        let no_creator_transaction_notification = TransactionNotification {
            to_subaccount: Some(Subaccount(garbage_subaccount)),
            ..ok_transaction_notification
        };

        let no_creator_result = authorize_sender_to_create_canister_via_ledger_notify(
            &no_creator_transaction_notification,
        );

        let no_creator_result = match no_creator_result {
            Err(err) => err.to_lowercase(),
            wrong => panic!(
                "No destination subaccount result is supposed to be Err, but was {:?}",
                wrong,
            ),
        };
        for key_word in ["determine", "creator", "subaccount"] {
            assert!(
                no_creator_result.contains(key_word),
                "{} not in {:?}",
                key_word,
                no_creator_result,
            );
        }
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
        let mut rng = rand::thread_rng();
        // The sum of all the valid rates, i.e., the rates at midnight.
        let mut valid_rates_sum = 0;
        // Iterate over two intervals (half of which should be ignored), from the oldest
        // to the latest rate.
        for day in (0..2 * NUM_DAYS_FOR_ICP_XDR_AVERAGE).rev() {
            // Generate a valid rate, i.e., the ICP/XDR rate at midnight.
            let valid_rate: u64 = rng.gen_range(1_000_000..10_000_000);
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
                        xdr_permyriad_per_icp: rng.gen_range(1_000_000..10_000_000),
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
                        xdr_permyriad_per_icp: rng.gen_range(1_000_000..10_000_000),
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
        let mut rng = rand::thread_rng();
        let mut rates = vec![];
        let mut timestamp = 1658102400;
        for _index in 0..ICP_XDR_CONVERSION_RATE_CACHE_SIZE {
            rates.push(IcpXdrConversionRate {
                timestamp_seconds: timestamp,
                xdr_permyriad_per_icp: current_rate as u64,
            });
            current_rate += rng.gen_range(0..20_000) - 10_000;
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
        use candid_parser::utils::{service_equal, CandidSource};
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
}
