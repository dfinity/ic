use crate::CanisterRuntime;
use crate::logs::Priority;
use crate::state::eventlog::{EventLogger, EventType};
use crate::state::invariants::CheckInvariantsImpl;
use crate::state::{Mode, replace_state};
use crate::storage::{count_events, migrate_old_events_if_not_empty, record_event};
use candid::{CandidType, Deserialize};
use canlog::log;
use ic_base_types::CanisterId;
use serde::Serialize;

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct UpgradeArgs {
    /// Minimum amount of bitcoin that can be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieve_btc_min_amount: Option<u64>,

    /// Specifies the minimum number of confirmations on the Bitcoin network
    /// required for the minter to accept a transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confirmations: Option<u32>,

    /// Maximum time in nanoseconds that a transaction should spend in the queue
    /// before being sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time_in_queue_nanos: Option<u64>,

    /// The mode in which the minter is running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_fee: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[deprecated(note = "use check_fee instead")]
    pub kyt_fee: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub btc_checker_principal: Option<CanisterId>,

    /// The principal of the kyt canister.
    /// NOTE: this field is optional for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[deprecated(note = "use btc_checker_principal instead")]
    pub kyt_principal: Option<CanisterId>,

    /// The expiration duration (in seconds) for cached entries in
    /// the get_utxos cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_utxos_cache_expiration_seconds: Option<u64>,
}

pub fn post_upgrade<R: CanisterRuntime>(upgrade_args: Option<UpgradeArgs>, runtime: &R) {
    if let Some(upgrade_args) = upgrade_args {
        log!(
            Priority::Info,
            "[upgrade]: updating configuration with {:?}",
            upgrade_args
        );
        record_event(EventType::Upgrade(upgrade_args), runtime);
    };

    let start = ic_cdk::api::instruction_counter();

    if let Some(removed) = migrate_old_events_if_not_empty() {
        log!(
            Priority::Info,
            "[upgrade]: {} empty events removed",
            removed
        )
    }
    log!(
        Priority::Info,
        "[upgrade]: replaying {} events",
        count_events()
    );

    let eventlog = runtime.event_logger();

    let state = eventlog
        .replay::<CheckInvariantsImpl>(eventlog.events_iter())
        .unwrap_or_else(|e| {
            ic_cdk::trap(format!("[upgrade]: failed to replay the event log: {e:?}"))
        });

    runtime.validate_config(&state);

    replace_state(state);

    let end = ic_cdk::api::instruction_counter();

    log!(
        Priority::Info,
        "[upgrade]: replaying events consumed {} instructions",
        end - start
    );
}
