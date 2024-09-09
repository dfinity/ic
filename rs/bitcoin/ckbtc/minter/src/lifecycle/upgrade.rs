use crate::logs::P0;
use crate::state::eventlog::{replay, Event};
use crate::state::{replace_state, Mode};
use crate::storage::{count_events, events, record_event};
use candid::{CandidType, Deserialize};
use ic_base_types::CanisterId;
use ic_canister_log::log;
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
    pub kyt_fee: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kyt_principal: Option<CanisterId>,
}

pub fn post_upgrade(upgrade_args: Option<UpgradeArgs>) {
    if let Some(upgrade_args) = upgrade_args {
        log!(
            P0,
            "[upgrade]: updating configuration with {:?}",
            upgrade_args
        );
        record_event(&Event::Upgrade(upgrade_args));
    };

    let start = ic_cdk::api::instruction_counter();

    log!(P0, "[upgrade]: replaying {} events", count_events());

    let state = replay(events()).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "[upgrade]: failed to replay the event log: {:?}",
            e
        ))
    });

    state.validate_config();

    replace_state(state);

    let end = ic_cdk::api::instruction_counter();

    log!(
        P0,
        "[upgrade]: replaying events consumed {} instructions",
        end - start
    );
}
