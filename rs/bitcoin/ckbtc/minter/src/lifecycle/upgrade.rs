use crate::logs::P0;
use crate::state::eventlog::replay;
use crate::state::replace_state;
use crate::storage::{count_events, events};
use ic_canister_log::log;

pub fn post_upgrade() {
    log!(P0, "[upgrade]: replaying {} events", count_events());

    let start = ic_cdk::api::instruction_counter();

    replace_state(replay(events()).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "[upgrade]: failed to replay the event log: {:?}",
            e
        ))
    }));

    let end = ic_cdk::api::instruction_counter();

    log!(
        P0,
        "[upgrade]: replaying events consumed {} instructions",
        end - start
    );
}
