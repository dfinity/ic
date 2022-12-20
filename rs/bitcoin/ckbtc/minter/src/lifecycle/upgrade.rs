use crate::lifecycle::init::InitArgs;
use crate::logs::P0;
use crate::state::eventlog::{replay, Event};
use crate::state::replace_state;
use crate::storage::{count_events, events, record_event};
use ic_canister_log::log;

pub fn post_upgrade(init_args: Option<InitArgs>) {
    if let Some(init_args) = init_args {
        log!(P0, "[upgrade]: replacing init args with {:?}", init_args);
        record_event(&Event::Init(init_args));
    };

    let start = ic_cdk::api::instruction_counter();

    log!(P0, "[upgrade]: replaying {} events", count_events());

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
