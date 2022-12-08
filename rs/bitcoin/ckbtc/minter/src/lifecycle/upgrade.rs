use crate::eventlog::replay;
use crate::state::replace_state;
use crate::storage::{count_events, events};

pub fn post_upgrade() {
    ic_cdk::println!("[upgrade]: replaying {} events", count_events());

    let start = ic_cdk::api::instruction_counter();

    replace_state(replay(events()).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "[upgrade]: failed to replay the event log: {:?}",
            e
        ))
    }));

    let end = ic_cdk::api::instruction_counter();

    ic_cdk::println!(
        "[upgrade]: replaying events consumed {} instructions",
        end - start
    );
}
