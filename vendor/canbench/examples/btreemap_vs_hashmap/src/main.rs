use candid::{CandidType, Encode};
use ic_cdk::pre_upgrade;
use std::cell::RefCell;

#[derive(CandidType)]
struct User {
    name: String,
}

#[derive(Default, CandidType)]
struct State {
    // TIP: try replacing the `BTreeMap` below with a `HashMap` and run `canbench`.
    // Notice how the performance changes.
    users: std::collections::BTreeMap<u64, User>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[pre_upgrade]
fn pre_upgrade() {
    // Serialize state.
    let bytes = {
        #[cfg(feature = "canbench-rs")]
        let _p = canbench_rs::bench_scope("serialize_state");
        STATE.with(|s| Encode!(s).unwrap())
    };

    // Write to stable memory.
    // Use artificial loop to showcase repeated scopes.
    for _ in 0..5 {
        #[cfg(feature = "canbench-rs")]
        let _p = canbench_rs::bench_scope("writing_to_stable_memory");
        ic_cdk::stable::StableWriter::default()
            .write(&bytes)
            .unwrap();
    }
}

#[cfg(feature = "canbench-rs")]
mod benches {
    use super::*;
    use canbench_rs::bench;

    // Benchmarks inserting 1 million users into the state.
    #[bench]
    fn insert_users() {
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            for i in 0..1_000_000 {
                s.users.insert(
                    i,
                    User {
                        name: "foo".to_string(),
                    },
                );
            }
        });
    }

    // Benchmarks removing 1 million users from the state.
    #[bench(raw)]
    fn remove_users() -> canbench_rs::BenchResult {
        insert_users();

        // Only benchmark removing users. Inserting users isn't
        // included in the results of our benchmark.
        canbench_rs::bench_fn(|| {
            STATE.with(|s| {
                let mut s = s.borrow_mut();
                for i in 0..1_000_000 {
                    s.users.remove(&i);
                }
            })
        })
    }

    #[bench(raw)]
    fn pre_upgrade_bench() -> canbench_rs::BenchResult {
        insert_users();

        // Only benchmark the pre_upgrade. Inserting users isn't
        // included in the results of our benchmark.
        canbench_rs::bench_fn(pre_upgrade)
    }
}

fn main() {}
