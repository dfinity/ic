use candid::{Decode, Encode};
use dfn_core::api;
use ic_base_types::CanisterId;
use rand::{distributions::Distribution, rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use random_traffic_test::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;

thread_local! {
    static RNG: RefCell<StdRng> = RefCell::new(StdRng::seed_from_u64(13));
    static CONFIG: RefCell<Config> = RefCell::default();
    static CALLS_PER_ROUND: Cell<u32> = Cell::default();
    static CALL_ID: Cell<u32> = Cell::default();
    static RECORDS: RefCell<BTreeMap<u32, Record>> = RefCell::default();
}

/// Replaces the canister state according to `f` by parsing `arg_data` of type `T`; returns the old
/// state.
fn replace_state<T, F>(f: F)
where
    T: candid::CandidType + for<'a> serde::Deserialize<'a>,
    F: FnOnce(T) -> T,
{
    let msg = match candid::Decode!(&api::arg_data()[..], T) {
        Ok(item) => Ok(f(item)),
        Err(_) => Err(()),
    };

    let msg = candid::Encode!(&msg).unwrap();
    api::reply(&msg[..]);
}

/// Sets the test config.
#[export_name = "canister_update replace_config"]
fn replace_config() {
    replace_state(|config: Config| CONFIG.replace(config));
}

/// Sets the requests per round to be sent each heart beat.
#[export_name = "canister_update replace_calls_per_round"]
fn replace_calls_per_round() {
    replace_state(|calls_per_round: u32| CALLS_PER_ROUND.replace(calls_per_round));
}

/// Seeds `RNG`.
#[export_name = "canister_update seed_rng"]
fn seed_rng() {
    RNG.with_borrow_mut(|rng| {
        let seed = candid::Decode!(&api::arg_data()[..], u64).unwrap();
        *rng = StdRng::seed_from_u64(seed);
    });
    api::reply(&[]);
}

fn insert_new_call_record(call_id: u32, record: Record) {
    RECORDS.with_borrow_mut(|records| {
        records.insert(call_id, record);
    })
}

fn set_reply(call_id: u32, reply: Reply) {
    RECORDS.with_borrow_mut(|records| {
        records.get_mut(&call_id).unwrap().reply = Some(reply);
    });
}

/// Returns the canister records.
#[export_name = "canister_query records"]
fn records() {
    let records = RECORDS.with_borrow(|records| records.values().cloned().collect::<Vec<_>>());
    let msg = candid::Encode!(&records).unwrap();
    api::reply(&msg[..]);
}

/// Returns a random receiver if any.
fn choose_receiver() -> Option<CanisterId> {
    CONFIG.with_borrow(|config| {
        RNG.with_borrow_mut(|rng| config.receivers.as_slice().choose(rng).cloned())
    })
}

/// Wrapper to generate a random `u32` from one of the ranges in `Config`.
fn gen_range<F>(f: F) -> u32
where
    F: FnOnce(&Config) -> RangeInclusive<u32>,
{
    CONFIG.with_borrow(|config| RNG.with_borrow_mut(|rng| rng.gen_range(f(&config))))
}

/// Returns a message id for use in keeping records.
fn next_call_id() -> u32 {
    let id = CALL_ID.take();
    CALL_ID.set(id + 1);
    id
}

/// Attemps to call a randomly chosen `receiver` with a random payload size. Records calls
/// attempted in `RECORDS` in the order they were made. Once a reply is received, this record is
/// updated in place.
fn try_call() -> Result<(), ()> {
    let receiver = choose_receiver().ok_or(())?;
    let payload_bytes = gen_range(|config| config.call_bytes_min..=config.call_bytes_max);

    let call_id = next_call_id();
    let on_reply = move || {
        let reply = api::arg_data();
        set_reply(call_id, Reply::Bytes(reply.len() as u32));
    };
    let on_reject = move || {
        set_reply(
            call_id,
            Reply::AsynchronousRejection(api::reject_code(), api::reject_message()),
        );
    };

    match api::call_with_callbacks(
        api::CanisterId::try_from(receiver).unwrap(),
        "handle_call",
        &vec![0_u8; payload_bytes as usize][..],
        on_reply,
        on_reject,
    ) {
        0 => {
            insert_new_call_record(
                call_id,
                Record {
                    receiver,
                    sent_bytes: payload_bytes,
                    reply: None,
                },
            );
            Ok(())
        }
        error_code => {
            insert_new_call_record(
                call_id,
                Record {
                    receiver,
                    sent_bytes: payload_bytes,
                    reply: Some(Reply::SynchronousRejection(error_code)),
                },
            );
            Err(())
        }
    }
}

/// Replies with a random payload size after a random count of instructions have passed.
fn reply() {
    let payload_bytes = gen_range(|config| config.reply_bytes_min..=config.reply_bytes_max);
    let instructions_count =
        gen_range(|config| config.instructions_count_min..=config.instructions_count_max);

    // Do some thinking.
    let counts = api::performance_counter(0) + instructions_count as u64;
    while counts > api::performance_counter(0) {}

    let msg = vec![0_u8; payload_bytes as usize];
    api::reply(&msg[..]);
}

/// Determines whether a downstream call should be attempted or if a reply should be sent back.
fn probe_make_call() -> bool {
    CONFIG.with_borrow(|config| {
        let dist = rand::distributions::WeightedIndex::new(&[
            config.downstream_call_weight,
            config.reply_weight,
        ])
        .unwrap();
        let choices = [true, false];
        RNG.with_borrow_mut(|rng| choices[dist.sample(rng)])
    })
}

/// Randomly determines whether to make a downstream call; reply if not or if the downstream call fails.
#[export_name = "canister_update handle_call"]
fn handle_call() {
    if probe_make_call() {
        if let Err(()) = try_call() {
            reply();
        }
    } else {
        reply();
    }
}

/// Attempts to call random canisters; stops once
/// - the maximum number of calls per round is reached.
/// - calling fails synchronously.
#[export_name = "canister_heartbeat"]
fn heartbeat() {
    //let calls_per_round = CALLS_PER_ROUND.get();
    //for _ in 0..calls_per_round {
    for _ in 0..CALLS_PER_ROUND.get() {
        if let Err(()) = try_call() {
            return;
        }
    }
}

#[export_name = "canister_init"]
fn main() {}
