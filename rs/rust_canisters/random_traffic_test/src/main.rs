use candid::{Decode, Encode};
use dfn_core::api;
use ic_base_types::CanisterId;
use rand::{
    distributions::{Distribution, WeightedIndex},
    rngs::StdRng,
    seq::SliceRandom,
    Rng, SeedableRng,
};
use random_traffic_test::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;

thread_local! {
    /// Random number generator used for determining payload sizes et.al.
    static RNG: RefCell<StdRng> = RefCell::new(StdRng::seed_from_u64(13));
    /// Weight for making a reply used in a weighted binomial distribution.
    static REPLY_WEIGHT: Cell<u32> = Cell::new(1);
    /// Weight for making a downstream call used in a weighted binomial distribution.
    static CALL_WEIGHT: Cell<u32> = Cell::new(0);
    /// A configuration holding parameters for how to the canister should behave, such as the range
    /// of payload bytes it should send.
    static CONFIG: RefCell<Config> = RefCell::default();
    /// The maximum number of calls each heartbeat can make.
    static MAX_CALLS_PER_HEARTBEAT: Cell<u32> = Cell::default();
    /// An ID used as an entry in `RECORDS` unique for each call.
    static CALL_ID: Cell<u32> = Cell::default();
    /// A collection of records; one record for each call. Keeps track of how each call went,
    /// whether it was rejected or not and how many bytes we received as a reply.
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

/// Replaces the test config.
#[export_name = "canister_update replace_config"]
fn replace_config() {
    replace_state(|config: Config| CONFIG.replace(config));
}

/// Replaces the requests per round to be sent each heart beat.
#[export_name = "canister_update replace_max_calls_per_heartbeat"]
fn replace_max_calls_per_heartbeat() {
    replace_state(|max_calls_per_heartbeat: u32| {
        MAX_CALLS_PER_HEARTBEAT.replace(max_calls_per_heartbeat)
    });
}

/// Replaces the reply weight.
#[export_name = "canister_update replace_reply_weight"]
fn replace_reply_weight() {
    replace_state(|reply_weight: u32| REPLY_WEIGHT.replace(reply_weight));
}

/// Replaces the call weight.
#[export_name = "canister_update replace_call_weight"]
fn replace_call_weight() {
    replace_state(|call_weight: u32| CALL_WEIGHT.replace(call_weight));
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

/// Probes a weighted binomial distribution to decide whether to make a reply (true) or a
/// downstream call (false). Defaults to `true` for bad weights (i.e. both 0).
fn make_reply() -> bool {
    RNG.with_borrow_mut(|rng| {
        WeightedIndex::new(&[REPLY_WEIGHT.get(), CALL_WEIGHT.get()])
            .map(|dist| dist.sample(rng) == 0)
            .unwrap_or(true)
    })
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
fn try_call(is_downstream_call: bool) -> Result<(), ()> {
    let receiver = choose_receiver().ok_or(())?;
    let payload_bytes = gen_range(|config| config.call_bytes_min..=config.call_bytes_max);

    let call_id = next_call_id();
    let on_reply = move || {
        set_reply(call_id, Reply::Bytes(api::arg_data().len() as u32));
        if is_downstream_call {
            reply();
        }
    };
    let on_reject = move || {
        set_reply(
            call_id,
            Reply::AsynchronousRejection(api::reject_code(), api::reject_message()),
        );
        if is_downstream_call {
            reply();
        }
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

/// Randomly determines whether to make a downstream call; reply if not or if the downstream call fails.
#[export_name = "canister_update handle_call"]
fn handle_call() {
    if make_reply() {
        reply();
    } else {
        // Try to make a downstream call; reply if it fails synchronously.
        //
        // Note: replies for all other cases are handled in the corresponding
        // callbacks, so this function does reply on every branch.
        if let Err(()) = try_call(true) {
            reply();
        }
    }
}

/// Attempts to call random canisters; stops once
/// - the maximum number of calls per round is reached.
/// - calling fails synchronously.
#[export_name = "canister_heartbeat"]
fn heartbeat() {
    for _ in 0..MAX_CALLS_PER_HEARTBEAT.get() {
        if let Err(()) = try_call(false) {
            return;
        }
    }
}

#[export_name = "canister_init"]
fn main() {}
