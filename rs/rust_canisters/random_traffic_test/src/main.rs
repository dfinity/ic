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
use std::ops::RangeInclusive;

thread_local! {
    /// Random number generator used for determining payload sizes et.al.
    static RNG: RefCell<StdRng> = RefCell::new(StdRng::seed_from_u64(13));
    /// Weight for making a reply used in a weighted binomial distribution.
    static REPLY_WEIGHT: Cell<u32> = const { Cell::new(1) };
    /// Weight for making a downstream call used in a weighted binomial distribution.
    static CALL_WEIGHT: Cell<u32> = const { Cell::new(0) };
    /// A configuration holding parameters for how to the canister should behave, such as the range
    /// of payload bytes it should send.
    static CONFIG: RefCell<Config> = RefCell::default();
    /// The maximum number of calls each heartbeat will attempt to make.
    static MAX_CALLS_PER_HEARTBEAT: Cell<u32> = Cell::default();
    /// A collection of records; one record for each call. Keeps track of how each call went,
    /// whether it was rejected or not and how many bytes we received as a reply.
    static RECORDS: RefCell<Vec<Record>> = RefCell::default();
}

/// Calls `f` on a candid type taken from `arg_data()`; sends replies the result of `f`.
fn with_candid_encoding<T, F>(f: F)
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

/// Sets the test config; returns the current config.
#[export_name = "canister_update set_config"]
fn set_config() {
    with_candid_encoding(|config: Config| CONFIG.replace(config));
}

/// Sets the requests per round to be sent each heart beat; returns the current value.
#[export_name = "canister_update set_max_calls_per_heartbeat"]
fn set_max_calls_per_heartbeat() {
    with_candid_encoding(|max_calls_per_heartbeat: u32| {
        MAX_CALLS_PER_HEARTBEAT.replace(max_calls_per_heartbeat)
    });
}

/// Sets the reply weight; returns the current weight.
#[export_name = "canister_update set_reply_weight"]
fn set_reply_weight() {
    with_candid_encoding(|reply_weight: u32| REPLY_WEIGHT.replace(reply_weight));
}

/// Sets the call weight; returns the current weight.
#[export_name = "canister_update set_call_weight"]
fn set_call_weight() {
    with_candid_encoding(|call_weight: u32| CALL_WEIGHT.replace(call_weight));
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

/// Returns the canister records.
#[export_name = "canister_query records"]
fn records() {
    let records = RECORDS.with_borrow(|records| records.to_vec());
    let msg = candid::Encode!(&records).unwrap();
    api::reply(&msg[..]);
}

/// Returns a random receiver if any.
fn choose_receiver() -> Option<CanisterId> {
    CONFIG.with_borrow(|config| {
        RNG.with_borrow_mut(|rng| config.receivers.as_slice().choose(rng).cloned())
    })
}

/// Generates a random u32 contained in `range`.
fn gen_range(range: RangeInclusive<u32>) -> u32 {
    RNG.with_borrow_mut(|rng| rng.gen_range(range))
}

/// Returns the call bytes range as defined in `CONFIG`.
fn call_bytes_range() -> RangeInclusive<u32> {
    CONFIG.with_borrow(|config| config.call_bytes_min..=config.call_bytes_max)
}

/// Returns the reply bytes range as defined in `CONFIG`.
fn reply_bytes_range() -> RangeInclusive<u32> {
    CONFIG.with_borrow(|config| config.reply_bytes_min..=config.reply_bytes_max)
}

/// Returns the instructions count range as defined in `CONFIG`.
fn instructions_count_range() -> RangeInclusive<u32> {
    CONFIG.with_borrow(|config| config.instructions_count_min..=config.instructions_count_max)
}

/// Attemps to call a randomly chosen `receiver` with a random payload size. Records calls
/// attempted in `RECORDS` in the order they were made. Once a reply is received, this record is
/// updated in place.
///
/// `on_response` is executed upon awaiting the outcome of the call, both on reply and on reject.
/// By contrast, it is important to report a synchronous rejection without calling `on_response`
/// because we could otherwise get stuck attempting new calls indefinitely.
fn try_call(on_response: impl FnOnce() + Copy + 'static) -> Result<(), ()> {
    let receiver = choose_receiver().ok_or(())?;
    let payload_bytes = gen_range(call_bytes_range());

    // Insert a new call record at the back of `RECORDS`; returns the `index` of the new element at
    // the back.
    let index = RECORDS.with_borrow_mut(|records| {
        records.push(Record {
            receiver,
            sent_bytes: payload_bytes,
            reply: None,
        });
        records.len() - 1
    });

    // Updates the `Reply` at `index` in `RECORDS`.
    let set_reply_in_call_record = move |reply: Reply| {
        RECORDS.with_borrow_mut(|records| {
            records[index].reply = Some(reply);
        });
    };

    let error_code = api::call_with_callbacks(
        receiver,
        "handle_call",
        &vec![0_u8; payload_bytes as usize][..],
        move || {
            set_reply_in_call_record(Reply::Bytes(api::arg_data().len() as u32));
            on_response();
        },
        move || {
            set_reply_in_call_record(Reply::AsynchronousRejection(
                api::reject_code(),
                api::reject_message(),
            ));
            on_response();
        },
    );
    if error_code == 0 {
        Ok(())
    } else {
        set_reply_in_call_record(Reply::SynchronousRejection(error_code));
        Err(())
    }
}

/// Samples a weighted binomial distribution to decide whether to make a reply (true) or a
/// downstream call (false). Defaults to `true` for bad weights (e.g. both 0).
fn should_reply_now() -> bool {
    RNG.with_borrow_mut(|rng| {
        WeightedIndex::new([REPLY_WEIGHT.get(), CALL_WEIGHT.get()])
            .map_or(true, |dist| dist.sample(rng) == 0)
    })
}

/// Handles incoming calls; this method is called from the heartbeat method.
///
/// Replies if:
/// - sampling the weighted binomial distribution tells us to do so.
/// - if it tells us not to do so but the attempted downstream call fails synchronously.
///
/// Note that a reply to a successful downstream call is made from the callbacks provided for this
/// call; this amounts to awaiting the outcome of the call asynchronously first.
#[export_name = "canister_update handle_call"]
fn handle_call() {
    // Passing handle_call() as the `on_response` for `try_call()` leads to random call trees where
    // it is recursively decided to make another call or reply on each node upon awaiting the
    // outcome. The shape of the call tree is statistically determined by the values of `REPLY_WEIGHT`
    // and `CALL_WEIGHT`.
    //
    // Note: Awaiting each call before possibly making another one also ensures there is only ever
    // one response despite potentially multiple downstream calls, something that doesn't matter for
    // the heartbeat where calls are not awaited because the heartbeat can't give a response anyway.
    if should_reply_now() || try_call(handle_call).is_err() {
        let payload_bytes = gen_range(reply_bytes_range());
        let instructions_count = gen_range(instructions_count_range());

        // Do some thinking.
        let counts = api::performance_counter(0) + instructions_count as u64;
        while counts > api::performance_counter(0) {}

        let msg = vec![0_u8; payload_bytes as usize];
        api::reply(&msg[..]);
    }
}

/// Sends out calls to `handle_call()` on random instances of this canister as provided by the
/// `receivers` in `CONFIG`. This is done in quick succession without awaiting the outcome of these
/// calls until either `MAX_CALLS_PER_HEARTBEAT` is reached or a synchronous rejection is observed.
///
/// This approach makes sense for the heartbeat because
/// - it does not need to make a reply so it can freely make calls and then forget about them.
/// - it allows for a quick generation of a lot of traffic.
///
/// Note that each such call may then spawn its own call tree with a random structure determined by
/// the weights chosen, but unlike the heartbeat, the calls are awaited on each node in this call
/// trees. In a sense the heartbeat may plant up to `MAX_CALLS_PER_HEARTBEAT` new call trees very
/// quickly, but the trees then grow, wither and eventually die slowly.
#[export_name = "canister_heartbeat"]
fn heartbeat() {
    for _ in 0..MAX_CALLS_PER_HEARTBEAT.get() {
        // Passing a no-op to `try_call()` as the `on_response` reflects the' make calls and forget
        // about them' approach described above.
        if let Err(()) = try_call(|| {}) {
            return;
        }
    }
}

#[export_name = "canister_init"]
fn main() {}
