use candid::CandidType;
use futures::future::select_all;
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::{
    api,
    call::{Call, CallFailed, CallFuture, Response as CallResponse},
};
use ic_cdk::{heartbeat, init, query, update};
use rand::{
    distributions::{Distribution, WeightedIndex},
    rngs::StdRng,
    seq::SliceRandom,
    Rng, SeedableRng,
};
use random_traffic_test::*;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::IntoFuture;
use std::hash::{DefaultHasher, Hasher};
use std::time::Duration;

thread_local! {
    /// A configuration holding parameters determining the canisters behavior, such as the range
    /// of payload bytes it should send.
    static CONFIG: RefCell<Config> = RefCell::default();
    /// Random number generator used for determining payload sizes et.al.
    static RNG: RefCell<StdRng> = RefCell::new(StdRng::seed_from_u64(13));
    /// A hasher used to generate unique call tree IDs.
    static HASHER: RefCell<DefaultHasher> = RefCell::default();
    /// An index for each attempted call; starts at 0 and then increments with each call.
    static CALL_INDEX: Cell<u32> = Cell::default();
    /// A collection of timestamps and records; one record for each call. Keeps track of whether it was
    /// rejected or not and how many bytes were sent and received.
    static RECORDS: RefCell<BTreeMap<u32, (u64, Record)>> = RefCell::default();
    /// Counter incremented at the end of the heartbeat to indicate successful invocations (as
    /// opposed to silent abortions).
    static SUCCESSFUL_HEARTBEAT_INVOCATIONS: Cell<u32> = Cell::default();
    /// A counter for synchronous rejections.
    static SYNCHRONOUS_REJECTIONS_COUNT: Cell<u32> = Cell::default();
    /// A `COIN` that can be 'flipped' to determine whether to make a downstream call or not.
    /// The default value set here will yield only 'reply'.
    static DOWNSTREAM_CALL_COIN: RefCell<WeightedIndex<u32>> = RefCell::new(WeightedIndex::<u32>::new([0, 100]).unwrap());
    /// A `COIN` that can be 'flipped' to determine whether to make a best-effort call or a guaranteed response call.
    /// The default value set here will yield only 'best_effort'
    static BEST_EFFORT_CALL_COIN: RefCell<WeightedIndex<u32>> = RefCell::new(WeightedIndex::<u32>::new([100, 0]).unwrap());
}

/// The intercanister message sent to `handle_call()` by the heartbeat of this canister
/// or `handle_call()` itself in case of a downstream call.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, CandidType)]
struct Message {
    /// A unique ID to allow tracing of call trees in the records.
    call_tree_id: u32,
    /// The depth of the call starting from 0 and incrementing by 1 for each downstream call.
    call_depth: u32,
    /// Optional padding, to bring the payload to the desired byte size.
    #[serde(with = "serde_bytes")]
    padding: Vec<u8>,
}

impl Message {
    /// Creates a new `Message` of size `bytes_count`; may slightly exceed the target for
    /// very small numbers.
    fn new(call_tree_id: u32, call_depth: u32, bytes_count: u32) -> Self {
        Self {
            call_tree_id,
            call_depth,
            padding: vec![0_u8; (bytes_count as usize).saturating_sub(std::mem::size_of::<Self>())],
        }
    }

    /// Returns the number of bytes the message consists of.
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.padding.len()
    }
}

/// Wrapper around the reply from `handle_call()` such that `serde_bytes` can be used.
#[derive(Serialize, Deserialize, CandidType)]
struct Reply(#[serde(with = "serde_bytes")] Vec<u8>);

/// Returns the next call index.
fn next_call_index() -> u32 {
    CALL_INDEX.replace(CALL_INDEX.get() + 1)
}

/// Returns the next call tree ID.
fn next_call_tree_id() -> u32 {
    HASHER.with_borrow_mut(|hasher| {
        // Hash something to generate a new unique number.
        hasher.write_u64(42);
        // Using only the upper 32 bits should be more than enough
        // since all we need is some unique number.
        (hasher.finish() >> 32) as u32
    })
}

/// Generates a random `u32` by sampling `min..=max`.
fn sample((min, max): (u32, u32)) -> u32 {
    RNG.with_borrow_mut(|rng| rng.gen_range(min..=max))
}

/// Generates a random payload size for a call.
fn gen_call_bytes() -> u32 {
    CONFIG.with_borrow(|config| sample(config.call_bytes_range))
}

/// Generates a random payload size for a reply.
fn gen_reply_bytes() -> u32 {
    CONFIG.with_borrow(|config| sample(config.reply_bytes_range))
}

/// Generates a random number of simulated instructions for generating a reply.
fn gen_instructions_count() -> u32 {
    CONFIG.with_borrow(|config| sample(config.instructions_count_range))
}

/// Generates a timeout in seconds for a best-effort call.
fn gen_timeout_secs() -> u32 {
    CONFIG.with_borrow(|config| sample(config.timeout_secs_range))
}

/// Picks a random receiver from `config.receivers` if any; otherwise return own canister ID.
fn receiver() -> CanisterId {
    match CONFIG.with_borrow(|config| {
        RNG.with_borrow_mut(|rng| config.receivers.as_slice().choose(rng).cloned())
    }) {
        Some(receiver) => receiver,
        None => CanisterId::try_from(api::canister_self().as_slice()).unwrap(),
    }
}

/// Sets the test config; returns the current config.
#[update]
fn set_config(config: Config) -> Config {
    fn to_weights(mut percentage: u32) -> [u32; 2] {
        if percentage > 100 {
            percentage = 100;
        }
        [percentage, 100 - percentage]
    }

    // Update `COINS`.
    DOWNSTREAM_CALL_COIN
        .replace(WeightedIndex::<u32>::new(to_weights(config.downstream_call_percentage)).unwrap());
    BEST_EFFORT_CALL_COIN.replace(
        WeightedIndex::<u32>::new(to_weights(config.best_effort_call_percentage)).unwrap(),
    );

    CONFIG.replace(config)
}

/// Seeds `RNG`.
#[update]
fn seed_rng(seed: u64) {
    RNG.with_borrow_mut(|rng| *rng = StdRng::seed_from_u64(seed));
}

/// Sets `CONFIG` such that the canister stops making calls altogether; returns the config
/// prior to modifying.
#[update]
fn stop_chatter() -> Config {
    set_config(CONFIG.with_borrow(|config| Config {
        calls_per_heartbeat: 0,
        downstream_call_percentage: 0,
        ..config.clone()
    }))
}

/// Returns the canister records.
#[query]
fn records() -> BTreeMap<u32, Record> {
    RECORDS.with_borrow(|records| {
        records
            .iter()
            .map(|(index, (_, record))| (*index, record.clone()))
            .collect()
    })
}

/// Returns the number of synchronous rejections.
#[query]
fn synchronous_rejections_count() -> u32 {
    SYNCHRONOUS_REJECTIONS_COUNT.get()
}

/// Returns the number of successful heartbeat invocations.
#[query]
fn successful_heartbeat_invocations() -> u32 {
    SUCCESSFUL_HEARTBEAT_INVOCATIONS.get()
}

/// Flip the `DOWNSTREAM_CALL_COIN` to determine whether we should make a downstream call or reply
/// instead.
fn should_make_downstream_call() -> bool {
    RNG.with_borrow_mut(|rng| DOWNSTREAM_CALL_COIN.with_borrow(|coin| coin.sample(rng)) == 0)
}

/// Flip the `BEST_EFFORT_COIN` to determine whether we should make a best-effort call or a
/// guaranteed response call.
fn should_make_best_effort_call() -> bool {
    RNG.with_borrow_mut(|rng| BEST_EFFORT_CALL_COIN.with_borrow(|coin| coin.sample(rng)) == 0)
}

/// Generates a future for a randomized call that can be awaited; inserts a new record at `index`
/// that must be updated (or removed) after awaiting the call. For each call, the call index is
/// incremented by 1, such that successive calls have adjacent indices.
fn setup_call(call_tree_id: u32, call_depth: u32) -> (CallFuture<'static, 'static>, u32) {
    let msg = Message::new(call_tree_id, call_depth, gen_call_bytes());
    let sent_bytes = msg.count_bytes() as u32;
    let receiver = receiver();
    let caller = (call_depth > 0).then_some(CanisterId::unchecked_from_principal(PrincipalId(
        api::msg_caller(),
    )));
    let timeout_secs = should_make_best_effort_call().then_some(gen_timeout_secs());

    let call = match timeout_secs {
        Some(timeout_secs) => {
            Call::bounded_wait(receiver.into(), "handle_call").change_timeout(timeout_secs)
        }
        None => Call::unbounded_wait(receiver.into(), "handle_call"),
    }
    .with_arg(msg);

    // Once the call was successfully generated, insert a call timestamp and record at `index`.
    let index = next_call_index();
    RECORDS.with_borrow_mut(|records| {
        records.insert(
            index,
            (
                api::time(),
                Record {
                    receiver,
                    caller,
                    call_tree_id,
                    call_depth,
                    sent_bytes,
                    timeout_secs,
                    duration_and_response: None,
                },
            ),
        )
    });

    (call.into_future(), index)
}

/// Updates the record at `index` using the `result` of the corresponding call.
///
/// Removes the record for a synchronous rejection since those can be quite numerous when the
/// subnet is at its limits. Note that since the call `index` is part of the records, removing
/// the records for synchronous rejections will result in gaps in these numbers thus they are
/// still included indirectly.
fn update_record(result: &Result<CallResponse, CallFailed>, index: u32) {
    // Updates the `Response` at `index` in `RECORDS`.
    let set_reply_in_call_record = move |response: Response| {
        RECORDS.with_borrow_mut(|records| {
            let (call_timestamp, record) = records.get_mut(&index).unwrap();
            assert!(
                record.duration_and_response.is_none(),
                "duplicate reply received"
            );
            let response_timestamp = api::time();
            assert!(
                response_timestamp >= *call_timestamp,
                "retrograde blocktime"
            );

            let call_duration = Duration::from_nanos(response_timestamp - *call_timestamp);
            record.duration_and_response = Some((call_duration, response));
        });
    };

    match result {
        Ok(response) => {
            let bytes_received = response
                .candid::<Reply>()
                .expect("candid decode failed")
                .0
                .len() as u32;
            set_reply_in_call_record(Response::Reply(bytes_received));
        }
        Err(CallFailed::InsufficientLiquidCycleBalance(_)) => {
            unreachable!("not doing anything with cycles for now");
        }
        Err(CallFailed::CallPerformFailed(_)) => {
            // Remove the record for synchronous rejections.
            SYNCHRONOUS_REJECTIONS_COUNT.set(SYNCHRONOUS_REJECTIONS_COUNT.get() + 1);
            RECORDS.with_borrow_mut(|records| {
                assert!(records
                    .remove(&index)
                    .unwrap()
                    .1
                    .duration_and_response
                    .is_none())
            });
        }
        Err(CallFailed::CallRejected(rejection)) => {
            set_reply_in_call_record(Response::Reject(
                rejection.raw_reject_code(),
                rejection.reject_message().to_string(),
            ));
        }
    }
}

/// Generates `calls_per_heartbeat` call futures. They are awaited; whenever a call concludes
/// its record is updated (or removed in case of a synchronous rejection).
///
/// Returns the number of successful calls (i.e. calls that got a reply).
#[update]
async fn pulse(calls_count: u32) -> u32 {
    let (mut futures, mut record_indices) = (Vec::new(), Vec::new());
    for _ in 0..calls_count {
        let (future, index) = setup_call(next_call_tree_id(), 0);
        futures.push(Box::pin(future));
        record_indices.push(index);
    }

    let mut calls_success_counter = 0;
    while !futures.is_empty() {
        // Wait for any call to conclude.
        let (result, index, remaining_futures) = select_all(futures).await;
        if result.is_ok() {
            calls_success_counter += 1;
        }

        // Update records.
        update_record(&result, record_indices.remove(index));

        // Continue awaiting the remaining futures.
        futures = remaining_futures;
    }

    calls_success_counter
}

/// Calls `pulse(calls_per_heartbeat)` each round; increments `SUCCESSFUL_HEARTBEAT_INVOCATIONS`
/// for heartbeats that try to make at least 1 call.
#[heartbeat]
async fn heartbeat() {
    let calls_count = CONFIG.with_borrow(|config| config.calls_per_heartbeat);
    if calls_count > 0 {
        pulse(calls_count).await;
        SUCCESSFUL_HEARTBEAT_INVOCATIONS
            .replace(SUCCESSFUL_HEARTBEAT_INVOCATIONS.get() + calls_count);
    }
}

/// Handles incoming calls; this method is called from the heartbeat method.
///
/// Replies if:
/// - flipping the coin tells us to do so.
/// - if it tells us not to do so but the attempted downstream call fails for any reason.
#[update]
async fn handle_call(msg: Message) -> Reply {
    // Make downstream calls as long as flipping the coin tells us to do so.
    while should_make_downstream_call() {
        let (future, record_index) = setup_call(msg.call_tree_id, msg.call_depth + 1);

        let result = future.await;
        update_record(&result, record_index);

        // Stop making downstream calls if a call fails; this prevents getting stuck in this loop
        // forever since at some point we must run out of memory if we just keep making calls.
        if result.is_err() {
            break;
        }
    }

    let payload_bytes = gen_reply_bytes();

    // Do some thinking.
    let counts = api::performance_counter(0) + gen_instructions_count() as u64;
    while counts > api::performance_counter(0) {}

    Reply(vec![0_u8; payload_bytes as usize])
}

/// Initializes the `HASHER` by hashing our own canister ID.
#[init]
fn initialize_hasher() {
    HASHER.with_borrow_mut(|hasher| hasher.write(api::canister_self().as_slice()));
}

fn main() {}
