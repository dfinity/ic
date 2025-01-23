use candid::{CandidType, Encode};
use futures::future::select_all;
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::{api, caller, id};
use ic_cdk_macros::{heartbeat, init, query, update};
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
use std::future::Future;
use std::hash::{DefaultHasher, Hasher};
use std::ops::RangeInclusive;

thread_local! {
    /// Random number generator used for determining payload sizes et.al.
    static RNG: RefCell<StdRng> = RefCell::new(StdRng::seed_from_u64(13));
    /// Weight for making a reply used in a weighted binomial distribution.
    static REPLY_WEIGHT: Cell<u32> = const { Cell::new(1) };
    /// Weight for making a downstream call used in a weighted binomial distribution.
    static CALL_WEIGHT: Cell<u32> = const { Cell::new(0) };
    /// A configuration holding parameters determining the canisters behavior, such as the range
    /// of payload bytes it should send.
    static CONFIG: RefCell<Config> = RefCell::default();
    /// The maximum number of calls each heartbeat will attempt to make.
    static MAX_CALLS_PER_HEARTBEAT: Cell<u32> = Cell::default();
    /// A hasher used to generate unique call tree IDs.
    static HASHER: RefCell<DefaultHasher> = RefCell::default();
    /// An index for each attempted call; starts at 0 and then increments with each call.
    static CALL_INDEX: Cell<u32> = Cell::default();
    /// A collection of records; one record for each call. Keeps track of how each call went,
    /// whether it was rejected or not and how many bytes were received.
    static RECORDS: RefCell<BTreeMap<u32, Record>> = RefCell::default();
    /// A counter for synchronous rejections.
    static SYNCHRONOUS_REJECTIONS_COUNT: Cell<u32> = Cell::default();
}

/// The intercanister message sent to `handle_call()` by the heartbeat of this canister
/// or `handle_call()` itself in case of a downstream call.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, CandidType)]
struct Message {
    /// A unique ID to allow tracing of call trees in the records.
    call_tree_id: u32,
    /// The depth of the call starting from 0 and incrementing by 1 for each downstream call.
    call_depth: u32,
    /// A payload of a certain size; it otherwise does not any contain information.
    payload: Vec<u8>,
}

impl Message {
    /// Creates a new `Message` of size `bytes_count`; may slightly exceed the target for
    /// very small numbers.
    fn new(call_tree_id: u32, call_depth: u32, bytes_count: usize) -> Self {
        Self {
            call_tree_id,
            call_depth,
            payload: vec![0_u8; bytes_count.saturating_sub(std::mem::size_of::<Self>())],
        }
    }

    /// Returns the number of bytes the message consists of.
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.payload.len()
    }
}

/// Returns a random receiver if any.
fn choose_receiver() -> Option<CanisterId> {
    CONFIG.with_borrow(|config| {
        RNG.with_borrow_mut(|rng| config.receivers.as_slice().choose(rng).cloned())
    })
}

/// Generates a random `u32` contained in `range`.
fn gen_range(range: RangeInclusive<u32>) -> u32 {
    RNG.with_borrow_mut(|rng| rng.gen_range(range))
}

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

/// Returns `true` if `error_msg` corresponds to a synchronous rejection.
fn synchronous_rejection(error_msg: &str) -> bool {
    error_msg.contains("Couldn't send message")
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

/// Sets the test config; returns the current config.
#[update]
fn set_config(config: Config) -> Config {
    CONFIG.replace(config)
}

/// Sets the requests per round to be sent each heart beat; returns the current value.
#[update]
fn set_max_calls_per_heartbeat(max_calls_per_heartbeat: u32) -> u32 {
    MAX_CALLS_PER_HEARTBEAT.replace(max_calls_per_heartbeat)
}

/// Sets the reply weight; returns the current weight.
#[update]
fn set_reply_weight(reply_weight: u32) -> u32 {
    REPLY_WEIGHT.replace(reply_weight)
}

/// Sets the call weight; returns the current weight.
#[update]
fn set_call_weight(call_weight: u32) -> u32 {
    CALL_WEIGHT.replace(call_weight)
}

/// Seeds `RNG`.
#[update]
fn seed_rng(seed: u64) {
    RNG.with_borrow_mut(|rng| *rng = StdRng::seed_from_u64(seed));
}

/// Returns the canister records.
#[query]
fn records() -> BTreeMap<u32, Record> {
    RECORDS.with_borrow(|records| records.clone())
}

/// Returns the number of synchronous rejections.
#[query]
fn synchronous_rejections_count() -> u32 {
    SYNCHRONOUS_REJECTIONS_COUNT.get()
}

/// Generates a future for a randomized call that can be awaited; inserts a new record at `index`
/// that must updated (or removed) after awaiting the call. For each call, the call index is
/// incremented by 1, such that successive calls have adjacent indices.
fn setup_call(
    receiver: CanisterId,
    call_tree_id: u32,
    call_depth: u32,
) -> (impl Future<Output = api::call::CallResult<Vec<u8>>>, u32) {
    let msg = Message::new(
        call_tree_id,
        call_depth,
        gen_range(call_bytes_range()) as usize,
    );

    // Inserts a new call record at the next `index`.
    let index = next_call_index();
    RECORDS.with_borrow_mut(|records| {
        records.insert(
            index,
            Record {
                receiver,
                caller: (call_depth > 0)
                    .then_some(CanisterId::unchecked_from_principal(PrincipalId(caller()))),
                call_tree_id,
                call_depth,
                sent_bytes: msg.count_bytes() as u32,
                reply: None,
            },
        );
    });

    let future = api::call::call_raw(receiver.into(), "handle_call", Encode!(&msg).unwrap(), 0);

    (future, index)
}

/// Updates the record at `index` using the `response` to the corresponding call.
///
/// Removes the record for a synchronous rejection since those can be quite numerous when the
/// subnet is at its limits. Note that since the call `index` is part of the records, removing
/// the records for synchronous rejections will result in gaps in these numbers thus they are
/// still included indirectly.
fn update_record(response: &api::call::CallResult<Vec<u8>>, index: u32) {
    // Updates the `Reply` at `index` in `RECORDS`.
    let set_reply_in_call_record = move |reply: Reply| {
        RECORDS.with_borrow_mut(|records| {
            let record = records.get_mut(&index).unwrap();
            assert!(record.reply.is_none(), "duplicate reply received");
            record.reply = Some(reply);
        });
    };
    match response {
        Err((_, msg)) if synchronous_rejection(msg) => {
            // Remove the record for synchronous rejections.
            SYNCHRONOUS_REJECTIONS_COUNT.set(SYNCHRONOUS_REJECTIONS_COUNT.get() + 1);
            RECORDS.with_borrow_mut(|records| {
                assert!(records.remove(&index).unwrap().reply.is_none())
            });
        }
        Err((reject_code, msg)) => {
            set_reply_in_call_record(Reply::Reject(*reject_code as u32, msg.to_string()));
        }
        Ok(result) => {
            set_reply_in_call_record(Reply::Bytes(result.len() as u32));
        }
    }
}

/// Generates `MAX_CALLS_PER_HEARTBEAT` calls as futures. The records are updated whenever a
/// reply comes in, i.e. not only after all of them have completed.
#[heartbeat]
async fn heartbeat() {
    let (mut futures, mut record_indices) = (Vec::new(), Vec::new());
    for _ in 0..MAX_CALLS_PER_HEARTBEAT.get() {
        let Some(receiver) = choose_receiver() else {
            return;
        };
        let (future, index) = setup_call(receiver, next_call_tree_id(), 0);
        futures.push(future);
        record_indices.push(index);
    }

    while !futures.is_empty() {
        // Wait for any call to conclude.
        let (result, index, remaining_futures) = select_all(futures).await;

        // Update records.
        update_record(&result, record_indices.remove(index));

        // Continue awaiting the remaining futures.
        futures = remaining_futures;
    }
}

/// Handles incoming calls; this method is called from the heartbeat method.
///
/// Replies if:
/// - sampling the weighted binomial distribution tells us to do so.
/// - if it tells us not to do so but the attempted downstream call fails for any reason.
#[update]
async fn handle_call(msg: Message) -> Vec<u8> {
    // Samples a weighted binomial distribution to decide whether to make a downstream call (true)
    // or reply (false). Defaults to `false` for bad weights (e.g. both 0).
    fn should_make_downstream_call() -> bool {
        RNG.with_borrow_mut(|rng| {
            WeightedIndex::new([CALL_WEIGHT.get(), REPLY_WEIGHT.get()])
                .is_ok_and(|dist| dist.sample(rng) == 0)
        })
    }

    // Make downstream calls until
    // - sampling the distribution tells us to stop.
    // - setting up a call fails.
    // - a downstream call is rejected for any reason.
    while should_make_downstream_call() {
        let Some(receiver) = choose_receiver() else {
            break;
        };
        let (future, record_index) = setup_call(receiver, msg.call_tree_id, msg.call_depth + 1);

        let result = future.await;
        update_record(&result, record_index);

        // Stop making downstream calls if a call fails; this prevents getting stuck in this loop
        // forever since at some point we must run out of memory if we just keep making calls.
        if result.is_err() {
            break;
        }
    }

    let payload_bytes = gen_range(reply_bytes_range());
    let instructions_count = gen_range(instructions_count_range());

    // Do some thinking.
    let counts = api::performance_counter(0) + instructions_count as u64;
    while counts > api::performance_counter(0) {}

    vec![0_u8; payload_bytes as usize]
}

/// Initializes the `HASHER` by hashing our own canister ID.
#[init]
fn initialize_hasher() {
    HASHER.with_borrow_mut(|hasher| hasher.write(id().as_slice()));
}

fn main() {}
