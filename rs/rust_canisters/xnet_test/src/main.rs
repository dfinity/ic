//! This module contains a canister used for XNet integration test.
//!
//! In order to build it, run:
//!
//! ```text
//! cargo build --target wasm32-unknown-unknown --release
//! ```
use candid::{CandidType, Deserialize, Principal};
use futures::future::join_all;
use ic_cdk::api::management_canister::provisional::CanisterId;
use ic_cdk::{
    api::{
        call::{call, call_with_payment},
        caller, canister_balance, id, time,
    },
    setup,
};
use ic_cdk_macros::{heartbeat, query, update};
use rand::Rng;
use rand_pcg::Lcg64Xsh32;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use xnet_test::{Metrics, NetworkTopology, StartArgs};

thread_local! {
    /// Whether this canister is generating traffic.
    ///
    /// The canister starts generating traffic when it received "start" message
    /// and stops when it receives "stop" message.
    static RUNNING: RefCell<bool> = const { RefCell::new(false) };

    /// The configuration of the subnets that should be specified in the init
    /// argument on canister install. A `Vec` of subnets, each a `Vec` of canister IDs.
    static NETWORK_TOPOLOGY: RefCell<NetworkTopology> = const { RefCell::new(Vec::new()) };

    /// Number of requests to send to each subnet (other than ours) every round.
    static PER_SUBNET_RATE: RefCell<u64> = const { RefCell::new(1) };

    /// Pad requests AND responses to this size (in bytes) if smaller.
    static PAYLOAD_SIZE: RefCell<u64> = const { RefCell::new(1024) };

    /// State of the messaging that we use to check invariants (e.g., sequence
    /// numbers).
    static STATE: RefCell<MessagingState> = RefCell::new(Default::default());

    /// Various metrics observed by this canister, e.g. message latency distribution.
    static METRICS: RefCell<Metrics> = RefCell::new(Default::default());

    /// The pseudo-random number generator we use to pick the next canister to talk to.
    /// It doesn't need to be cryptographically secure, we just want it to be simple and fast.
    /// The default values for state and stream parameters come from the official documentation:
    /// https://rust-random.github.io/rand/rand_pcg/struct.Lcg64Xsh32.html
    static RNG: RefCell<Lcg64Xsh32> = RefCell::new(Lcg64Xsh32::new(0xcafe_f00d_d15e_a5e5, 0x0a02_bdbf_7bb3_c0a7));
}

/// Input for `return_cycles` method.
#[derive(CandidType, Deserialize)]
struct CanisterIdRecord {
    canister_id: Principal,
}

/// Request sent by the "fanout" method.
#[derive(CandidType, Deserialize)]
struct Request {
    /// Sequence number of this message in the stream of messages sent to the
    /// destination canister.
    seq_no: u64,
    /// Local time observed in the round when this message was sent.
    time_nanos: u64,
    /// Optional padding, to bring the payload to the desired byte size.
    #[serde(with = "serde_bytes")]
    padding: Vec<u8>,
}

/// A `Reply` to the `Request` message, sent from the "handle_request" method.
#[derive(CandidType, Deserialize)]
struct Reply {
    /// Time copied from the corresponding request.  It's used to compute the
    /// roundtrip latency on the caller side.
    time_nanos: u64,
    /// Optional padding, to bring the payload to the desired byte size.
    #[serde(with = "serde_bytes")]
    padding: Vec<u8>,
}

/// State of the XNet messaging.
#[derive(Default)]
struct MessagingState {
    /// The last sequence number expected to be observed in a request from the
    /// corresponding canister.
    in_seq_no: BTreeMap<CanisterId, u64>,
    /// The last sequence number used to send a message to the corresponding
    /// canister.
    out_seq_no: BTreeMap<CanisterId, u64>,
}

impl MessagingState {
    fn next_out_seq_no(&mut self, canister_id: CanisterId) -> u64 {
        let entry = self.out_seq_no.entry(canister_id).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Sets `in_seq_no` to the provided value and returns the previous value.
    fn set_in_seq_no(&mut self, canister_id: CanisterId, in_seq_no: u64) -> u64 {
        let entry = self.in_seq_no.entry(canister_id).or_insert(0);
        let res = *entry;
        *entry = in_seq_no;
        res
    }
}

/// Returns true if this canister should continue generating traffic.
fn is_running() -> bool {
    RUNNING.with(|r| *r.borrow())
}

/// Canister heartbeat, calls `fanout()` if `RUNNING` is `true`.
#[heartbeat]
async fn heartbeat() {
    if !is_running() {
        return;
    }

    fanout().await;
}

/// Appends a message to the log, ensuring log size stays below 2000 bytes.
fn log(message: &str) {
    METRICS.with(|m| {
        let mut m = m.borrow_mut();
        m.log.push_str(message);
        m.log.push('\n');
        if m.log.len() > 2000 {
            let mut split_index = m.log.len() - 1000;
            while !m.log.is_char_boundary(split_index) {
                split_index += 1;
            }
            m.log = m.log.split_off(split_index);
        }
    });
}

/// Initializes network topology and instructs this canister to start sending
/// requests to other canisters.
#[update]
fn start(start_args: StartArgs) -> String {
    NETWORK_TOPOLOGY.with(move |canisters| {
        *canisters.borrow_mut() = start_args.network_topology;
    });
    PER_SUBNET_RATE.with(|r| *r.borrow_mut() = start_args.canister_to_subnet_rate);
    PAYLOAD_SIZE.with(|r| *r.borrow_mut() = start_args.payload_size_bytes);

    RUNNING.with(|r| *r.borrow_mut() = true);

    "started".to_string()
}

/// Stops traffic.
#[update]
fn stop() -> String {
    RUNNING.with(|r| *r.borrow_mut() = false);
    "stopped".to_string()
}

/// Sends `PER_SUBNET_RATE` messages to random canisters on the remote subnets.
/// Invoked by the canister heartbeat handler as long as `RUNNING` is `true`
/// (`start()` was and `stop()` was not yet called).
async fn fanout() {
    let self_id = id();

    let network_topology =
        NETWORK_TOPOLOGY.with(|network_topology| network_topology.borrow().clone());

    let mut futures = vec![];
    for canisters in network_topology {
        if canisters.is_empty() {
            continue;
        }

        if canisters.contains(&self_id) {
            // Same subnet
            continue;
        }

        for _ in 0..PER_SUBNET_RATE.with(|r| *r.borrow()) {
            let idx = RNG.with(|rng| rng.borrow_mut().gen_range(0..canisters.len()));
            let canister = canisters[idx];

            let seq_no = STATE.with(|s| s.borrow_mut().next_out_seq_no(canister));

            let payload_size = PAYLOAD_SIZE.with(|p| *p.borrow()) as usize;
            let payload = Request {
                seq_no,
                time_nanos: time(),
                padding: vec![0; payload_size.saturating_sub(16)],
            };

            let res = call::<(Request,), (Reply,)>(canister, "handle_request", (payload,));
            futures.push(res);
            METRICS.with(move |m| m.borrow_mut().calls_attempted += 1);
        }
    }

    let results = join_all(futures).await;

    for res in results {
        match res {
            Ok((reply,)) => {
                let elapsed = Duration::from_nanos(time() - reply.time_nanos);
                METRICS.with(|m| m.borrow_mut().latency_distribution.observe(elapsed));
            }
            Err((err_code, err_message)) => {
                // Catch whether the call failed due to a synchronous or
                // asynchronous error. Based on the current implementation of
                // the Rust CDK, a synchronous error will contain a specific
                // error message.
                if err_message.contains("Couldn't send message") {
                    log(&format!(
                        "{} call failed with {:?}",
                        time() / 1_000_000,
                        err_code
                    ));
                    METRICS.with(|m| m.borrow_mut().call_errors += 1);
                } else {
                    METRICS.with(|m| m.borrow_mut().reject_responses += 1);
                }
            }
        }
    }
}

/// Endpoint that handles requests from canisters located on remote subnets.
#[update]
fn handle_request(req: Request) -> Reply {
    let caller = caller();
    let in_seq_no = STATE.with(|s| s.borrow_mut().set_in_seq_no(caller, req.seq_no));

    if req.seq_no <= in_seq_no {
        METRICS.with(|m| m.borrow_mut().seq_errors += 1);
    }

    let payload_size = PAYLOAD_SIZE.with(|p| *p.borrow()) as usize;
    Reply {
        time_nanos: req.time_nanos,
        padding: vec![0; payload_size.saturating_sub(8)],
    }
}

/// Deposits the cycles this canister has minus 1T at the given destination.
#[update]
async fn return_cycles(canister_id_record: CanisterIdRecord) -> String {
    let cycle_refund = canister_balance().saturating_sub(1_000_000_000_000);
    let _ = call_with_payment::<(CanisterIdRecord,), ()>(
        Principal::from_str("aaaaa-aa").unwrap(),
        "deposit_cycles",
        (canister_id_record,),
        cycle_refund,
    )
    .await;

    "ok".to_string()
}

/// Query call that serializes metrics as a candid message.
#[query]
fn metrics() -> Metrics {
    METRICS.with(|m| m.borrow().clone())
}

#[export_name = "canister_init"]
fn main() {
    setup();
}
