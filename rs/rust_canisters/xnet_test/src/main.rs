//! This module contains a canister used for XNet integration test.
//!
//! In order to build it, run:
//!
//! ```text
//! cargo build --target wasm32-unknown-unknown --release
//! ```
use candid::{CandidType, Decode, Deserialize, Encode};
use dfn_core::api;
use rand::Rng;
use rand_pcg::Lcg64Xsh32;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;
use xnet_test::{CanisterId, Metrics, NetworkTopology};

thread_local! {
    /// Whether this canister is generating traffic.
    ///
    /// The canister starts generating traffic when it received "start" message
    /// and stops when it receives "stop" message.
    static RUNNING: RefCell<bool> = RefCell::new(false);

    /// The configuration of the subnets that should be specified in the init
    /// argument on canister install. A `Vec` of subnets, each a `Vec` of canister IDs.
    static NETWORK_TOPOLOGY: RefCell<NetworkTopology> = RefCell::new(Vec::new());

    /// Number of requests to send to each subnet (other than ours) every round.
    static PER_SUBNET_RATE: RefCell<u64> = RefCell::new(1);

    /// Pad requests AND responses to this size (in bytes) if smaller.
    static PAYLOAD_SIZE: RefCell<u64> = RefCell::new(1024);

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

/// Request sent by the "fanout" method.
#[derive(CandidType, Deserialize)]
struct Request {
    /// Sequence number of this message in the stream of messages sent to the
    /// destination canister.
    seq_no: u64,
    /// Local time observed in the round when this message was sent.
    time_nanos: u64,
}

/// A `Reply` to the `Request` message, sent from the "handle_request" method.
#[derive(CandidType, Deserialize)]
struct Reply {
    /// Time copied from the corresponding request.  It's used to compute the
    /// roundtrip latency on the caller side.
    time_nanos: u64,
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

/// Calls "msg_reply" with reply being argument encoded as Candid.
fn candid_reply<T: CandidType>(t: &T) {
    let msg = candid::Encode!(t).expect("failed to encode reply");
    api::reply(&msg[..])
}

/// Encodes `t` as Candid, padded to `PAYLOAD_SIZE`.
fn candid_encode_padded<T: CandidType>(t: &T) -> Vec<u8> {
    let msg = candid::Encode!(t, &vec![13u8; 1]).expect("failed to encode message");

    let payload_size = PAYLOAD_SIZE.with(|p| *p.borrow()) as usize;
    if msg.len() < payload_size {
        candid::Encode!(t, &vec![13u8; payload_size - msg.len() + 1])
            .expect("failed to encode message")
    } else {
        msg
    }
}

/// Returns system time in nanoseconds.
fn time_nanos() -> u64 {
    unsafe { api::ic0::time() }
}

/// Callback for handling replies from "handle_request".
fn on_reply(_env: *mut ()) {
    let (reply, _) =
        candid::Decode!(&api::arg_data()[..], Reply, Vec<u8>).expect("failed to decode response");
    let elapsed = Duration::from_nanos((time_nanos() - reply.time_nanos) as u64);
    METRICS.with(|m| m.borrow_mut().latency_distribution.observe(elapsed));
}

/// Callback for handling reject responses from "handle_request".
fn on_reject(_env: *mut ()) {
    METRICS.with(|m| m.borrow_mut().reject_responses += 1);
}

/// Returns true if this canister should continue generating traffic.
fn is_running() -> bool {
    RUNNING.with(|r| *r.borrow())
}

/// Enqueues a `fanout()` "loopback" call for next round.
fn schedule_fanout() {
    if !is_running() {
        return;
    }

    let noop = |_| ();
    let err_code = api::call_raw(
        api::id(),
        "fanout",
        &[][..],
        noop,
        noop,
        None,
        std::ptr::null_mut(),
        api::Funds::zero(),
    );
    if err_code != 0 {
        // This is a critical error (no more requests will be sent once this happens).
        log(&format!(
            "{} CRITICAL: fanout failed with {}\n",
            time_nanos() / 1_000_000,
            err_code
        ));
    }
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
#[export_name = "canister_update start"]
fn start() {
    dfn_core::printer::hook();
    let (network_topology, rate, payload_size) =
        candid::Decode!(&api::arg_data()[..], NetworkTopology, u64, u64)
            .expect("failed to decode subnet canister ids");

    NETWORK_TOPOLOGY.with(move |canisters| {
        *canisters.borrow_mut() = network_topology;
    });

    PER_SUBNET_RATE.with(|r| *r.borrow_mut() = rate);
    PAYLOAD_SIZE.with(|r| *r.borrow_mut() = payload_size);

    RUNNING.with(|r| *r.borrow_mut() = true);

    schedule_fanout();

    candid_reply(&"started");
}

/// Stops traffic.
#[export_name = "canister_update stop"]
fn stop() {
    RUNNING.with(|r| *r.borrow_mut() = false);
    candid_reply(&"stopped");
}

/// An internal endpoint that sends a messages to a random canister on each of
/// the remote subnets. This endpoint is repeatedly triggered from the "start"
/// call.
#[export_name = "canister_update fanout"]
fn fanout() {
    if !is_running() {
        return;
    }

    let self_id = api::id();

    let network_topology =
        NETWORK_TOPOLOGY.with(|network_topology| network_topology.borrow().clone());

    for canisters in network_topology {
        if canisters.is_empty() {
            continue;
        }

        if canisters.contains(&self_id.get().as_slice().to_vec()) {
            // Same subnet
            continue;
        }

        for _ in 0..PER_SUBNET_RATE.with(|r| *r.borrow()) {
            let idx = RNG.with(|rng| rng.borrow_mut().gen_range(0, canisters.len()));
            let canister = canisters[idx].clone();

            let seq_no = STATE.with(|s| s.borrow_mut().next_out_seq_no(canister.clone()));

            let msg = candid_encode_padded(&Request {
                seq_no,
                time_nanos: time_nanos(),
            });

            let err_code = api::call_raw(
                api::CanisterId::try_from(canister.clone()).unwrap(),
                "handle_request",
                &msg[..],
                on_reply,
                on_reject,
                None,
                std::ptr::null_mut(),
                api::Funds::zero(),
            );

            if err_code != 0 {
                log(&format!(
                    "{} call failed with {}",
                    time_nanos() / 1_000_000,
                    err_code
                ));
                METRICS.with(|m| m.borrow_mut().call_errors += 1);
            } else {
                METRICS.with(move |m| m.borrow_mut().requests_sent += 1);
            }
        }
    }

    candid_reply(&"ok");

    schedule_fanout();
}

/// Endpoint that handles requests from canisters located on remote subnets.
#[export_name = "canister_update handle_request"]
fn handle_request() {
    let (req, _) =
        candid::Decode!(&api::arg_data()[..], Request, Vec<u8>).expect("failed to decode request");
    let caller = api::caller();
    let in_seq_no = STATE.with(|s| {
        s.borrow_mut()
            .set_in_seq_no(caller.clone().into_vec(), req.seq_no)
    });

    if req.seq_no <= in_seq_no {
        METRICS.with(|m| m.borrow_mut().seq_errors += 1);
    }

    let msg = candid_encode_padded(&Reply {
        time_nanos: req.time_nanos,
    });
    api::reply(&msg[..]);
}

/// Deposits the cycles this canister has minus 1T according to the given
/// `DepositCyclesArgs`
#[export_name = "canister_update return_cycles"]
fn return_cycles() {
    let cycle_refund = api::canister_cycle_balance().saturating_sub(1_000_000_000_000);
    let noop = |_| ();
    let _ = api::call_raw(
        api::CanisterId::from_str("aaaaa-aa").unwrap(),
        "deposit_cycles",
        &api::arg_data(),
        noop,
        noop,
        None,
        std::ptr::null_mut(),
        api::Funds {
            cycles: cycle_refund,
        },
    );

    candid_reply(&"ok");
}

/// Query call that serializes metrics as a candid message.
#[export_name = "canister_query metrics"]
fn metrics() {
    let msg = METRICS
        .with(|m| candid::Encode!(&*m.borrow()))
        .expect("failed to encode metrics");

    api::reply(&msg[..]);
}

#[export_name = "canister_init"]
fn main() {}
