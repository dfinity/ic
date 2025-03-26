use ic_base_types::{CanisterId, PrincipalId};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    thread::LocalKey,
    time::{Duration, SystemTime},
};

/// Tracks the age of canister calls that are being made on behalf of another
/// canister (presumably, another NNS canister, especially NNS Governance).
///
/// Generally, this would be used in three simple steps:
///
/// ```
/// use ic_base_types::{CanisterId, PrincipalId};
/// use ic_nervous_system_proxied_canister_calls_tracker::ProxiedCanisterCallsTracker;
/// use std::{cell::RefCell, time::{Duration, SystemTime}};
///
/// // Step 0: Instantiate.
/// thread_local! {
///     static PROXIED_CANISTER_CALLS_TRACKER: RefCell<ProxiedCanisterCallsTracker> =
///         RefCell::new(ProxiedCanisterCallsTracker::new(
///             SystemTime::now, // In a canister, use dfn_core::api::call, or equivalent.
///         ));
/// }
///
/// // Step 1: Write: Track canister calls.
/// let caller = PrincipalId::new_user_test_id(0xCAFE);
/// let target_canister_id = CanisterId::from(0xBEEF);
/// {
///     let args = vec![0_u8];
///
///     // Tracking will end automatically when _tracker is dropped. To avoid
///     // clippy harassment regarding an apparently unused variable, choose a
///     // name that begins with _. The name must not be just _ though, because
///     // in that case, object gets dropped immediately (ending tracking of the
///     // method call that comes immediately after). _tracker is a reasonable
///     // choice.
///     let _tracker = ProxiedCanisterCallsTracker::start_tracking(
///         &PROXIED_CANISTER_CALLS_TRACKER,
///         caller,
///         target_canister_id,
///         "get_down_tonight",
///         &args,
///     );
///
///     // Do stuff, including await.
/// }
///
/// // Step 2: Read: Calculate statistics.
/// let age = PROXIED_CANISTER_CALLS_TRACKER.with(|tracker| -> Duration {
///     tracker
///         .borrow()
///         .get_method_name_caller_callee_to_in_flight_max_age()
///         .get(&("get_down_tonight".to_string(), caller, target_canister_id))
///         .map(|age| age.clone())
///         .unwrap_or_default()
/// });
/// println!("age: {} s", age.as_secs_f64());
/// ```
#[derive(Debug)]
pub struct ProxiedCanisterCallsTracker {
    clock: fn() -> SystemTime,
    next_call_id: ProxiedCallId,
    id_to_open_call: BTreeMap<ProxiedCallId, CanisterCallMetadata>,
}

impl ProxiedCanisterCallsTracker {
    /// # Arguments:
    /// * `clock` - A function that returns the current time. Used to determine
    ///   when tracking begins, ends, and how long canister calls (being made on
    ///   behalf of another (NNS) canister) have been in flight.
    pub fn new(clock: fn() -> SystemTime) -> Self {
        let next_call_id = ProxiedCallId(1);
        let id_to_open_call = BTreeMap::new();

        Self {
            clock,
            next_call_id,
            id_to_open_call,
        }
    }

    /// Returns an RAII object.
    ///
    /// That is, when that object is dropped, then tracking of the canister call
    /// (being made on behalf of another (NNS) canister) ends.
    ///
    /// This is what allows us to know what calls are in flight, and how long
    /// they have been in flight.
    pub fn start_tracking(
        ego: &'static LocalKey<RefCell<Self>>,
        caller: PrincipalId,
        callee: CanisterId,
        method_name: &str,
        args: &[u8],
    ) -> SingleProxiedCallTracker {
        let proxied_call_id = ego.with(|ego| {
            let mut ego = ego.borrow_mut();

            let proxied_call_id: ProxiedCallId = ego.next_call_id.next();
            let now = (ego.clock)();
            ego.id_to_open_call.insert(
                proxied_call_id,
                CanisterCallMetadata::new(now, caller, callee, method_name, args),
            );

            proxied_call_id
        });

        SingleProxiedCallTracker {
            proxied_call_id,
            parent: ego,
        }
    }

    /// Returns true if there are no in-flight canister calls that are being
    /// made on behalf of another (NNS) canister.
    pub fn is_empty(&self) -> bool {
        self.id_to_open_call.is_empty()
    }

    /// Returns how many in flight canister calls there are being made on behalf
    /// of some other (NNS) canister.
    pub fn len(&self) -> usize {
        self.id_to_open_call.len()
    }

    /// Returns a map to age of in flight canister call being made on behalf of
    /// another (NNS) canister.
    ///
    /// The map is keyed by caller (on whose behalf the call is being made),
    /// callee (i.e. the canister being called), and method name.
    pub fn get_method_name_caller_callee_to_in_flight_max_age(
        &self,
    ) -> BTreeMap<(String, PrincipalId, CanisterId), Duration> {
        let now = (self.clock)();
        let mut result = BTreeMap::new();

        for call in self.id_to_open_call.values() {
            let CanisterCallMetadata {
                created_at,
                caller,
                callee,
                method_name,

                args_metadata: _,
            } = call.clone();

            // now - created_at
            let age = now.duration_since(created_at).unwrap_or_else(|err| {
                // This occurs when the original time is somehow in the
                // future. Whereas, Duration does not support negative values.
                println!(
                    "Call was logged at {} s in the future. WAT.",
                    err.duration().as_secs_f64()
                );

                // An absurd value that people will hopefully recognize, and
                // realize that we are experiencing this bug.
                Duration::from_secs(9_876_543_210)
            });

            let key = (method_name, caller, callee);
            result
                .entry(key)
                // This does not replace current value. Only inserts if there is
                // no value for key yet. We do not want to replace existing
                // value, because it must be larger, This is because the oldest
                // entries in self.id_to_open_call are in the "front".
                .or_insert(age);
        }

        result
    }

    pub fn get_method_name_caller_callee_to_in_flight_count(
        &self,
    ) -> BTreeMap<(String, PrincipalId, CanisterId), u64> {
        let mut result = BTreeMap::new();

        for call in self.id_to_open_call.values() {
            let CanisterCallMetadata {
                caller,
                callee,
                method_name,

                created_at: _,
                args_metadata: _,
            } = call.clone();

            let key = (method_name, caller, callee);
            let value = result.entry(key).or_default();

            *value += 1
        }

        result
    }
}

/// You wouldn't construct one of these directly. Instead, you get one of these
/// by calling ProxiedCanisterCallsTracker::start_tracking.
///
/// When this gets dropped, tracking of the canister call ends (per the RAII
/// pattern).
pub struct SingleProxiedCallTracker {
    proxied_call_id: ProxiedCallId,
    parent: &'static LocalKey<RefCell<ProxiedCanisterCallsTracker>>,
}

impl Drop for SingleProxiedCallTracker {
    fn drop(&mut self) {
        let proxied_call_id = self.proxied_call_id;
        self.parent.with(|parent| {
            parent.borrow_mut().id_to_open_call.remove(&proxied_call_id);
        });
    }
}

// Privates
// ========

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
struct ProxiedCallId(u128);

impl ProxiedCallId {
    /// Behaves like the suffix ++ operator in C.
    ///
    /// Does two things:
    ///   1. Returns inner value (as of when entering the call).
    ///   2. Increments (with wrapping) the internal value.
    fn next(&mut self) -> Self {
        let result = self.0;
        self.0 = self.0.wrapping_add(1);
        Self(result)
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct CanisterCallMetadata {
    created_at: SystemTime,
    caller: PrincipalId,
    callee: CanisterId,
    method_name: String,
    // This is not used yet, but it contains some nice data. Also, care has been
    // taken to avoid taking up an inordinate amount of space.
    args_metadata: CanisterCallArgsMetadata,
}

impl CanisterCallMetadata {
    fn new(
        created_at: SystemTime,
        caller: PrincipalId,
        callee: CanisterId,
        method_name: &str,
        args: &[u8],
    ) -> Self {
        let method_name = method_name.to_string();
        let args_metadata = CanisterCallArgsMetadata::new(args);

        Self {
            created_at,
            caller,
            callee,
            method_name,
            args_metadata,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Eq, PartialEq, Debug)]
struct CanisterCallArgsMetadata {
    len: usize,

    // These could overlap.
    head: Vec<u8>,
    tail: Vec<u8>,
    // We could also add hash, but it seems pretty unlikely that that would be
    // useful.
    //
    // Another thing we could potentially put here: is_candid_deserializable.
}

impl CanisterCallArgsMetadata {
    // The particular value used here is fairly arbitrary. The only important
    // property of this number is that it is smallish to avoid blowing up
    // memory. E.g. 42 or 100 would probably do just as well.
    const SLICE_SIZE: usize = 64;

    fn new(args: &[u8]) -> Self {
        let len = args.len();

        let head_end = Self::SLICE_SIZE.min(len);
        let head = args[0..head_end].to_vec();

        let tail_start = len.saturating_sub(Self::SLICE_SIZE);
        let tail = args[tail_start..len].to_vec();

        Self { len, head, tail }
    }
}

#[cfg(test)]
mod tests;
