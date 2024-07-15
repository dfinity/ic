use std::time::Duration;

/// This constant defines the maximum amount of time an ingress message can wait
/// to start executing after submission before it is expired.  Hence, if an
/// ingress message is submitted at time `t` and it has not been scheduled for
/// execution till time `t+MAX_INGRESS_TTL`, it will be expired.
///
/// At the time of writing, this constant is also used to control how long the
/// status of a completed ingress message (IngressStatus ∈ [Completed, Failed])
/// is maintained by the IC before it is deleted from the ingress history.
pub const MAX_INGRESS_TTL: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// Duration subtracted from `MAX_INGRESS_TTL` by
/// `expiry_time_from_now()` when creating an ingress message.
pub const PERMITTED_DRIFT: Duration = Duration::from_secs(60);

/// Duration added to `MAX_INGRESS_TTL` when checking the max allowed
/// expiry at the http handler. The purpose is to admit ingress created with
/// MAX_INGRESS_TTL by clients with a slightly skewed local clock instead
/// of rejecting them right away.
pub const PERMITTED_DRIFT_AT_VALIDATOR: Duration = Duration::from_secs(30);

/// The maximum number of messages that can be present in the ingress history
/// at any one time.
///
/// The value is the product of the default `max_ingress_messages_per_block`
/// configured in the subnet record; and the `MAX_INGRESS_TTL` (assuming a block
/// rate of 1 block per second). Times 2, since we could theoretically have
/// `MAX_INGRESS_TTL` worth of `Received` messages; plus the same number of
/// messages in terminal states.
pub const INGRESS_HISTORY_MAX_MESSAGES: usize = 2 * 1000 * MAX_INGRESS_TTL.as_secs() as usize;

/// Message count limit for `System` subnet outgoing streams used for throttling
/// the matching input stream.
pub const SYSTEM_SUBNET_STREAM_MSG_LIMIT: usize = 100;

/// The `ic-prep` configuration for app subnets is used for new app subnets with at most
/// 13 nodes. App subnets with more nodes will be deployed with the `ic-prep`
/// configuration for NNS subnet.
pub const SMALL_APP_SUBNET_MAX_SIZE: usize = 13;

/// Cycles threshold to reduce logging load for canister operations with cycles.
pub const LOG_CANISTER_OPERATION_CYCLES_THRESHOLD: u128 = 100_000_000_000;
