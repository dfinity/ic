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
/// `current_time_and_expiry_time()` when creating an ingress message.
pub const PERMITTED_DRIFT: Duration = Duration::from_secs(60);

/// Duration added to `MAX_INGRESS_TTL` when checking the max allowed
/// expiry at the http handler. The purpose is to admit ingress created with
/// MAX_INGRESS_TTL by clients with a slightly skewed local clock instead
/// of rejecting them right away.
pub const PERMITTED_DRIFT_AT_VALIDATOR: Duration = Duration::from_secs(30);

/// Duration added to `MAX_INGRESS_TTL` when checking the max allowed expiry
/// at the artifact manager when it receives ingress from http_handler or p2p.
/// The purpose is to account for time drift between subnet nodes.
///
/// Together with `PERMITTED_DRIFT_AT_VALIDATOR` we give some leeway to
/// accommodate possible time drift both between the user client and a subnet
/// node, and between subnet nodes.
///
/// Note that when a blockmaker creates a payload, it will only choose from
/// its ingress pool based on MAX_INGRESS_TTL. So time drift considerations
/// may lead to more messages being admitted to the ingress pool, but
/// shouldn't impact other parts of the system.
pub const PERMITTED_DRIFT_AT_ARTIFACT_MANAGER: Duration = Duration::from_secs(60);

/// Message count limit for `System` subnet outgoing streams used for throttling
/// the matching input stream.
pub const SYSTEM_SUBNET_STREAM_MSG_LIMIT: usize = 100;
