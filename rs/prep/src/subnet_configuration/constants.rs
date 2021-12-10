use ic_types::Height;
use std::time::Duration;

pub const KILOBYTE: u64 = 1024;
pub const MEGABYTE: u64 = KILOBYTE * KILOBYTE;
/// The configuration for app subnets is used for new app subnets with at most
/// 13 nodes. App subnets with more than 13 nodes will be deployed with the NNS
/// subnet configs.
pub const SMALL_APP_SUBNET_MAX_SIZE: usize = 13;
pub const UNIT_DELAY_APP_SUBNET: Duration = Duration::from_millis(1000);
pub const UNIT_DELAY_NNS_SUBNET: Duration = Duration::from_millis(3000);
pub const INITIAL_NOTARY_DELAY_APP_SUBNET: Duration = Duration::from_millis(600);
pub const INITIAL_NOTARY_DELAY_NNS_SUBNET: Duration = Duration::from_millis(2000);
pub const INGRESS_BYTES_PER_BLOCK_SOFT_CAP: u64 = 2 * MEGABYTE;
pub const MAX_INGRESS_MESSAGES_PER_BLOCK: u64 = 1000;
pub const MAX_BLOCK_PAYLOAD_SIZE: u64 = 4 * MEGABYTE;
/// This sets the upper bound on how big a single ingress message can be, as
/// allowing messages larger than around 3.5MB has various security and
/// performance impacts on the network.  More specifically, large messages can
/// allow dishonest block makers to always manage to get their blocks notarized;
/// and when the consensus protocol is configured for smaller messages, a large
/// message in the network can cause the finalization rate to drop.
pub const MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET: u64 = 2 * MEGABYTE;
pub const MAX_INGRESS_BYTES_PER_MESSAGE_NNS_SUBNET: u64 = 3 * MEGABYTE + 512 * KILOBYTE;
/// The default length for a DKG interval. This is the number of rounds we
/// would have after a DKG summary block, making the total length
/// `DKG_INTERVAL_LENGTH` + 1.
pub const DKG_INTERVAL_LENGTH_APP_SUBNET: Height = Height::new(499);
pub const DKG_INTERVAL_LENGTH_NNS_SUBNET: Height = Height::new(99);
/// The default upper bound for the number of allowed dkg dealings in a
/// block.
pub const DKG_DEALINGS_PER_BLOCK: usize = 1;
// for subnets with more than 13 nodes constants for large networks are used
