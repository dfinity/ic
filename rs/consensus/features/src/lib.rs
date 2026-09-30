/// [IC-1718]: Whether the `hashes-in-blocks` feature is enabled. If the flag is set to `true`, we
/// will strip all ingress messages, IDKG dealings and canister HTTP responses from blocks,
/// before sending them to peers.
/// On a receiver side, we will reconstruct the blocks by looking up the referenced ingress messages
/// in the ingress pool, IDKG dealings in the IDKG pool and canister HTTP responses in the canister
/// HTTP pool, or, if they are not there, by fetching missing artifacts from peers who are
/// advertising the blocks.
pub const HASHES_IN_BLOCKS_ENABLED: bool = true;
