/// [IC-1718]: Whether the `hashes-in-blocks` feature is enabled. If the flag is set to `true`, we
/// will strip all ingress messages and IDKG dealings from blocks, before sending them to peers.
/// On a receiver side, we will reconstruct the blocks by looking up the referenced ingress messages
/// in the ingress pool and IDKG dealings in the IDKG pool, or, if they are not there, by fetching
/// missing artifacts from peers who are advertising the blocks.
pub const HASHES_IN_BLOCKS_ENABLED: bool = true;

/// Whether the new, proposal driven, subnet splitting is supported by the Consensus protocol.
pub const SUBNET_SPLITTING_V2_ENABLED: bool = false;
