use crate::registry::Registry;
use candid::CandidType;
use ic_registry_routing_table::CanisterIdRange;
use ic_types::{NodeId, SubnetId};
use serde::{Deserialize, Serialize};

impl Registry {
    /// Validates the payload and applies the mutation derived from the payload to the registry.
    ///
    /// The following mutations will be performed on the registry:
    /// 1. add a new subnet,
    /// 2. update the subnet list record to include the newly added subnet,
    /// 3. update the catch up package contents of the `source` subnet, to include an information
    ///    that the subnet is split,
    /// 4. create catch up package contents for the newly added subnet,
    /// 5. modify the routing table and reroute some of the canister IDs from the source subnet to
    ///    the newly added subnet,
    /// 6. modify the CanisterMigrations entry, to also include the information that the source
    ///    subnet is being split.
    pub async fn split_subnet(&mut self, _payload: SplitSubnetPayload) -> Result<(), String> {
        unimplemented!();
    }
}

#[derive(Debug, CandidType, Deserialize, Serialize)]
pub struct SplitSubnetPayload {
    pub destination_canister_ranges: Vec<CanisterIdRange>,
    pub destination_node_ids: Vec<NodeId>,
    pub source_subnet_id: SubnetId,
}
