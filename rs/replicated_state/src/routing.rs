use crate::ReplicatedState;
use ic_base_types::{CanisterId, SubnetId};

/// Returns ids of canisters that do not belong to this subnet state according
/// to the subnet routing table.
pub fn find_canisters_not_in_routing_table(
    state: &ReplicatedState,
    own_subnet_id: SubnetId,
) -> Vec<CanisterId> {
    // Since we should almost never have canisters that are not in the
    // routing table, it is wasteful to traverse all our canisters every round.
    //
    // On the other hand, we expect the number of canister ranges assigned
    // to a subnet to be small.  So we traverse canister ranges instead and
    // use fast range queries on the canister map to find canisters outside
    // of assigned ranges.
    //
    // The overall complexity of this algorithm is `QR + log(N) * R`, where
    //   - QR is the cost of querying canister ranges assigned to a subnet.
    //   - N is the number of canisters.
    //   - R is the number or ranges assigned to the subnet.

    use std::ops::Bound::{Excluded, Unbounded};

    let routing_table = &state.metadata.network_topology.routing_table;

    let id_ranges: Vec<_> = routing_table
        .ranges(own_subnet_id)
        .iter()
        .cloned()
        .collect();

    if id_ranges.is_empty() {
        return state.canister_states.keys().cloned().collect();
    }

    let mut canister_ids = Vec::new();

    // Mark for deletion all the canisters to the left of the first range.
    if let Some(first_range) = id_ranges.first() {
        for (canister_id, _) in state
            .canister_states
            .range((Unbounded, Excluded(first_range.start)))
        {
            canister_ids.push(*canister_id);
        }
    }
    // Mark for deletion all the canisters that slip between two successive ranges.
    for (left, right) in id_ranges.iter().zip(id_ranges.iter().skip(1)) {
        for (canister_id, _) in state
            .canister_states
            .range((Excluded(left.end), Excluded(right.start)))
        {
            canister_ids.push(*canister_id);
        }
    }
    // Mark for deletion all canisters to the right of the last range.
    if let Some(last_range) = id_ranges.last() {
        for (canister_id, _) in state
            .canister_states
            .range((Excluded(last_range.end), Unbounded))
        {
            canister_ids.push(*canister_id);
        }
    }

    // Post-condition: the "clever" algorithm behaves like the naive one.
    #[cfg(debug_assertions)]
    {
        let expected_canisters: Vec<_> = state
            .canister_states
            .keys()
            .filter(|id| routing_table.route(id.get()) != Some(own_subnet_id))
            .cloned()
            .collect();
        assert_eq!(expected_canisters, canister_ids);
    }

    canister_ids
}

#[cfg(test)]
mod tests;
