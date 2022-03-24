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

    use std::iter::once;
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

    // Compute the inversion of id ranges that belong to the subnet.
    //
    // For that we build lists of left and right bounds (adjusted to include the
    // unbounded intervals to the left and to the right of the assigned
    // intervals) and zip these two lists together.
    //
    // Example:
    //
    // Input range:     [[1, 10], [20, 40]] (all bounds inclusive)
    //
    // Left bounds:     | Unbounded   | Excluded(10) | Excluded(40) |
    // Right bounds:    | Excluded(1) | Excluded(20) | Unbounded    |
    //
    // Zip column-wise: [(-inf, 1), (10, 20), (40, inf)]
    let lbounds = once(Unbounded).chain(id_ranges.iter().map(|l| Excluded(l.end)));
    let rbounds = id_ranges
        .iter()
        .map(|r| Excluded(r.start))
        .chain(once(Unbounded));

    // Mark for deletion all the canisters that fall into inverted intervals.
    #[allow(clippy::let_and_return)]
    let canister_ids = lbounds
        .zip(rbounds)
        .flat_map(|bounds| {
            state
                .canister_states
                .range(bounds)
                .map(|(canister_id, _)| *canister_id)
        })
        .collect();

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
