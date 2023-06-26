use ic_registry_routing_table::CanisterIdRange;

pub(crate) fn canister_id_range_to_string(canister_id_range: &CanisterIdRange) -> String {
    format!("{}:{}", canister_id_range.start, canister_id_range.end)
}

pub(crate) fn canister_id_ranges_to_strings(canister_id_ranges: &[CanisterIdRange]) -> Vec<String> {
    canister_id_ranges
        .iter()
        .map(canister_id_range_to_string)
        .collect::<Vec<_>>()
}
