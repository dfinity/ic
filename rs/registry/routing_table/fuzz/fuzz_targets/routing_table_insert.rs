#![no_main]
use arbitrary::Arbitrary;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;

thread_local! {
    static ROUTING_TABLE: RefCell<RoutingTable> = RefCell::new(RoutingTable::new());
}

#[derive(Debug, Arbitrary)]
struct RoutingTableInsertData {
    x: u64,
    y: u64,
    z: u64,
}


fuzz_target!(|table_data: RoutingTableInsertData| {
    let (start, end, subnet_id) = (CanisterId::from_u64(table_data.x), CanisterId::from_u64(table_data.y), table_data.z);

    let canister_ranges: CanisterIdRange;
    if start > end {
        canister_ranges = CanisterIdRange {
            start: end, 
            end: start,
        };
    } else {
        canister_ranges = CanisterIdRange {
            start: start, 
            end: end,
        };
    }

    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(subnet_id));

    let _ = ROUTING_TABLE.with_borrow_mut(|table| {table.insert(canister_ranges, subnet) });

});
