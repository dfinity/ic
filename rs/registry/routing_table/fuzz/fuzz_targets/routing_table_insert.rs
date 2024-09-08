#![no_main]
use arbitrary::Arbitrary;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges, RoutingTable};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::collections::HashSet;

thread_local! {
    static ROUTING_TABLE: RefCell<RoutingTable> = RefCell::new(RoutingTable::new());
    static KNOWN_SUBNET:  RefCell<HashSet<SubnetId>> = RefCell::new(HashSet::new());
}

#[derive(Debug, Arbitrary)]
struct RoutingTableInsertData {
    x: u64,
    y: u64,
    z: u64,
    migration: bool,
}

fuzz_target!(|table_data: RoutingTableInsertData| {
    let (start, end, subnet_id, migration) = (
        CanisterId::from_u64(table_data.x),
        CanisterId::from_u64(table_data.y),
        table_data.z,
        table_data.migration,
    );

    let canister_range = if start > end {
        CanisterIdRange {
            start: end,
            end: start,
        }
    } else {
        CanisterIdRange { start, end }
    };

    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(subnet_id));
    ROUTING_TABLE.with_borrow_mut(|table| {
        let known_subnet = KNOWN_SUBNET.with_borrow(|subnets| subnets.contains(&subnet));

        if known_subnet && migration {
            let canister_ranges = CanisterIdRanges::try_from(vec![canister_range]).unwrap();
            let _ = table.assign_ranges(canister_ranges, subnet);
        } else {
            let _ = table.insert(canister_range, subnet);
            KNOWN_SUBNET.with_borrow_mut(|subnets| subnets.insert(subnet));
        }
    });
});
