use super::*;
use crate::SystemStateAccessorDirect;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_routing_table::CanisterIdRange;
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, state::SystemStateBuilder,
    types::ids::subnet_test_id,
};
use maplit::btreemap;
use std::convert::TryInto;

#[test]
fn large_methods_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 10;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 100;
    let callback = WasmClosure::new(0, 0);
    let max_size_inter_subnet = NumBytes::from(10);
    RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_inter_subnet,
        1,
    )
    .unwrap_err();
}

#[test]
fn large_callee_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 100;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_inter_subnet = NumBytes::from(10);
    RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_inter_subnet,
        1,
    )
    .unwrap_err();
}

#[test]
fn payloads_larger_than_intra_limit_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 1;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_inter_subnet = NumBytes::from(10);
    let mut req_in_prep = RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_inter_subnet,
        1,
    )
    .unwrap();
    req_in_prep
        .extend_method_payload(0, 100, &heap)
        .unwrap_err();
}

#[test]
fn payloads_larger_than_inter_limit_rejected() {
    let (sender_subnet, sender_subnet_type, sender, dest, routing_table, subnet_records) = {
        let subnet_type = SubnetType::Application;
        let sender_subnet = subnet_test_id(1);
        let sender_subnet_canister_id_range = CanisterIdRange {
            start: CanisterId::from(0),
            end: CanisterId::from(0xffffffff),
        };
        let sender = CanisterId::from(0x1);
        assert!(sender_subnet_canister_id_range.start <= sender);
        assert!(sender <= sender_subnet_canister_id_range.end);

        let foreign_subnet_id = subnet_test_id(2);
        let foreign_subnet_canister_id_range = CanisterIdRange {
            start: CanisterId::from(0x100000000),
            end: CanisterId::from(0x1ffffffff),
        };
        let dest = CanisterId::from(0x100000001);
        assert!(foreign_subnet_canister_id_range.start <= dest);
        assert!(dest <= foreign_subnet_canister_id_range.end);

        let routing_table = Arc::new(RoutingTable::new(btreemap! {
            foreign_subnet_canister_id_range => foreign_subnet_id,
            sender_subnet_canister_id_range => sender_subnet,
        }));

        let subnet_records = btreemap! {
            sender_subnet => subnet_type,
            foreign_subnet_id => subnet_type,
        };

        (
            sender_subnet,
            subnet_type,
            sender,
            dest,
            routing_table,
            subnet_records,
        )
    };

    let callee_source = 0;
    let callee_size = dest.get().as_slice().len().try_into().unwrap();
    let mut heap = dest.get().as_slice().to_vec();
    heap.append(&mut vec![0; 1024]);
    let method_name_source = 0;
    let method_name_len = 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_inter_subnet = NumBytes::from(10);
    let mut req_in_prep = RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_inter_subnet,
        10,
    )
    .unwrap();
    req_in_prep.extend_method_payload(0, 50, &heap).unwrap();
    let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());

    into_request(
        routing_table,
        &subnet_records,
        req_in_prep,
        CallContextId::from(1),
        sender_subnet,
        sender_subnet_type,
        &SystemStateAccessorDirect::new(
            SystemStateBuilder::default().build(),
            cycles_account_manager,
        ),
        &no_op_logger(),
    )
    .unwrap_err();
}

#[test]
fn application_subnet_cannot_send_cycles_to_verified_subnet() {
    let sender_subnet = subnet_test_id(1);
    let sender_subnet_type = SubnetType::Application;
    let sender_subnet_canister_id_range = CanisterIdRange {
        start: CanisterId::from(0),
        end: CanisterId::from(0xffffffff),
    };
    let sender = CanisterId::from(0x1);
    assert!(sender_subnet_canister_id_range.start <= sender);
    assert!(sender <= sender_subnet_canister_id_range.end);

    let dest_subnet = subnet_test_id(2);
    let dest_subnet_type = SubnetType::VerifiedApplication;
    let dest_subnet_canister_id_range = CanisterIdRange {
        start: CanisterId::from(0x100000000),
        end: CanisterId::from(0x1ffffffff),
    };
    let dest = CanisterId::from(0x100000001);
    assert!(dest_subnet_canister_id_range.start <= dest);
    assert!(dest <= dest_subnet_canister_id_range.end);

    let routing_table = Arc::new(RoutingTable::new(btreemap! {
        dest_subnet_canister_id_range => dest_subnet,
        sender_subnet_canister_id_range => sender_subnet,
    }));

    let subnet_records = btreemap! {
        sender_subnet => sender_subnet_type,
        dest_subnet => dest_subnet_type,
    };

    let callee_source = 0;
    let callee_size = dest.get().as_slice().len().try_into().unwrap();
    let mut heap = dest.get().as_slice().to_vec();
    heap.append(&mut vec![0; 1024]);
    let method_name_source = 0;
    let method_name_len = 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_inter_subnet = NumBytes::from(1024);
    let mut req_in_prep = RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_inter_subnet,
        10,
    )
    .unwrap();
    req_in_prep.extend_method_payload(0, 50, &heap).unwrap();
    req_in_prep.add_cycles(Cycles::from(100));

    let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
    into_request(
        routing_table,
        &subnet_records,
        req_in_prep,
        CallContextId::from(1),
        sender_subnet,
        sender_subnet_type,
        &SystemStateAccessorDirect::new(
            SystemStateBuilder::default().build(),
            cycles_account_manager,
        ),
        &no_op_logger(),
    )
    .unwrap_err();
}
