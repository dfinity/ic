use super::*;

use crate::invariants::common::RegistrySnapshot;
use ic_base_types::SubnetId;
use ic_protobuf::{
    registry::{
        node::v1::NodeRecord,
        subnet::v1::{CanisterCyclesCostSchedule, SubnetListRecord, SubnetRecord, SubnetType},
    },
    types::v1::PrincipalId as PrincipalIdPb,
};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id, user_test_id};

#[test]
fn only_application_subnets_can_be_free_cycles_cost_schedule() {
    let system_subnet_id = subnet_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let (mut snapshot, mut test_subnet_record) =
        setup_minimal_registry_snapshot_for_check_subnet_invariants(
            system_subnet_id,
            test_subnet_id,
        );

    // Trivial case. (Never forget the trivial case, because this is an edge
    // case, and edge cases is where many mistakes are made.)
    check_subnet_invariants(&snapshot).unwrap();

    // Happy case: a compliant `SubnetRecord`.
    test_subnet_record.subnet_type = i32::from(SubnetType::Application);
    test_subnet_record.canister_cycles_cost_schedule = i32::from(CanisterCyclesCostSchedule::Free);
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    check_subnet_invariants(&snapshot).unwrap();

    // System or verified application subnets cannot be on "free" cycles cost schedule.
    test_subnet_record.subnet_type = i32::from(SubnetType::System);
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    assert_non_compliant_record(
        &snapshot,
        "is not an application subnet but has a free cycles cost schedule",
    );

    test_subnet_record.subnet_type = i32::from(SubnetType::VerifiedApplication);
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    assert_non_compliant_record(
        &snapshot,
        "is not an application subnet but has a free cycles cost schedule",
    );
}

#[test]
fn only_rented_subnets_can_have_subnet_admins() {
    let system_subnet_id = subnet_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let (mut snapshot, mut test_subnet_record) =
        setup_minimal_registry_snapshot_for_check_subnet_invariants(
            system_subnet_id,
            test_subnet_id,
        );

    // Trivial case. (Never forget the trivial case, because this is an edge
    // case, and edge cases is where many mistakes are made.)
    check_subnet_invariants(&snapshot).unwrap();

    // Happy case: a compliant `SubnetRecord`.
    test_subnet_record.subnet_type = i32::from(SubnetType::Application);
    test_subnet_record.canister_cycles_cost_schedule = i32::from(CanisterCyclesCostSchedule::Free);
    test_subnet_record.subnet_admins = vec![PrincipalIdPb::from(user_test_id(1).get())];
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    check_subnet_invariants(&snapshot).unwrap();

    // System or verified application subnets cannot have non-empty list of subnet admins.
    test_subnet_record.subnet_type = i32::from(SubnetType::System);
    test_subnet_record.canister_cycles_cost_schedule =
        i32::from(CanisterCyclesCostSchedule::Normal);
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    assert_non_compliant_record(
        &snapshot,
        "is not a rented subnet but has a non-empty subnet admins list",
    );

    test_subnet_record.subnet_type = i32::from(SubnetType::VerifiedApplication);
    test_subnet_record.canister_cycles_cost_schedule =
        i32::from(CanisterCyclesCostSchedule::Normal);
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    assert_non_compliant_record(
        &snapshot,
        "is not a rented subnet but has a non-empty subnet admins list",
    );
}

fn setup_minimal_registry_snapshot_for_check_subnet_invariants(
    system_subnet_id: SubnetId,
    test_subnet_id: SubnetId,
) -> (RegistrySnapshot, SubnetRecord) {
    let mut snapshot = RegistrySnapshot::new();

    let system_node_id = node_test_id(1);
    snapshot.insert(
        make_node_record_key(system_node_id.to_owned()).into_bytes(),
        NodeRecord::default().encode_to_vec(),
    );

    let subnet_list_record = SubnetListRecord {
        subnets: vec![system_subnet_id.get().into_vec()],
    };
    snapshot.insert(
        make_subnet_list_record_key().into_bytes(),
        subnet_list_record.encode_to_vec(),
    );
    let subnet_record = SubnetRecord {
        membership: vec![system_node_id.get().into_vec()],
        subnet_type: i32::from(SubnetType::System),
        ..Default::default()
    };
    snapshot.insert(
        make_subnet_record_key(system_subnet_id).into_bytes(),
        subnet_record.encode_to_vec(),
    );

    // Add a test subnet in the subnet list.
    let test_node_id = node_test_id(100);
    snapshot.insert(
        make_node_record_key(test_node_id.to_owned()).into_bytes(),
        NodeRecord::default().encode_to_vec(),
    );
    let subnet_list_record = SubnetListRecord {
        subnets: vec![
            system_subnet_id.get().into_vec(),
            test_subnet_id.get().into_vec(),
        ],
    };
    snapshot.insert(
        make_subnet_list_record_key().into_bytes(),
        subnet_list_record.encode_to_vec(),
    );
    let test_subnet_record = SubnetRecord {
        membership: vec![test_node_id.get().to_vec()],
        ..Default::default()
    };
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );

    (snapshot, test_subnet_record)
}

fn assert_non_compliant_record(snapshot: &RegistrySnapshot, error_msg: &str) {
    let Err(err) = check_subnet_invariants(snapshot) else {
        panic!("Expected Err, but got Ok!");
    };
    let message = err.msg.to_lowercase();
    assert!(message.contains(error_msg));
}
