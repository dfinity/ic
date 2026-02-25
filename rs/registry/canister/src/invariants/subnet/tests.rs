use super::*;

use crate::invariants::common::RegistrySnapshot;
use ic_base_types::SubnetId;
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    subnet::v1::{
        CanisterCyclesCostSchedule, SubnetFeatures, SubnetListRecord, SubnetRecord, SubnetType,
    },
};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};

#[test]
fn only_application_subnets_can_be_free_cycles_cost_schedule() {
    let system_subnet_id = subnet_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let (mut snapshot, mut test_subnet_record) =
        setup_minimal_registry_snapshot_for_check_subnet_invariants(
            system_subnet_id,
            test_subnet_id,
            1,
            false,
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
fn only_sev_enabled_subnets_consist_of_sev_enabled_nodes() {
    let system_subnet_id = subnet_test_id(1);
    let test_subnet_id = subnet_test_id(2);
    let test_node_id = node_test_id(103);

    // get a snapshot without chip IDs
    let (mut snapshot, mut test_subnet_record) =
        setup_minimal_registry_snapshot_for_check_subnet_invariants(
            system_subnet_id,
            test_subnet_id,
            4,
            false,
        );

    // a non SEV-enabled subnet only with nodes without chip ID is compliant
    check_subnet_invariants(&snapshot).unwrap();

    // a non SEV-enabled subnet with some nodes with and some without chip IDs is compliant
    let test_node_record = NodeRecord {
        chip_id: Some("a chip id".into()),
        ..Default::default()
    };
    snapshot.insert(
        make_node_record_key(test_node_id).into_bytes(),
        test_node_record.encode_to_vec(),
    );
    check_subnet_invariants(&snapshot).unwrap();

    // an SEV-enabled subnet only with nodes without chip ID is NOT compliant
    test_subnet_record.features = Some(SubnetFeatures {
        sev_enabled: Some(true),
        ..Default::default()
    });
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    let test_node_record = NodeRecord {
        chip_id: None,
        ..Default::default()
    };
    snapshot.insert(
        make_node_record_key(test_node_id).into_bytes(),
        test_node_record.encode_to_vec(),
    );
    assert_non_compliant_record(
        &snapshot,
        "subnet fbysm-3acaa-aaaaa-aaaap-yai is sev-enabled but at least one of its nodes is not",
    );

    // get a snapshot with chip IDs
    let (mut snapshot, mut test_subnet_record) =
        setup_minimal_registry_snapshot_for_check_subnet_invariants(
            system_subnet_id,
            test_subnet_id,
            4,
            true,
        );

    // a non SEV-enabled subnet only with nodes without chip ID is compliant
    check_subnet_invariants(&snapshot).unwrap();

    // an SEV-enabled subnet only with nodes with chip ID is compliant
    test_subnet_record.features = Some(SubnetFeatures {
        sev_enabled: Some(true),
        ..Default::default()
    });
    snapshot.insert(
        make_subnet_record_key(test_subnet_id).into_bytes(),
        test_subnet_record.encode_to_vec(),
    );
    check_subnet_invariants(&snapshot).unwrap();

    // an SEV-enabled subnet with some nodes with and some without chip ID is NOT compliant
    let test_node_record = NodeRecord {
        chip_id: None,
        ..Default::default()
    };
    snapshot.insert(
        make_node_record_key(test_node_id).into_bytes(),
        test_node_record.encode_to_vec(),
    );
    assert_non_compliant_record(
        &snapshot,
        "subnet fbysm-3acaa-aaaaa-aaaap-yai is sev-enabled but at least one of its nodes is not",
    );
}

fn setup_minimal_registry_snapshot_for_check_subnet_invariants(
    system_subnet_id: SubnetId,
    test_subnet_id: SubnetId,
    num_nodes_in_test_subnet: usize,
    with_chip_id: bool,
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
    for i in 0..num_nodes_in_test_subnet {
        let node_id = node_test_id((i + 100) as u64);
        let mut node_record = NodeRecord::default();
        if with_chip_id {
            node_record.chip_id = Some(format!("chip-id-{i}").into_bytes());
        }
        snapshot.insert(
            make_node_record_key(node_id.to_owned()).into_bytes(),
            node_record.encode_to_vec(),
        );
    }

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
    let membership = (0..num_nodes_in_test_subnet)
        .map(|i| node_test_id((i + 100) as u64).get().to_vec())
        .collect();

    let test_subnet_record = SubnetRecord {
        membership,
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
    println!("Error message: {message}");
    assert!(message.contains(error_msg));
}
