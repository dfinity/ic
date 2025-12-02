use super::*;

use ic_base_types::{NodeId, PrincipalId};
use ic_protobuf::registry::node::v1::{ConnectionEndpoint, NodeRecord};
use ic_registry_keys::make_node_record_key;
use prost::Message;

#[test]
fn test_ssh_node_state_write_access_not_too_long() {
    let mut snapshot = RegistrySnapshot::new();

    // Trivial case. (Never forget the trivial case, because this is an edge
    // case, and edge cases is where many mistakes are made.)
    check_node_record_invariants(&snapshot).unwrap();

    let http_1 = ConnectionEndpoint {
        port: 8888,
        ..Default::default()
    };
    let http_2 = ConnectionEndpoint {
        port: 666,
        ..http_1.clone()
    };

    // Happy case: a compliant NodeRecord.
    snapshot.insert(
        make_node_record_key(NodeId::from(PrincipalId::new_user_test_id(42))).into_bytes(),
        NodeRecord {
            // This is ok
            ssh_node_state_write_access: vec![],
            http: Some(http_1.clone()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    check_node_record_invariants(&snapshot).unwrap();

    // Sad case: a non-compliant NodeRecord.
    snapshot.insert(
        make_node_record_key(NodeId::from(PrincipalId::new_user_test_id(43))).into_bytes(),
        NodeRecord {
            // This is ok
            ssh_node_state_write_access: vec!["too many".to_string(); 51],
            http: Some(http_2.clone()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let Err(err) = check_node_record_invariants(&snapshot) else {
        panic!("Expected Err, but got Ok!");
    };
    let message = err.msg.to_lowercase();
    for key_word in ["too many", "ssh_node_state_write_access", "666"] {
        assert!(message.contains(key_word), "{err:?}");
    }
}
