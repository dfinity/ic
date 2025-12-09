use std::collections::HashSet;

use super::*;
use ic_registry_client_helpers::subnet::SubnetListRegistry;
use ic_test_utilities_registry::get_mainnet_delta_00_6d_c1;
use ic_types::PrincipalId;

const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

#[test]
fn can_read_mainnet_data() {
    let (tmpdir, _store) = get_mainnet_delta_00_6d_c1();
    let local_registry = LocalRegistry::new(tmpdir.path(), DEFAULT_QUERY_TIMEOUT)
        .expect("Could not instantiate local registry with mainnet state.");

    let latest_version = local_registry.get_latest_version();
    assert_eq!(latest_version.get(), 0x6dc1);

    let root_subnet_id = local_registry
        .get_root_subnet_id(latest_version)
        .expect("Could not fetch root subnet id.")
        .unwrap();
    assert_eq!(root_subnet_id, expected_root_subnet_id());

    let subnet_ids = local_registry
        .get_subnet_ids(latest_version)
        .expect("Could not fetch subnet ids")
        .unwrap();
    assert_eq!(subnet_ids.len(), 29);

    let root_subnet_node_ids = local_registry
        .get_node_ids_on_subnet(root_subnet_id, latest_version)
        .expect("Could not retrieve root subnet node ids")
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(root_subnet_node_ids.len(), 37);
}

fn expected_root_subnet_id() -> SubnetId {
    SubnetId::new(
        PrincipalId::from_str(
            "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe",
        )
        .unwrap(),
    )
}
