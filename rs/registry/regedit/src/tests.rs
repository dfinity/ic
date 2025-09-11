#![cfg(test)]
use crate::{
    args::{Command, RegistrySpec, SourceSpec, VersionSpec, universal_projection},
    diff::DELETED_MARKER,
    execute_command, normalization,
    snapshot::SPECIAL_FIELD_PREFIX,
};
use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::{NodeConfiguration, NodeIndex},
    prep_state_directory::IcPrepStateDir,
    subnet_configuration::{SubnetConfig, SubnetRunningState},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::ReplicaVersion;
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};
use tempfile::TempDir;

const NODE_INDEX: NodeIndex = 100;
const SUBNET_ID: u64 = 0;

#[test]
fn adding_deleting_values_shows_up_in_diff() {
    let (_guard, ic_prep_dir) = run_ic_prep();
    let registry_spec = local_store_latest_snapshot(ic_prep_dir.registry_local_store_path());
    let projection = universal_projection();
    let cmd = Command::Snapshot {
        registry_spec: registry_spec.clone(),
        projection: projection.clone(),
    };

    let original_snapshot = execute_command(cmd).unwrap();
    let mut snapshot = original_snapshot;

    let obj = snapshot.as_object_mut().unwrap();

    // remove last key (arbitrary choice)
    let removed_key = obj.keys().next_back().unwrap().clone();
    assert!(obj.remove(&removed_key).is_some());

    let arbitrary_bytes: Vec<u8> = (b'A'..b'z').collect();

    let new_key = "a_key_that_does_not_exist".to_string();
    let mut arbitrary_obj = "(binary-data)".to_string();
    arbitrary_bytes
        .iter()
        .for_each(|x| arbitrary_obj.push_str(&format!("{x:02x}")));
    let arbitrary_value = serde_json::to_value(&arbitrary_obj).unwrap();
    obj.insert(new_key.clone(), arbitrary_value);

    let digest = ic_crypto_sha2::Sha256::hash(arbitrary_bytes.as_slice());
    let digest_hex = digest
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join("");
    let expected_arbitrary_value =
        serde_json::to_value(format!("(binary-data|sha256){digest_hex}")).unwrap();

    let cmd = Command::ShowDiff {
        registry_spec: registry_spec.clone(),
        snapshot: snapshot.clone(),
    };

    let out = execute_command(cmd).unwrap();
    let diff = out.as_object().unwrap();

    let diff_keys: Vec<_> = diff.keys().cloned().collect();

    let expected_keys_in_diff: HashSet<_> = vec![new_key.clone(), removed_key.clone()]
        .into_iter()
        .collect();
    let actual_keys: HashSet<_> = filter_special_keys(diff_keys).into_iter().collect();

    let deleted_marker = serde_json::to_value(DELETED_MARKER).unwrap();
    assert_eq!(actual_keys, expected_keys_in_diff);
    assert_eq!(diff.get(&new_key).unwrap(), &expected_arbitrary_value);
    assert_eq!(diff.get(&removed_key).unwrap(), &deleted_marker);

    execute_command(Command::ApplyUpdate {
        local_store_path: ic_prep_dir.registry_local_store_path(),
        snapshot: snapshot.clone(),
        amend: false,
    })
    .unwrap();

    let (mut expected_snapshot, _) = normalization::normalize(snapshot);
    expected_snapshot
        .0
        .as_object_mut()
        .unwrap()
        .insert("__version".into(), serde_json::to_value(2).unwrap());
    expected_snapshot
        .0
        .as_object_mut()
        .unwrap()
        .insert(new_key, expected_arbitrary_value);

    let cmd = Command::Snapshot {
        registry_spec,
        projection,
    };
    let final_snapshot = execute_command(cmd).unwrap();

    assert_eq!(expected_snapshot.0, final_snapshot);
}

pub fn local_store_latest_snapshot(path: PathBuf) -> RegistrySpec {
    let source = SourceSpec::LocalStore(path);
    let version = VersionSpec::RelativeToLatest(0);

    RegistrySpec { version, source }
}

pub fn filter_special_keys(keys: Vec<String>) -> Vec<String> {
    keys.iter()
        .filter(|k| !k.starts_with(SPECIAL_FIELD_PREFIX))
        .cloned()
        .collect()
}

pub fn run_ic_prep() -> (TempDir, IcPrepStateDir) {
    let mut subnet_nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();
    subnet_nodes.insert(
        NODE_INDEX,
        NodeConfiguration {
            xnet_api: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            public_api: SocketAddr::from_str("0.0.0.0:8080").unwrap(),
            node_operator_principal_id: None,
            secret_key_store: None,
            domain: None,
            node_reward_type: None,
        },
    );

    let mut topology_config = TopologyConfig::default();
    topology_config.insert_subnet(
        SUBNET_ID,
        SubnetConfig::new(
            SUBNET_ID,
            subnet_nodes,
            ReplicaVersion::default(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            SubnetType::System,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
            vec![],
            SubnetRunningState::Active,
            None,
        ),
    );

    let temp_dir = tempfile::tempdir().unwrap();
    let ic_config = IcConfig::new(
        /* target_dir= */ temp_dir.path(),
        topology_config,
        ReplicaVersion::default(),
        /* generate_subnet_records= */ true, // see note above
        /* nns_subnet_index= */ Some(0),
        /* release_package_url= */ None,
        /* release_package_sha256_hex */ None,
        /* guest_launch_measurements */ None,
        Some(ProvisionalWhitelist::All),
        None,
        None,
        /* ssh_readonly_access_to_unassigned_nodes */ vec![],
    );
    ic_config.initialize().unwrap();
    let path: PathBuf = temp_dir.path().into();
    (temp_dir, IcPrepStateDir::new(path))
}
