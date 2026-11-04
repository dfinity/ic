use super::*;
use ic_interfaces_registry::RegistryClientVersionedResult;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use std::{collections::BTreeMap, sync::Arc};

const HOLD: Duration = Duration::from_secs(30 * 60);

/// A [`FakeRegistryClient`] that also reports registry canister timestamps, which
/// the fake on its own does not.
struct StampedRegistryClient {
    inner: Arc<FakeRegistryClient>,
    canister_timestamps: BTreeMap<RegistryVersion, Time>,
}

impl RegistryClient for StampedRegistryClient {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>> {
        self.inner.get_versioned_value(key, version)
    }

    fn get_key_family(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError> {
        self.inner.get_key_family(key_prefix, version)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        self.inner.get_latest_version()
    }

    fn get_version_timestamp(&self, version: RegistryVersion) -> Option<Time> {
        self.inner.get_version_timestamp(version)
    }

    fn get_version_canister_timestamp(&self, version: RegistryVersion) -> Option<Time> {
        self.canister_timestamps.get(&version).copied()
    }
}

/// Builds a registry whose subnet membership is `memberships[i]` at version
/// `i + 1`, stamping the versions listed in `stamped_versions`.
fn new_registry_fixture(
    memberships: Vec<Vec<u64>>,
    stamped_versions: BTreeMap<u64, Time>,
) -> StampedRegistryClient {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    for (index, members) in memberships.iter().enumerate() {
        let version = RegistryVersion::from(index as u64 + 1);
        let subnet_record = SubnetRecord {
            membership: members
                .iter()
                .map(|id| node_test_id(*id).get().into_vec())
                .collect::<Vec<Vec<u8>>>(),
            ..SubnetRecord::default()
        };
        data_provider
            .add(
                &make_subnet_record_key(subnet_test_id(0)),
                version,
                Some(subnet_record),
            )
            .unwrap();
    }

    let inner = Arc::new(FakeRegistryClient::new(data_provider));
    inner.update_to_latest_version();

    StampedRegistryClient {
        inner,
        canister_timestamps: stamped_versions
            .into_iter()
            .map(|(version, time)| (RegistryVersion::from(version), time))
            .collect::<BTreeMap<RegistryVersion, Time>>(),
    }
}

fn time(secs: u64) -> Time {
    Time::from_secs_since_unix_epoch(secs).unwrap()
}

#[test]
fn test_version_without_membership_change_is_adoptable_immediately() {
    // Step 1: Prepare the world. Version 2 changes something other than the
    // membership, and is stamped as having just been applied.
    let registry = new_registry_fixture(
        vec![vec![1, 2, 3], vec![1, 2, 3]],
        BTreeMap::from([(2, time(1_000))]),
    );

    // Step 2: Run the code under test.
    let result = highest_adoptable_version(
        &registry,
        subnet_test_id(0),
        RegistryVersion::from(1),
        RegistryVersion::from(2),
        time(1_000),
        HOLD,
    );

    // Step 3: Verify results. Nothing is being held, so the hold does not apply.
    assert_eq!(result.unwrap(), RegistryVersion::from(2));
}

#[test]
fn test_fresh_membership_change_is_held_back() {
    // Step 1: Prepare the world. Version 2 adds a node and was applied just now.
    let registry = new_registry_fixture(
        vec![vec![1, 2, 3], vec![1, 2, 3, 4]],
        BTreeMap::from([(2, time(1_000))]),
    );

    // Step 2: Run the code under test.
    let result = highest_adoptable_version(
        &registry,
        subnet_test_id(0),
        RegistryVersion::from(1),
        RegistryVersion::from(2),
        time(1_000) + HOLD.saturating_sub(Duration::from_secs(1)),
        HOLD,
    );

    // Step 3: Verify results. The membership stays where it was.
    assert_eq!(result.unwrap(), RegistryVersion::from(1));
}

#[test]
fn test_membership_change_is_adopted_once_the_hold_expires() {
    // Step 1: Prepare the world. Same as above, but the block is built later.
    let registry = new_registry_fixture(
        vec![vec![1, 2, 3], vec![1, 2, 3, 4]],
        BTreeMap::from([(2, time(1_000))]),
    );

    // Step 2: Run the code under test.
    let result = highest_adoptable_version(
        &registry,
        subnet_test_id(0),
        RegistryVersion::from(1),
        RegistryVersion::from(2),
        time(1_000) + HOLD,
        HOLD,
    );

    // Step 3: Verify results. The deadline is inclusive.
    assert_eq!(result.unwrap(), RegistryVersion::from(2));
}

#[test]
fn test_later_version_is_held_together_with_the_membership_change_below_it() {
    // Step 1: Prepare the world. Version 2 adds a node and is fresh; version 3
    // changes something unrelated. Registry versions form a single sequence, so
    // version 3 cannot be adopted without also adopting version 2.
    //
    // Note the stamps are non-decreasing, as the registry canister guarantees.
    // That is what lets the rule judge a candidate by its own stamp alone.
    let registry = new_registry_fixture(
        vec![vec![1, 2, 3], vec![1, 2, 3, 4], vec![1, 2, 3, 4]],
        BTreeMap::from([(2, time(1_000)), (3, time(1_000))]),
    );

    // Step 2: Run the code under test.
    let result = highest_adoptable_version(
        &registry,
        subnet_test_id(0),
        RegistryVersion::from(1),
        RegistryVersion::from(3),
        time(1_000) + HOLD.saturating_sub(Duration::from_secs(1)),
        HOLD,
    );

    // Step 3: Verify results.
    assert_eq!(result.unwrap(), RegistryVersion::from(1));
}

#[test]
fn test_unstamped_membership_change_is_treated_as_long_past() {
    // Step 1: Prepare the world. Version 2 adds a node but carries no registry
    // canister timestamp, as versions written before this mechanism do. Waiting on
    // it would mean waiting on a time nodes disagree about.
    let registry = new_registry_fixture(vec![vec![1, 2, 3], vec![1, 2, 3, 4]], BTreeMap::new());

    // Step 2: Run the code under test.
    let result = highest_adoptable_version(
        &registry,
        subnet_test_id(0),
        RegistryVersion::from(1),
        RegistryVersion::from(2),
        time(1_000),
        HOLD,
    );

    // Step 3: Verify results.
    assert_eq!(result.unwrap(), RegistryVersion::from(2));
}

#[test]
fn test_removals_are_not_held_back() {
    // Step 1: Prepare the world. Version 2 only removes a node, so there is nobody
    // waiting to sync state and no reason to wait.
    let registry = new_registry_fixture(
        vec![vec![1, 2, 3, 4], vec![1, 2, 3]],
        BTreeMap::from([(2, time(1_000))]),
    );

    // Step 2: Run the code under test.
    let result = highest_adoptable_version(
        &registry,
        subnet_test_id(0),
        RegistryVersion::from(1),
        RegistryVersion::from(2),
        time(1_000),
        HOLD,
    );

    // Step 3: Verify results. Nobody has to sync, so there is nothing to wait for.
    assert_eq!(result.unwrap(), RegistryVersion::from(2));
}

#[test]
fn test_swap_is_held_back_because_it_adds_a_node() {
    // Step 1: Prepare the world. Version 2 swaps node 4 out for node 5, which is
    // the case the hold exists for: the outgoing node must keep carrying consensus
    // until the incoming one has synced.
    let registry = new_registry_fixture(
        vec![vec![1, 2, 3, 4], vec![1, 2, 3, 5]],
        BTreeMap::from([(2, time(1_000))]),
    );

    // Step 2: Run the code under test.
    let result = highest_adoptable_version(
        &registry,
        subnet_test_id(0),
        RegistryVersion::from(1),
        RegistryVersion::from(2),
        time(1_000),
        HOLD,
    );

    // Step 3: Verify results.
    assert_eq!(result.unwrap(), RegistryVersion::from(1));
}
