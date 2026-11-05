//! Implements `get-subnet-replica-version`: reports which replica version a
//! subnet runs.
//!
//! Most subnets name their replica version directly, in
//! `SubnetRecord.replica_version_id`, which `get-subnet` already shows. Cloud
//! Engines are different: their `replica_version_id` is typically blank, which
//! means "follow the standard engine replica version". A blank engine's version
//! then comes from the registry-wide `StandardEngineReplicaVersionRecord`,
//! which names an old and a new version, plus a `deployment_progress` between
//! 0.0 and 1.0. Each engine has an upgrade priority (see
//! `engine_upgrade_priority`), and the engine takes the new version if and only
//! if its priority is <= `deployment_progress`.
//!
//! This module works that out, following the same rule as
//! `SubnetRegistry::get_replica_version` (which is what the orchestrator uses),
//! so that no one has to do the arithmetic by hand.

use ic_protobuf::registry::{
    standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord,
    subnet::v1::{SubnetRecord as SubnetRecordPb, SubnetType},
};
use ic_registry_client_helpers::subnet::engine_upgrade_priority;
use ic_registry_keys::{make_standard_engine_replica_version_record_key, make_subnet_record_key};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_transport::Error;
use ic_types::SubnetId;
use prost::Message;
use serde::Serialize;
use std::fmt;

/// The replica version that a subnet runs, and where that version comes from.
///
/// `Display` renders it for humans; `Serialize` renders it for `--json`.
#[derive(Clone, PartialEq, Debug, Serialize)]
pub(crate) struct SubnetReplicaVersion {
    subnet_id: String,
    replica_version_id: String,
    #[serde(flatten)]
    source: ReplicaVersionSource,
}

/// Where a subnet's replica version comes from.
#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
enum ReplicaVersionSource {
    /// `SubnetRecord.replica_version_id` names the version directly.
    SubnetRecord,

    /// `SubnetRecord.replica_version_id` is blank (only allowed for Cloud
    /// Engines), so the version comes from `StandardEngineReplicaVersionRecord`.
    StandardEngineReplicaVersion {
        new_replica_version_id: String,
        old_replica_version_id: String,
        deployment_progress: f64,

        /// The engine takes `new_replica_version_id` if and only if this is <=
        /// `deployment_progress`.
        upgrade_priority: f64,
    },
}

/// Fetches the registry records that determine the replica version of
/// `subnet_id`, and works out that version.
///
/// `StandardEngineReplicaVersionRecord` is only fetched when the subnet's own
/// `replica_version_id` is blank, because only then does it matter.
pub(crate) async fn try_get_subnet_replica_version(
    registry_canister: &RegistryCanister,
    subnet_id: SubnetId,
) -> Result<SubnetReplicaVersion, String> {
    let subnet_record_key = make_subnet_record_key(subnet_id);
    let subnet_record =
        try_get_latest_registry_value::<SubnetRecordPb>(registry_canister, &subnet_record_key)
            .await?
            .ok_or_else(|| format!("There is no {subnet_record_key} key in the registry."))?;

    let standard_engine_replica_version = if subnet_record.replica_version_id.is_empty() {
        try_get_latest_registry_value::<StandardEngineReplicaVersionRecord>(
            registry_canister,
            &make_standard_engine_replica_version_record_key(),
        )
        .await?
    } else {
        None
    };

    try_resolve_subnet_replica_version(
        subnet_id,
        &subnet_record,
        standard_engine_replica_version.as_ref(),
    )
}

/// Returns the latest value under `key`, or `None` if the registry has no such
/// key.
async fn try_get_latest_registry_value<Value: Message + Default>(
    registry_canister: &RegistryCanister,
    key: &str,
) -> Result<Option<Value>, String> {
    let result = registry_canister
        .get_value_with_update(key.as_bytes().to_vec(), None)
        .await;

    let bytes = match result {
        Ok((bytes, _registry_version)) => bytes,
        Err(Error::KeyNotPresent(_)) => return Ok(None),
        Err(err) => return Err(format!("Unable to get {key} from the registry: {err:?}")),
    };

    Value::decode(&bytes[..])
        .map(Some)
        .map_err(|err| format!("Unable to decode the value of {key}: {err}"))
}

/// Works out the replica version of `subnet_id`, given its `SubnetRecord` and,
/// if the registry has one, the `StandardEngineReplicaVersionRecord`.
fn try_resolve_subnet_replica_version(
    subnet_id: SubnetId,
    subnet_record: &SubnetRecordPb,
    standard_engine_replica_version: Option<&StandardEngineReplicaVersionRecord>,
) -> Result<SubnetReplicaVersion, String> {
    // Pinned: the subnet record names the version directly.
    if !subnet_record.replica_version_id.is_empty() {
        return Ok(SubnetReplicaVersion {
            subnet_id: subnet_id.to_string(),
            replica_version_id: subnet_record.replica_version_id.clone(),
            source: ReplicaVersionSource::SubnetRecord,
        });
    }

    // Only Cloud Engines may leave replica_version_id blank.
    let subnet_type = subnet_record.subnet_type();
    if subnet_type != SubnetType::CloudEngine {
        return Err(format!(
            "Subnet {subnet_id} has a blank replica_version_id, but its subnet_type is \
             {subnet_type:?}, not CloudEngine. Only Cloud Engines may follow the standard \
             engine replica version, so the registry is inconsistent."
        ));
    }

    let Some(standard_engine_replica_version) = standard_engine_replica_version else {
        return Err(format!(
            "Subnet {subnet_id} is a Cloud Engine with a blank replica_version_id, but the \
             registry has no {} key to determine its replica version from.",
            make_standard_engine_replica_version_record_key(),
        ));
    };

    let StandardEngineReplicaVersionRecord {
        new_replica_version_id,
        old_replica_version_id,
        deployment_progress,
    } = standard_engine_replica_version.clone();

    // The same rule as SubnetRegistry::get_replica_version.
    let upgrade_priority = engine_upgrade_priority(subnet_id, &new_replica_version_id);
    let is_on_new_replica_version = upgrade_priority <= deployment_progress;
    let replica_version_id = if is_on_new_replica_version {
        new_replica_version_id.clone()
    } else {
        old_replica_version_id.clone()
    };

    Ok(SubnetReplicaVersion {
        subnet_id: subnet_id.to_string(),
        replica_version_id,
        source: ReplicaVersionSource::StandardEngineReplicaVersion {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
            upgrade_priority,
        },
    })
}

impl fmt::Display for SubnetReplicaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            subnet_id,
            replica_version_id,
            source,
        } = self;

        writeln!(
            formatter,
            "Subnet {subnet_id} runs replica version {replica_version_id}."
        )?;

        let ReplicaVersionSource::StandardEngineReplicaVersion {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
            upgrade_priority,
        } = source
        else {
            return write!(
                formatter,
                "The subnet record pins this version (replica_version_id)."
            );
        };

        let outcome = if upgrade_priority <= deployment_progress {
            "<= deployment_progress, so this engine takes the new version"
        } else {
            "> deployment_progress, so this engine stays on the old version"
        };

        writeln!(
            formatter,
            "The subnet record's replica_version_id is blank, so this Cloud Engine follows \
             the standard engine replica version:"
        )?;
        writeln!(
            formatter,
            "  new_replica_version_id: {new_replica_version_id}"
        )?;
        writeln!(
            formatter,
            "  old_replica_version_id: {old_replica_version_id}"
        )?;
        // Debug, so that e.g. 1.0 shows as "1.0", not "1".
        writeln!(
            formatter,
            "  deployment_progress:    {deployment_progress:?}"
        )?;
        write!(
            formatter,
            "  upgrade_priority:       {upgrade_priority:.6} ({outcome})"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::PrincipalId;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    /// Together with NEW_REPLICA_VERSION_ID, gives an upgrade priority of about
    /// 0.211377. This was independently computed in the helpers crate's
    /// `engine_priority_matches_hand_computed_value` test.
    const ENGINE_SUBNET_ID: &str = "y6zu2-uqdaa-aaaaa-aaaap-yai";
    const NEW_REPLICA_VERSION_ID: &str = "eb3ab997954f2a91db8a42f84132cf37078d481c";
    const OLD_REPLICA_VERSION_ID: &str = "79c01052b5f7f49d3cf53d04d696cb2893294cd3";
    const ENGINE_UPGRADE_PRIORITY: f64 = 0.211_377;

    fn engine_subnet_id() -> SubnetId {
        SubnetId::from(PrincipalId::from_str(ENGINE_SUBNET_ID).unwrap())
    }

    fn new_subnet_record(subnet_type: SubnetType, replica_version_id: &str) -> SubnetRecordPb {
        SubnetRecordPb {
            subnet_type: i32::from(subnet_type),
            replica_version_id: replica_version_id.to_string(),
            ..Default::default()
        }
    }

    fn new_standard_engine_replica_version(
        deployment_progress: f64,
    ) -> StandardEngineReplicaVersionRecord {
        StandardEngineReplicaVersionRecord {
            new_replica_version_id: NEW_REPLICA_VERSION_ID.to_string(),
            old_replica_version_id: OLD_REPLICA_VERSION_ID.to_string(),
            deployment_progress,
        }
    }

    /// Resolves the engine at ENGINE_SUBNET_ID, which has a blank
    /// replica_version_id, at the given `deployment_progress`.
    fn resolve_blank_engine_replica_version_or_panic(
        deployment_progress: f64,
    ) -> SubnetReplicaVersion {
        try_resolve_subnet_replica_version(
            engine_subnet_id(),
            &new_subnet_record(SubnetType::CloudEngine, /* replica_version_id = */ ""),
            Some(&new_standard_engine_replica_version(deployment_progress)),
        )
        .unwrap()
    }

    #[test]
    fn test_pinned_subnet_reports_its_own_replica_version() {
        // Step 1: Prepare the world. The standard engine replica version must be
        // ignored, because the subnet pins its own version, even as an engine.
        let subnet_record = new_subnet_record(SubnetType::CloudEngine, "pinned_version");
        let standard_engine_replica_version = new_standard_engine_replica_version(1.0);

        // Step 2: Run the code under test.
        let result = try_resolve_subnet_replica_version(
            engine_subnet_id(),
            &subnet_record,
            Some(&standard_engine_replica_version),
        );

        // Step 3: Verify result(s).
        assert_eq!(
            result,
            Ok(SubnetReplicaVersion {
                subnet_id: ENGINE_SUBNET_ID.to_string(),
                replica_version_id: "pinned_version".to_string(),
                source: ReplicaVersionSource::SubnetRecord,
            })
        );
    }

    #[test]
    fn test_blank_engine_follows_deployment_progress() {
        // Step 1: Prepare the world. The engine's priority sits between these
        // two levels of deployment progress.
        let progress_just_below_priority = ENGINE_UPGRADE_PRIORITY - 0.01;
        let progress_just_above_priority = ENGINE_UPGRADE_PRIORITY + 0.01;

        // Step 2: Run the code under test, at various levels of deployment
        // progress.
        let observed_replica_version_ids = [
            0.0,
            progress_just_below_priority,
            progress_just_above_priority,
            1.0,
        ]
        .map(|deployment_progress| {
            resolve_blank_engine_replica_version_or_panic(deployment_progress).replica_version_id
        });

        // Step 3: Verify result(s). The engine switches to the new version
        // once deployment progress reaches its priority, and not before.
        assert_eq!(
            observed_replica_version_ids,
            [
                OLD_REPLICA_VERSION_ID,
                OLD_REPLICA_VERSION_ID,
                NEW_REPLICA_VERSION_ID,
                NEW_REPLICA_VERSION_ID,
            ]
            .map(String::from)
        );
    }

    #[test]
    fn test_blank_engine_reports_how_its_version_was_chosen() {
        // Step 1: Prepare the world. (Nothing to do.)

        // Step 2: Run the code under test.
        let subnet_replica_version = resolve_blank_engine_replica_version_or_panic(0.5);

        // Step 3: Verify result(s).

        // Step 3.1: The inputs to the decision are reported alongside it.
        let ReplicaVersionSource::StandardEngineReplicaVersion {
            new_replica_version_id,
            old_replica_version_id,
            deployment_progress,
            upgrade_priority,
        } = subnet_replica_version.source.clone()
        else {
            panic!("{subnet_replica_version:#?}");
        };
        assert_eq!(new_replica_version_id, NEW_REPLICA_VERSION_ID);
        assert_eq!(old_replica_version_id, OLD_REPLICA_VERSION_ID);
        assert_eq!(deployment_progress, 0.5);
        assert!(
            (upgrade_priority - ENGINE_UPGRADE_PRIORITY).abs() < 1e-6,
            "{upgrade_priority}"
        );

        // Step 3.2: JSON output tags where the version came from, next to the
        // version itself.
        let json = serde_json::to_value(&subnet_replica_version).unwrap();
        assert_eq!(json["subnet_id"], ENGINE_SUBNET_ID);
        assert_eq!(json["replica_version_id"], NEW_REPLICA_VERSION_ID);
        assert_eq!(json["source"], "standard_engine_replica_version");
        assert_eq!(json["deployment_progress"], 0.5);

        // Step 3.3: Human-readable output leads with the answer.
        let text = subnet_replica_version.to_string();
        assert!(
            text.starts_with(&format!(
                "Subnet {ENGINE_SUBNET_ID} runs replica version {NEW_REPLICA_VERSION_ID}."
            )),
            "{text}"
        );
        assert!(text.contains("takes the new version"), "{text}");
    }

    #[test]
    fn test_blank_non_engine_is_an_error() {
        // Step 1: Prepare the world.
        let subnet_record = new_subnet_record(SubnetType::Application, "");

        // Step 2: Run the code under test.
        let result = try_resolve_subnet_replica_version(
            engine_subnet_id(),
            &subnet_record,
            Some(&new_standard_engine_replica_version(1.0)),
        );

        // Step 3: Verify result(s).
        let err = result.unwrap_err();
        assert!(err.contains(ENGINE_SUBNET_ID), "{err}");
        assert!(err.contains("Application"), "{err}");
        assert!(err.contains("not CloudEngine"), "{err}");
    }

    #[test]
    fn test_blank_engine_without_standard_engine_replica_version_is_an_error() {
        // Step 1: Prepare the world.
        let subnet_record = new_subnet_record(SubnetType::CloudEngine, "");

        // Step 2: Run the code under test.
        let result = try_resolve_subnet_replica_version(
            engine_subnet_id(),
            &subnet_record,
            /* standard_engine_replica_version = */ None,
        );

        // Step 3: Verify result(s).
        let err = result.unwrap_err();
        assert!(err.contains(ENGINE_SUBNET_ID), "{err}");
        assert!(err.contains("standard_engine_replica_version"), "{err}");
    }
}
