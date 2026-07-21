use crate::deserialize_registry_value;
use ic_crypto_sha2::{DomainSeparationContext, Sha256};
use ic_interfaces_registry::{
    RegistryClient, RegistryClientResult, RegistryClientVersionedResult, RegistryVersionedRecord,
};
use ic_limits::{INITIAL_NOTARY_DELAY, UNIT_DELAY_APP_SUBNET};
use ic_protobuf::{
    registry::{
        node::v1::NodeRecord,
        replica_version::v1::ReplicaVersionRecord,
        standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord,
        subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord, SubnetType},
    },
    types::v1::SubnetId as SubnetIdProto,
};
use ic_registry_keys::{
    DEFAULT_INITIAL_DKG_SUBNET_ID_KEY, ROOT_SUBNET_ID_KEY, make_catch_up_package_contents_key,
    make_node_record_key, make_replica_version_key,
    make_standard_engine_replica_version_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_subnet_features::{ChainKeyConfig, SubnetFeatures};
use ic_types::{
    Height, NodeId, PrincipalId, PrincipalIdBlobParseError, RegistryVersion, ReplicaVersion,
    SubnetId,
    registry::RegistryClientError::{self, DecodeError},
};
use std::{convert::TryFrom, time::Duration};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct NotarizationDelaySettings {
    pub unit_delay: Duration,
    pub initial_notary_delay: Duration,
}

impl Default for NotarizationDelaySettings {
    fn default() -> Self {
        Self {
            initial_notary_delay: INITIAL_NOTARY_DELAY,
            unit_delay: UNIT_DELAY_APP_SUBNET,
        }
    }
}

pub struct IngressMessageSettings {
    /// Maximum number of bytes per message. This is a hard cap, which means
    /// ingress messages greater than the limit will be dropped.
    pub max_ingress_bytes_per_message: usize,
    /// Maximum number of ingress bytes per block. This is a hard cap, which means
    /// blocks will never have more than this number of ingress bytes.
    pub max_ingress_bytes_per_block: usize,
    /// Maximum number of messages per block. This is a hard cap, which means
    /// blocks will never have more than this number of messages.
    pub max_ingress_messages_per_block: usize,
}

/// A helper trait that wraps a [RegistryClient] and provides utility methods for
/// querying subnet information.
pub trait SubnetRegistry {
    fn get_subnet_record(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetRecord>;

    /// Returns `true` if the `subnet_id` is deleted at `version`.
    /// I.e., there used to be a `subnet_record` for this ID, but
    /// it was explicitly deleted.
    ///
    /// Returns `false` if the subnet still exists or has never existed.
    fn is_subnet_deleted(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<bool, RegistryClientError>;

    fn get_root_subnet_id(&self, version: RegistryVersion) -> RegistryClientResult<SubnetId>;

    /// Returns the [`SubnetId`] of the subnet to which `SetupInitialDKG`
    /// management canister calls are routed by default (i.e., when the request
    /// does not specify a subnet id explicitly), or `None` if no default has
    /// been set in the registry.
    fn get_default_initial_dkg_subnet_id(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetId>;

    fn get_node_ids_on_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<NodeId>>;

    fn get_subnet_size(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<usize>;

    /// Returns ingress message settings.
    fn get_ingress_message_settings(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<IngressMessageSettings>;

    /// Returns SubnetFeatures
    fn get_features(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetFeatures>;

    /// Returns chain key config
    fn get_chain_key_config(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ChainKeyConfig>;

    /// Returns notarization delay settings:
    /// - the unit delay for blockmaker;
    /// - the initial delay for notary, to give time to rank-0 block
    ///   propagation.
    fn get_notarization_delay_settings(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NotarizationDelaySettings>;

    /// Returns the upper bound for the number of dealings we allow in a block.
    fn get_dkg_dealings_per_block(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<usize>;

    /// Returns the length of all DKG intervals for the given subnet. The
    /// interval length is the number of rounds, following the summary
    /// block, where dealers exchange their dealings.
    fn get_dkg_interval_length(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Height>;

    /// Returns whether the subnet record instructs the subnet to halt
    fn get_is_halted(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<bool>;

    /// Returns whether the subnet record instructs the subnet to halt at the next cup height
    fn get_halt_at_cup_height(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<bool>;

    /// Except for CloudEngine subnets, this just returns the value in the
    /// [SubnetRecord]'s `replica_version_id` field, which is generally the git
    /// commit ID from which Replica was built.
    ///
    /// But when the subnet is of type CloudEngine, `replica_version_id` can be
    /// blank, which means that the engine is following
    /// [StandardEngineReplicaVersionRecord]. Non-blank `replica_version_id`
    /// means the same thing as in the non-CloudEngine case.
    ///
    /// Err is returned in various cases, but we call out a few in particular,
    /// because the error type is unintuitive: DecodeError is returned in the
    /// following cases:
    ///
    /// 1. CloudEngine with blank replica_version_id, but no
    ///    StandardEngineReplicaVersionRecord.
    ///
    /// 2. Non-CloudEngine with blank replica_version_id.
    ///
    /// 3. Replica version ID string cannot be converted to a ReplicaVersion
    ///    object. This means that the string contains some illegal characters.
    ///    In particular, only latin letters, digits, dot, dash, and underscore
    ///    are allowed (as of July 2026).
    ///
    /// In practice, such data problems are prevented from happening elsewhere
    /// (specifically, Registry's invariants checks), but we mention them here
    /// for completeness.
    fn get_replica_version(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersion>;

    /// Return the [ReplicaVersionRecord] as recorded in the subnet record
    /// at the given height.
    fn get_replica_version_record(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersionRecord>;

    fn get_replica_version_record_from_version_id(
        &self,
        replica_version_id: &ReplicaVersion,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersionRecord>;

    /// Return the [RegistryVersion] at which the [SubnetRecord] for the provided
    /// [SubnetId] was last updated.
    fn get_subnet_record_registry_version(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<RegistryVersion>;

    fn get_listed_subnet_for_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<(SubnetId, SubnetRecord)>;

    fn get_all_listed_subnet_records(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<(SubnetId, SubnetRecord)>>;

    /// Get the necessary material to construct a genesis/recovery CUP for the
    /// given subnet
    fn get_cup_contents(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<CatchUpPackageContents>;

    /// Returns the maximum block payload size in bytes.
    fn get_max_block_payload_size_bytes(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<u64>;

    /// Returns the subnet type (e.g., application, system, ...)
    fn get_subnet_type(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetType>;
}

impl<T: RegistryClient + ?Sized> SubnetRegistry for T {
    fn get_subnet_record(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetRecord> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        deserialize_registry_value::<SubnetRecord>(bytes)
    }

    fn is_subnet_deleted(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<bool, RegistryClientError> {
        // The subnet record is deleted (rather than nonexistent), if...
        self.get_versioned_value(&make_subnet_record_key(subnet_id), version)
            .map(|registry_versioned_record| {
                // ...the value is not present...
                registry_versioned_record.value.is_none()
                // ...and the registry version is NOT the initial registry version.
                    && registry_versioned_record.version.get() > 0
            })
    }

    /// Return the root subnet id if it is available and can be parsed
    fn get_root_subnet_id(&self, version: RegistryVersion) -> RegistryClientResult<SubnetId> {
        let bytes = self.get_value(ROOT_SUBNET_ID_KEY, version);
        Ok(deserialize_registry_value::<SubnetIdProto>(bytes)?
            .and_then(|subnet_id_proto| subnet_id_proto.principal_id)
            .map(|pr_id| {
                PrincipalId::try_from(pr_id.raw).map_err(|err| DecodeError {
                    error: format!("get_root_subnet_id() failed with {err}"),
                })
            })
            .transpose()?
            .map(SubnetId::from))
    }

    /// Returns the default initial DKG subnet id if it is set in the registry
    /// and can be parsed.
    fn get_default_initial_dkg_subnet_id(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetId> {
        let bytes = self.get_value(DEFAULT_INITIAL_DKG_SUBNET_ID_KEY, version);
        Ok(deserialize_registry_value::<SubnetIdProto>(bytes)?
            .and_then(|subnet_id_proto| subnet_id_proto.principal_id)
            .map(|pr_id| {
                PrincipalId::try_from(pr_id.raw).map_err(|err| DecodeError {
                    error: format!("get_default_initial_dkg_subnet_id() failed with {err}"),
                })
            })
            .transpose()?
            .map(SubnetId::from))
    }

    fn get_node_ids_on_subnet(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<NodeId>> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        deserialize_registry_value::<SubnetRecord>(bytes)?
            .map(|subnet| {
                get_node_ids_from_subnet_record(&subnet).map_err(|err| DecodeError {
                    error: format!("get_node_ids_on_subnet() failed with {err}"),
                })
            })
            .transpose()
    }

    fn get_subnet_size(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<usize> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(
            deserialize_registry_value::<SubnetRecord>(bytes)?
                .map(|subnet| subnet.membership.len()),
        )
    }

    /// Returns subnet record entries related to ingress messages.
    /// When [`SubnetRecord::max_ingress_bytes_per_block`] is not provided (i.e. it's set to 0), we
    /// will use the default value defined in [`ic_limits::MAX_INGRESS_BYTES_PER_BLOCK`].
    fn get_ingress_message_settings(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<IngressMessageSettings> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        let maybe_subnet_record = deserialize_registry_value::<SubnetRecord>(bytes)?;
        Ok(maybe_subnet_record.map(|subnet| IngressMessageSettings {
            max_ingress_bytes_per_message: subnet.max_ingress_bytes_per_message as usize,
            max_ingress_messages_per_block: subnet.max_ingress_messages_per_block as usize,
            max_ingress_bytes_per_block: match subnet.max_ingress_bytes_per_block {
                0 => ic_limits::MAX_INGRESS_BYTES_PER_BLOCK,
                max_ingress_bytes_per_block @ 1.. => max_ingress_bytes_per_block,
            } as usize,
        }))
    }

    fn get_features(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetFeatures> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        let subnet = deserialize_registry_value::<SubnetRecord>(bytes)?;
        Ok(subnet
            .and_then(|subnet| subnet.features)
            .map(SubnetFeatures::from))
    }

    fn get_chain_key_config(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ChainKeyConfig> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        let subnet = deserialize_registry_value::<SubnetRecord>(bytes)?;
        subnet
            .and_then(|subnet| subnet.chain_key_config.map(ChainKeyConfig::try_from))
            .transpose()
            .map_err(|err| DecodeError {
                error: format!("get_chain_key_config() failed with {err}"),
            })
    }

    fn get_notarization_delay_settings(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NotarizationDelaySettings> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(
            deserialize_registry_value::<SubnetRecord>(bytes)?.map(|subnet| {
                NotarizationDelaySettings {
                    unit_delay: Duration::from_millis(subnet.unit_delay_millis),
                    initial_notary_delay: Duration::from_millis(subnet.initial_notary_delay_millis),
                }
            }),
        )
    }

    fn get_dkg_dealings_per_block(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<usize> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(deserialize_registry_value::<SubnetRecord>(bytes)?
            .map(|subnet| subnet.dkg_dealings_per_block as usize))
    }

    fn get_dkg_interval_length(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Height> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(deserialize_registry_value::<SubnetRecord>(bytes)?
            .map(|subnet| Height::from(subnet.dkg_interval_length)))
    }

    fn get_is_halted(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<bool> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(deserialize_registry_value::<SubnetRecord>(bytes)?.map(|subnet| subnet.is_halted))
    }

    fn get_halt_at_cup_height(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<bool> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(deserialize_registry_value::<SubnetRecord>(bytes)?
            .map(|subnet| subnet.halt_at_cup_height))
    }

    fn get_replica_version(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersion> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        let Some(subnet_record) = deserialize_registry_value::<SubnetRecord>(bytes)? else {
            return Ok(None);
        };

        let str_to_result = |replica_version_id: &str,
                             case: &str|
         -> Result<Option<ReplicaVersion>, RegistryClientError> {
            let ok = ReplicaVersion::try_from(replica_version_id)
                // This wouldn't happen in practice (because of validation that
                // happens elsewhere), but we handle it here anyway, because
                // bugs.
                .map_err(|err| DecodeError {
                    error: format!(
                        "get_replica_version({subnet_id}): {case}: '{replica_version_id}' is not a valid \
                        ReplicaVersion: {err}"
                    ),
                })?;

            Ok(Some(ok))
        };

        // Specified directly in SubnetRecord.
        if !subnet_record.replica_version_id.is_empty() {
            return str_to_result(
                &subnet_record.replica_version_id,
                "specified directly in SubnetRecord",
            );
        }

        // Only engines are allowed to have a blank replica_version_id (i.e.
        // follow the standard engine deployment). Any other subnet type
        // with a blank replica_version_id indicates a real inconsistency.
        if subnet_record.subnet_type() != SubnetType::CloudEngine {
            return Err(DecodeError {
                error: format!(
                    "get_replica_version(): subnet {subnet_id} has a blank replica_version_id, \
                     but its subnet_type is {:?}, not CloudEngine",
                    subnet_record.subnet_type()
                ),
            });
        }

        let Some(standard_engine_record) =
            get_standard_engine_replica_version_record(self, version)?
        else {
            return Err(DecodeError {
                error: format!(
                    "get_replica_version(): subnet {subnet_id} has a blank replica_version_id, \
                     but no StandardEngineReplicaVersionRecord exists to resolve it"
                ),
            });
        };

        // Decide whether to take new or old version, based on our upgrade
        // priority vs. deployment_progress.
        let priority =
            engine_upgrade_priority(subnet_id, &standard_engine_record.new_replica_version_id);
        let resolved_replica_version_id = if priority <= standard_engine_record.deployment_progress
        {
            standard_engine_record.new_replica_version_id
        } else {
            standard_engine_record.old_replica_version_id
        };

        // At this point, resolved_replica_version_id should be a git commit ID
        // in the ic repo. This just converts it from a raw string.
        str_to_result(
            &resolved_replica_version_id,
            "using standard engine replica version",
        )
    }

    fn get_replica_version_record(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersionRecord> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(match deserialize_registry_value::<SubnetRecord>(bytes)? {
            Some(record) => {
                let bytes = self.get_value(
                    &make_replica_version_key(record.replica_version_id),
                    version,
                );
                deserialize_registry_value::<ReplicaVersionRecord>(bytes)?
            }
            None => None,
        })
    }

    fn get_replica_version_record_from_version_id(
        &self,
        replica_version_id: &ReplicaVersion,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersionRecord> {
        let bytes = self.get_value(&make_replica_version_key(replica_version_id), version);
        deserialize_registry_value::<ReplicaVersionRecord>(bytes)
    }

    fn get_subnet_record_registry_version(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<RegistryVersion> {
        let record = self.get_versioned_value(&make_subnet_record_key(subnet_id), version)?;
        let result = if record.value.is_some() {
            Some(record.version)
        } else {
            None
        };
        Ok(result)
    }

    /// Given a Node ID, this method returns a pair (subnet_id, subnet_record)
    /// iff there is a subnet that contains the node_id and subnet_id is
    /// contained in the subnet list.
    fn get_listed_subnet_for_node_id(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<(SubnetId, SubnetRecord)> {
        Ok(self
            .get_all_listed_subnet_records(version)?
            .and_then(|records| {
                records.into_iter().find(|(_subnet_id, record)| {
                    get_node_ids_from_subnet_record(record)
                        .unwrap()
                        .contains(&node_id)
                })
            }))
    }

    /// Returns a list of pairs (subnet_id, subnet_record). The subnet_id and
    /// the corresponding record are contained in the list iff the subnet_id is
    /// contained in the subnet list and the corresponding subnet record exists.
    fn get_all_listed_subnet_records(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<(SubnetId, SubnetRecord)>> {
        let mut records = vec![];
        if let Some(ids) = self.get_subnet_ids(version)? {
            for id in ids {
                if let Some(r) = self.get_subnet_record(id, version)? {
                    records.push((id, r));
                }
            }
            return Ok(Some(records));
        }
        Ok(None)
    }

    fn get_cup_contents(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<CatchUpPackageContents> {
        let record =
            self.get_versioned_value(&make_catch_up_package_contents_key(subnet_id), version)?;
        let bytes = Ok(record.value);
        let value = deserialize_registry_value::<CatchUpPackageContents>(bytes)?;

        Ok(RegistryVersionedRecord {
            key: record.key,
            version: record.version,
            value,
        })
    }

    fn get_max_block_payload_size_bytes(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<u64> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(deserialize_registry_value::<SubnetRecord>(bytes)?
            .map(|subnet| subnet.max_block_payload_size))
    }

    fn get_subnet_type(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetType> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(deserialize_registry_value::<SubnetRecord>(bytes)?.map(|subnet| subnet.subnet_type()))
    }
}

fn get_standard_engine_replica_version_record<T: RegistryClient + ?Sized>(
    client: &T,
    version: RegistryVersion,
) -> RegistryClientResult<StandardEngineReplicaVersionRecord> {
    let bytes = client.get_value(&make_standard_engine_replica_version_record_key(), version);
    deserialize_registry_value::<StandardEngineReplicaVersionRecord>(bytes)
}

/// Computes an engine's upgrade priority, a pseudo-random real/floating point
/// number in the closed interval [0.0, 1.0].
///
/// When an engine's upgrade priority <= deployment_progress, the engine takes
/// the standard new replica version (otherwise, it takes the old one).
///
/// Based on 2 things (their text/display representations, for consistency):
///
/// 1. the engine's ID
/// 2. the new replica version
fn engine_upgrade_priority(subnet_id: SubnetId, new_replica_version_id: &str) -> f64 {
    let mut hasher = Sha256::new_with_context(&DomainSeparationContext::new("upgrade priority"));
    hasher.write(new_replica_version_id.as_bytes());
    hasher.write(subnet_id.to_string().as_bytes());
    let digest = hasher.finish();

    let first_8_bytes = <[u8; 8]>::try_from(&digest[0..8]).unwrap();
    let priority_int = u64::from_le_bytes(first_8_bytes);

    priority_int as f64 / u64::MAX as f64
}

pub fn get_node_ids_from_subnet_record(
    subnet: &SubnetRecord,
) -> Result<Vec<NodeId>, PrincipalIdBlobParseError> {
    subnet
        .membership
        .iter()
        .map(|n| PrincipalId::try_from(&n[..]).map(NodeId::from))
        .collect::<Result<Vec<_>, _>>()
}

/// A helper trait to access the subnet list; the list of subnets that are part
/// of the current topology of the IC.
pub trait SubnetListRegistry {
    fn get_subnet_ids(&self, version: RegistryVersion) -> RegistryClientResult<Vec<SubnetId>>;
}

impl<T: RegistryClient + ?Sized> SubnetListRegistry for T {
    fn get_subnet_ids(&self, version: RegistryVersion) -> RegistryClientResult<Vec<SubnetId>> {
        let bytes = self.get_value(make_subnet_list_record_key().as_str(), version);
        deserialize_registry_value::<SubnetListRecord>(bytes)?
            .map(|subnet| {
                subnet
                    .subnets
                    .into_iter()
                    .map(|s| {
                        Ok(SubnetId::from(
                            PrincipalId::try_from(s.as_slice()).map_err(|err| DecodeError {
                                error: format!("get_subnet_ids() failed with {err}"),
                            })?,
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
    }
}

/// Helper methods primarily used in `transport`/`p2p` where both, where
/// transport information for an entire subnetwork are often needed.
pub trait SubnetTransportRegistry {
    /// Return a list of pairs containing the node id and corresponding node
    /// record for each node on subnetwork with `subnet_id`.
    ///
    /// As the transport information is stored individually for each node, this
    /// method performs `n+1` requests, where `n` is the number of nodes on the
    /// network. Potential inconsistencies are resolved as follows:
    ///
    /// * `Ok(None)` is returned if the request for the subnet member list
    ///   returns `Ok(None)`, or if any of the requests for transport
    ///   information returns `Ok(None)`.
    /// * `Err(_)` if the request for subnet membership fails.
    /// * The method panics in all other cases.
    ///
    /// # Panics
    ///
    /// If the membership list for a subnet can be retrieved, but one of the
    /// requests for a node contained in the membership list fails, the method
    /// panics.
    fn get_subnet_node_records(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<(NodeId, NodeRecord)>>;
}

impl<T: RegistryClient + ?Sized> SubnetTransportRegistry for T {
    fn get_subnet_node_records(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<(NodeId, NodeRecord)>> {
        let membership_bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        let node_ids: Vec<_> = match deserialize_registry_value::<SubnetRecord>(membership_bytes)?
            .map(|subnet| {
                subnet
                    .membership
                    .iter()
                    .map(|n| NodeId::from(PrincipalId::try_from(&n[..]).unwrap()))
                    .collect()
            }) {
            Some(val) => val,
            None => return Ok(None),
        };

        let mut res = Vec::new();
        for node_id in node_ids {
            let node_bytes = self.get_value(&make_node_record_key(node_id), version);
            let node_record = deserialize_registry_value::<NodeRecord>(node_bytes);
            match node_record {
                Ok(Some(node_record)) => res.push((node_id, node_record)),
                Ok(None) => return Ok(None),
                _ => panic!(),
            }
        }
        Ok(Some(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::PrincipalId;
    use std::{str::FromStr, sync::Arc};

    fn node_id(id: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(id))
    }

    fn subnet_id(id: u64) -> SubnetId {
        SubnetId::from(PrincipalId::new_subnet_test_id(id))
    }

    // Helper function to create a registry client with the provided information.
    fn create_test_registry_client(
        registry_version: RegistryVersion,
        subnet_records: Vec<(SubnetId, SubnetRecord)>,
        replica_version: Option<ReplicaVersion>,
    ) -> Arc<FakeRegistryClient> {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        for (subnet_id, subnet_record) in subnet_records.into_iter() {
            data_provider
                .add(
                    &make_subnet_record_key(subnet_id),
                    registry_version,
                    Some(subnet_record),
                )
                .unwrap();
        }

        if let Some(replica_version) = replica_version {
            let replica_version_record = ReplicaVersionRecord::default();
            data_provider
                .add(
                    &make_replica_version_key(String::from(&replica_version)),
                    registry_version,
                    Some(replica_version_record),
                )
                .unwrap();
        }

        let registry = Arc::new(FakeRegistryClient::new(data_provider));
        registry.update_to_latest_version();
        registry
    }

    #[test]
    fn can_get_node_ids_from_subnet() {
        let subnet_id = subnet_id(4);
        let version = RegistryVersion::from(2);
        let subnet_record = SubnetRecord {
            membership: vec![
                node_id(32_u64).get().into_vec(),
                node_id(33_u64).get().into_vec(),
            ],
            ..Default::default()
        };

        let registry = create_test_registry_client(version, vec![(subnet_id, subnet_record)], None);

        let node_ids = registry.get_node_ids_on_subnet(subnet_id, version).unwrap();

        assert_eq!(node_ids, Some(vec![node_id(32), node_id(33)]));
    }

    #[test]
    fn can_get_replica_version_from_subnet() {
        let subnet_id = subnet_id(4);
        let version = RegistryVersion::from(2);

        let replica_version = ReplicaVersion::try_from("some_version").unwrap();
        let replica_version_record = ReplicaVersionRecord::default();

        let subnet_record = SubnetRecord {
            replica_version_id: String::from(&replica_version),
            ..Default::default()
        };

        let registry = create_test_registry_client(
            version,
            vec![(subnet_id, subnet_record)],
            Some(replica_version.clone()),
        );

        let result = registry.get_replica_version(subnet_id, version).unwrap();
        assert_eq!(result, Some(replica_version));

        let result = registry
            .get_replica_version_record(subnet_id, version)
            .unwrap();
        assert_eq!(result, Some(replica_version_record))
    }

    #[test]
    fn engine_priority_matches_hand_computed_value() {
        // Step 1: Prepare the world. Constructed directly from its known
        // text representation, so this is correct by construction.
        let subnet_id =
            SubnetId::from(PrincipalId::from_str("y6zu2-uqdaa-aaaaa-aaaap-yai").unwrap());

        // Step 2: Run the code under test.
        let priority =
            engine_upgrade_priority(subnet_id, "eb3ab997954f2a91db8a42f84132cf37078d481c");

        // Step 3: Verify result(s). Value independently computed (via
        // Python's hashlib.sha256, not this crate's own code) over
        // len(domain) || domain || "eb3ab997954f2a91db8a42f84132cf37078d481c" || subnet_id.to_string(),
        // where domain = "upgrade priority". This confirms engine_upgrade_priority
        // implements the specified recipe exactly, not just some other
        // deterministic-but-wrong one.
        assert!((priority - 0.211_377).abs() < 1e-6, "got {priority}");
    }

    #[test]
    fn engine_replica_version_selection() {
        // Step 1: Prepare the world.

        // The first two subnets in Registry use the standard engine replica
        // version by having a blank replica_version_id.
        let id_dead = subnet_id(0xDEAD);
        let id_beef = subnet_id(0xBEEF);
        let priority_dead = engine_upgrade_priority(id_dead, "new");
        let priority_beef = engine_upgrade_priority(id_beef, "new");
        let (low_subnet_id, high_subnet_id) = if priority_dead < priority_beef {
            (id_dead, id_beef)
        } else {
            (id_beef, id_dead)
        };

        let data_provider = ProtoRegistryDataProvider::new();

        // Insert the first two subnets.
        for subnet_id in [low_subnet_id, high_subnet_id] {
            data_provider
                .add(
                    &make_subnet_record_key(subnet_id),
                    RegistryVersion::from(2),
                    Some(SubnetRecord {
                        replica_version_id: "".to_string(),
                        subnet_type: SubnetType::CloudEngine as i32,
                        ..Default::default()
                    }),
                )
                .unwrap();
        }

        // The third subnet overrides, does not use the standard engine replica
        // version.
        data_provider
            .add(
                &make_subnet_record_key(subnet_id(0xCAFE)),
                RegistryVersion::from(2),
                Some(SubnetRecord {
                    replica_version_id: "override".to_string(),
                    subnet_type: SubnetType::CloudEngine as i32,
                    ..Default::default()
                }),
            )
            .unwrap();

        // Standard engine replica version.
        assert_ne!(priority_dead, priority_beef);
        let deployment_progress = (priority_dead + priority_beef) / 2.0;
        data_provider
            .add(
                &make_standard_engine_replica_version_record_key(),
                RegistryVersion::from(2),
                Some(StandardEngineReplicaVersionRecord {
                    new_replica_version_id: "new".to_string(),
                    old_replica_version_id: "old".to_string(),
                    deployment_progress,
                }),
            )
            .unwrap();

        // From the Registry data assembled above, create a RegistryClient.
        let registry = FakeRegistryClient::new(Arc::new(data_provider));
        registry.update_to_latest_version();

        // Step 2: Run the code under test.
        let low_priority_result = registry
            .get_replica_version(low_subnet_id, RegistryVersion::from(2))
            .unwrap();
        let high_priority_result = registry
            .get_replica_version(high_subnet_id, RegistryVersion::from(2))
            .unwrap();
        let override_result = registry
            .get_replica_version(subnet_id(0xCAFE), RegistryVersion::from(2))
            .unwrap();

        // Step 3: Verify result(s).
        assert_eq!(
            low_priority_result,
            Some(ReplicaVersion::try_from("new").unwrap())
        );
        assert_eq!(
            high_priority_result,
            Some(ReplicaVersion::try_from("old").unwrap())
        );
        assert_eq!(
            override_result,
            Some(ReplicaVersion::try_from("override").unwrap())
        );
    }

    // This wouldn't occur in practice, so this test is "just" for completeness.
    #[test]
    fn blank_replica_version_id_without_standard_engine_record_is_an_error() {
        // Step 1: Prepare the world. A blank-replica_version_id subnet, but
        // no StandardEngineReplicaVersionRecord at all.
        let data_provider = ProtoRegistryDataProvider::new();
        data_provider
            .add(
                &make_subnet_record_key(subnet_id(0xBABE)),
                RegistryVersion::from(2),
                Some(SubnetRecord {
                    replica_version_id: "".to_string(),
                    subnet_type: SubnetType::CloudEngine as i32,
                    ..Default::default()
                }),
            )
            .unwrap();
        let registry = FakeRegistryClient::new(Arc::new(data_provider));
        registry.update_to_latest_version();

        // Step 2: Run the code under test.
        let result = registry.get_replica_version(subnet_id(0xBABE), RegistryVersion::from(2));

        // Step 3: Verify result(s).
        assert_matches!(result, Err(RegistryClientError::DecodeError { .. }));
    }

    // This wouldn't occur in practice, so this test is "just" for completeness.
    #[test]
    fn blank_replica_version_id_on_a_non_engine_subnet_is_an_error() {
        // Step 1: Prepare the world.
        let data_provider = ProtoRegistryDataProvider::new();

        // Add just one normal (i.e. non engine) subnet.
        data_provider
            .add(
                &make_subnet_record_key(subnet_id(0xBABE)),
                RegistryVersion::from(2),
                Some(SubnetRecord {
                    replica_version_id: "".to_string(),
                    subnet_type: SubnetType::Application as i32,
                    ..Default::default()
                }),
            )
            .unwrap();

        // Assemble the above Registry data into a RegistryClient.
        let registry = FakeRegistryClient::new(Arc::new(data_provider));
        registry.update_to_latest_version();

        // Step 2: Run the code under test.
        let result = registry.get_replica_version(subnet_id(0xBABE), RegistryVersion::from(2));

        // Step 3: Verify result(s).
        assert_matches!(result, Err(RegistryClientError::DecodeError { .. }));
    }

    // This wouldn't occur in practice, so this test is "just" for completeness.
    #[test]
    fn replica_version_id_with_illegal_characters_is_an_error() {
        // Step 1: Prepare the world. A SubnetRecord whose replica_version_id
        // contains a character that ReplicaVersion::try_from rejects.
        let data_provider = ProtoRegistryDataProvider::new();
        data_provider
            .add(
                &make_subnet_record_key(subnet_id(1)),
                RegistryVersion::from(2),
                Some(SubnetRecord {
                    replica_version_id: "G@RBAGE".to_string(),
                    ..Default::default()
                }),
            )
            .unwrap();
        let registry = FakeRegistryClient::new(Arc::new(data_provider));
        registry.update_to_latest_version();

        // Step 2: Run the code under test.
        let result = registry.get_replica_version(subnet_id(1), RegistryVersion::from(2));

        // Step 3: Verify result(s).
        assert_matches!(result, Err(RegistryClientError::DecodeError { .. }));
    }

    // This wouldn't occur in practice, so this test is "just" for completeness.
    #[test]
    fn resolved_standard_engine_replica_version_id_with_illegal_characters_is_an_error() {
        // Step 1: Prepare the world. An engine subnet with a blank
        // replica_version_id, resolving (via
        // StandardEngineReplicaVersionRecord) to a new_replica_version_id
        // that ReplicaVersion::try_from rejects.
        let data_provider = ProtoRegistryDataProvider::new();
        data_provider
            .add(
                &make_subnet_record_key(subnet_id(1)),
                RegistryVersion::from(2),
                Some(SubnetRecord {
                    replica_version_id: "".to_string(),
                    subnet_type: SubnetType::CloudEngine as i32,
                    ..Default::default()
                }),
            )
            .unwrap();
        data_provider
            .add(
                &make_standard_engine_replica_version_record_key(),
                RegistryVersion::from(2),
                Some(StandardEngineReplicaVersionRecord {
                    new_replica_version_id: "G@RBAGE".to_string(),
                    old_replica_version_id: "old".to_string(),
                    // Guarantees priority <= this, so new_replica_version_id
                    // (the illegal one) is the one that gets resolved.
                    deployment_progress: 1.0,
                }),
            )
            .unwrap();
        let registry = FakeRegistryClient::new(Arc::new(data_provider));
        registry.update_to_latest_version();

        // Step 2: Run the code under test.
        let result = registry.get_replica_version(subnet_id(1), RegistryVersion::from(2));

        // Step 3: Verify result(s).
        assert_matches!(result, Err(RegistryClientError::DecodeError { .. }));
    }

    #[test]
    fn can_get_is_halted_from_subnet() {
        let subnet_id = subnet_id(4);
        let version = RegistryVersion::from(2);

        for is_halted in [false, true] {
            let subnet_record = SubnetRecord {
                is_halted,
                ..Default::default()
            };

            let registry =
                create_test_registry_client(version, vec![(subnet_id, subnet_record)], None);

            assert_eq!(
                registry.get_is_halted(subnet_id, version),
                Ok(Some(is_halted))
            );
        }
    }

    #[test]
    fn can_get_halt_at_cup_height_from_subnet() {
        let subnet_id = subnet_id(4);
        let version = RegistryVersion::from(2);

        for halt_at_cup_height in [false, true] {
            let subnet_record = SubnetRecord {
                halt_at_cup_height,
                ..Default::default()
            };

            let registry =
                create_test_registry_client(version, vec![(subnet_id, subnet_record)], None);

            assert_eq!(
                registry.get_halt_at_cup_height(subnet_id, version),
                Ok(Some(halt_at_cup_height))
            );
        }
    }

    #[test]
    fn can_get_max_block_size_from_subnet_record() {
        let subnet_id = subnet_id(4);
        let version = RegistryVersion::from(2);
        let max_block_payload_size_bytes = 4 * 1024 * 1024; // 4MiB
        let replica_version = ReplicaVersion::try_from("some_version").unwrap();

        let subnet_record = SubnetRecord {
            max_block_payload_size: max_block_payload_size_bytes,
            replica_version_id: String::from(&replica_version),
            ..Default::default()
        };

        let registry = create_test_registry_client(
            version,
            vec![(subnet_id, subnet_record)],
            Some(replica_version.clone()),
        );

        let result = registry.get_replica_version(subnet_id, version).unwrap();
        assert_eq!(result, Some(replica_version));

        let result = registry
            .get_max_block_payload_size_bytes(subnet_id, version)
            .unwrap();
        assert_eq!(result, Some(max_block_payload_size_bytes))
    }
}
