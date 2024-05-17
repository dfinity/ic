use crate::deserialize_registry_value;
use ic_interfaces_registry::{
    RegistryClient, RegistryClientResult, RegistryClientVersionedResult, RegistryVersionedRecord,
};
use ic_protobuf::{
    registry::{
        node::v1::NodeRecord,
        replica_version::v1::ReplicaVersionRecord,
        subnet::v1::{CatchUpPackageContents, GossipConfig, SubnetListRecord, SubnetRecord},
    },
    types::v1::SubnetId as SubnetIdProto,
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_node_record_key, make_replica_version_key,
    make_subnet_list_record_key, make_subnet_record_key, ROOT_SUBNET_ID_KEY,
};
use ic_registry_subnet_features::{ChainKeyConfig, EcdsaConfig, SubnetFeatures};
use ic_types::{
    registry::RegistryClientError::DecodeError, Height, NodeId, PrincipalId,
    PrincipalIdBlobParseError, RegistryVersion, ReplicaVersion, SubnetId,
};
use std::{
    convert::{TryFrom, TryInto},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotarizationDelaySettings {
    pub unit_delay: Duration,
    pub initial_notary_delay: Duration,
}

pub struct IngressMessageSettings {
    /// Maximum number of bytes per message. This is a hard cap, which means
    /// ingress messages greater than the limit will be dropped.
    pub max_ingress_bytes_per_message: usize,
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

    fn get_root_subnet_id(&self, version: RegistryVersion) -> RegistryClientResult<SubnetId>;

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

    /// Returns gossip config
    fn get_gossip_config(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Option<GossipConfig>>;

    /// Returns SubnetFeatures
    fn get_features(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<SubnetFeatures>;

    /// Returns ecdsa config
    fn get_ecdsa_config(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<EcdsaConfig>;

    /// Returns chain key config
    fn get_chain_key_config(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ChainKeyConfig>;

    /// Returns notarization delay settings:
    /// - the unit delay for blockmaker;
    /// - the initial delay for notary, to give time to rank-0 block
    /// propagation.
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

    /// Return the [ReplicaVersion] as recorded in the subnet record
    /// at the given height.
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

    /// Return the root subnet id if it is available and can be parsed
    fn get_root_subnet_id(&self, version: RegistryVersion) -> RegistryClientResult<SubnetId> {
        let bytes = self.get_value(ROOT_SUBNET_ID_KEY, version);
        Ok(deserialize_registry_value::<SubnetIdProto>(bytes)?
            .and_then(|subnet_id_proto| subnet_id_proto.principal_id)
            .map(|pr_id| {
                PrincipalId::try_from(pr_id.raw).map_err(|err| DecodeError {
                    error: format!("get_root_subnet_id() failed with {}", err),
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
                    error: format!("get_node_ids_on_subnet() failed with {}", err),
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

    fn get_ingress_message_settings(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<IngressMessageSettings> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        Ok(
            deserialize_registry_value::<SubnetRecord>(bytes)?.map(|subnet| {
                IngressMessageSettings {
                    max_ingress_bytes_per_message: subnet.max_ingress_bytes_per_message as usize,
                    max_ingress_messages_per_block: subnet.max_ingress_messages_per_block as usize,
                }
            }),
        )
    }

    fn get_gossip_config(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<Option<GossipConfig>> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        let subnet = deserialize_registry_value::<SubnetRecord>(bytes)?;
        Ok(subnet.map(|subnet| subnet.gossip_config))
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

    fn get_ecdsa_config(
        &self,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> RegistryClientResult<EcdsaConfig> {
        let bytes = self.get_value(&make_subnet_record_key(subnet_id), version);
        let subnet = deserialize_registry_value::<SubnetRecord>(bytes)?;
        Ok(subnet.and_then(|subnet| subnet.ecdsa_config.map(|config| config.try_into().unwrap())))
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
                error: format!("get_chain_key_config() failed with {}", err),
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
        Ok(deserialize_registry_value::<SubnetRecord>(bytes)?
            .and_then(|record| ReplicaVersion::try_from(record.replica_version_id.as_ref()).ok()))
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
                                error: format!("get_subnet_ids() failed with {}", err),
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
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::PrincipalId;
    use std::sync::Arc;

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
                node_id(32u64).get().into_vec(),
                node_id(33u64).get().into_vec(),
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
