use crate::registry::{Registry, Version};
use candid::{CandidType, Encode};
use dfn_core::call;
use ic_base_types::SubnetId;
use ic_management_canister_types_private::{SetupInitialDKGArgs, SetupInitialDKGResponse};
use ic_protobuf::registry::subnet::v1::{self as pb, CatchUpPackageContents, SubnetRecord};
use ic_registry_keys::{
    make_canister_migrations_record_key, make_catch_up_package_contents_key,
    make_crypto_threshold_signing_pubkey_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges, WellFormedError, is_subset_of};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, update};
use ic_types::{CanisterId, NodeId, PrincipalId, RegistryVersion, subnet_id_into_protobuf};
use on_wire::bytes;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryFrom};

#[derive(Debug, PartialEq, Eq)]
/// Error which might occuring during validation of a payload.
enum PayloadValidationError {
    FailedToGetSourceSubnetRecord(String),
    UnknownNodeId(NodeId),
    UnequalSplit {
        proposed_destination_subnet_size: usize,
        current_source_subnet_size: usize,
    },
    DisallowedSourceSubnetType(SubnetType),
    SourceSubnetIsSigningSubnet,
    UnhostedCanisterIds,
    SplitAlreadyInProgress,
    EmptyDestinationCanisterIdRanges,
    EmptySourceCanisterIdRanges,
    NotEnabled,
    DuplcateDestinationNodeIds,
    InvalidCanisterIdRanges(WellFormedError),
}

#[cfg(not(test))]
/// Accept proposals only if the subnet splitting feature has been already enabled in the consensus.
const ENABLED: bool = ic_consensus_features::SUBNET_SPLITTING_V2_ENABLED;
#[cfg(test)]
/// In the test cases assume the feature is enabled.
const ENABLED: bool = true;

/// For now we only support splitting application subnets. Splitting system subnets is not allowed.
const SUPPORTED_SUBNET_TYPES: [SubnetType; 2] =
    [SubnetType::Application, SubnetType::VerifiedApplication];

impl Registry {
    /// Validates the payload and applies the mutation derived from the payload to the registry.
    ///
    /// The following mutations will be performed on the registry:
    /// 1. add a new subnet,
    /// 2. update the subnet list record to include the newly added subnet,
    /// 3. update the catch up package contents of the `source` subnet, to include an information
    ///    that the subnet is split,
    /// 4. create catch up package contents for the newly added subnet,
    /// 5. modify the routing table and reroute some of the canister ids from the source subnet to
    ///    the newly added subnet,
    /// 6. modify the CanisterMigrations entry, to also include the information that the source
    ///    subnet is being split.
    pub async fn split_subnet(&mut self, payload: SplitSubnetPayload) -> Result<(), String> {
        let pre_call_registry_version = self.latest_version();

        let (mut source_subnet_record, ranges_to_migrate) = self
            .validate_subnet_splitting_payload(&payload, pre_call_registry_version)
            .map_err(|err| format!("Failed to validate the payload: {err}"))?;
        let mut destination_subnet_record = source_subnet_record.clone();
        let source_nodes: Vec<NodeId> = source_subnet_record
            .membership
            .iter()
            .map(|bytes| {
                NodeId::from(PrincipalId::try_from(bytes).expect("Malformed registry entry"))
            })
            .filter(|node_id| !payload.destination_node_ids.contains(node_id))
            .collect();

        source_subnet_record.membership =
            source_nodes.iter().map(|id| id.get().into_vec()).collect();
        destination_subnet_record.membership = payload
            .destination_node_ids
            .iter()
            .map(|id| id.get().into_vec())
            .collect();

        let create_cup_contents = |nodes| async {
            let request =
                SetupInitialDKGArgs::new(nodes, RegistryVersion::new(pre_call_registry_version));
            let raw_response = call(
                CanisterId::ic_00(),
                "setup_initial_dkg",
                bytes,
                Encode!(&request).unwrap(),
            )
            .await
            .unwrap();

            let dkg_response = SetupInitialDKGResponse::decode(&raw_response).unwrap();

            let cup_contents = CatchUpPackageContents {
                initial_ni_dkg_transcript_low_threshold: Some(
                    dkg_response.low_threshold_transcript_record.clone(),
                ),
                initial_ni_dkg_transcript_high_threshold: Some(
                    dkg_response.high_threshold_transcript_record.clone(),
                ),
                ..CatchUpPackageContents::default()
            };

            (cup_contents, dkg_response)
        };

        let (destination_cup_contents, mut source_cup_contents) = futures::join!(
            create_cup_contents(payload.destination_node_ids.clone()),
            create_cup_contents(source_nodes)
        );
        let post_call_registry_version = self.latest_version();

        self.check_if_registry_changed_across_versions(
            payload.source_subnet_id,
            pre_call_registry_version,
            post_call_registry_version,
        )
        .map_err(|err| {
            format!("The registry was updated during the `setup_initial_dkg` calls: {err}")
        })?;
        // Just a safety check that the payload is still valid after the `setup_initial_dkg` calls
        self.validate_subnet_splitting_payload(&payload, post_call_registry_version)
            .map_err(|err| {
                format!("Failed to validate the payload after `setup_initial_dkg` calls: {err}")
            })?;

        let destination_subnet_id = destination_cup_contents.1.fresh_subnet_id;
        source_cup_contents.0.cup_type = Some(
            pb::catch_up_package_contents::CupType::SubnetSplitting(pb::SubnetSplittingArgs {
                destination_subnet_id: Some(subnet_id_into_protobuf(
                    destination_cup_contents.1.fresh_subnet_id,
                )),
            }),
        );

        let mut subnet_list_record = self.get_subnet_list_record();

        subnet_list_record
            .subnets
            .push(destination_subnet_id.get().to_vec());

        let mut mutations = vec![
            update(
                make_subnet_list_record_key(),
                subnet_list_record.encode_to_vec(),
            ),
            // source subnet record changes
            update(
                make_subnet_record_key(payload.source_subnet_id),
                source_subnet_record.encode_to_vec(),
            ),
            // source subnet threshold public key
            update(
                make_crypto_threshold_signing_pubkey_key(payload.source_subnet_id),
                source_cup_contents
                    .1
                    .subnet_threshold_public_key
                    .encode_to_vec(),
            ),
            // source cup contents
            update(
                make_catch_up_package_contents_key(payload.source_subnet_id),
                source_cup_contents.0.encode_to_vec(),
            ),
            // destination subnet record changes
            insert(
                make_subnet_record_key(destination_subnet_id),
                destination_subnet_record.encode_to_vec(),
            ),
            // destination subnet threshold public key
            insert(
                make_crypto_threshold_signing_pubkey_key(
                    destination_cup_contents.1.fresh_subnet_id,
                ),
                destination_cup_contents
                    .1
                    .subnet_threshold_public_key
                    .encode_to_vec(),
            ),
            // destination cup contents
            insert(
                make_catch_up_package_contents_key(destination_cup_contents.1.fresh_subnet_id),
                destination_cup_contents.0.encode_to_vec(),
            ),
        ];

        mutations.push(self.migrate_canister_ranges_mutation(
            post_call_registry_version,
            ranges_to_migrate.clone(),
            payload.source_subnet_id,
            destination_subnet_id,
        ));

        mutations.extend(self.add_subnet_to_routing_table_and_reroute(
            post_call_registry_version,
            ranges_to_migrate,
            destination_subnet_id,
        ));

        self.maybe_apply_mutation_internal(mutations);

        Ok(())
    }

    /// Validates the [`SplitSubnetPayload`] and returns the [`SubnetRecord`] of the subnet which is
    /// being proposed to be split.
    fn validate_subnet_splitting_payload(
        &self,
        payload: &SplitSubnetPayload,
        registry_version: Version,
    ) -> Result<(SubnetRecord, CanisterIdRanges), PayloadValidationError> {
        if !ENABLED {
            return Err(PayloadValidationError::NotEnabled);
        }

        let source_subnet_record = self
            .get_subnet(payload.source_subnet_id, registry_version)
            .map_err(PayloadValidationError::FailedToGetSourceSubnetRecord)?;

        let source_subnet_type = SubnetType::try_from(source_subnet_record.subnet_type)
            .expect("Malformed registry entry");

        if !SUPPORTED_SUBNET_TYPES.contains(&source_subnet_type) {
            return Err(PayloadValidationError::DisallowedSourceSubnetType(
                source_subnet_type,
            ));
        }

        let source_nodes: HashSet<NodeId> = source_subnet_record
            .membership
            .iter()
            .map(|bytes| {
                NodeId::from(PrincipalId::try_from(bytes).expect("Malformed registry entry"))
            })
            .collect();

        let destination_nodes: HashSet<&NodeId> = HashSet::from_iter(&payload.destination_node_ids);
        if destination_nodes.len() != payload.destination_node_ids.len() {
            return Err(PayloadValidationError::DuplcateDestinationNodeIds);
        }

        if 2 * destination_nodes.len() != source_nodes.len() {
            return Err(PayloadValidationError::UnequalSplit {
                proposed_destination_subnet_size: payload.destination_node_ids.len(),
                current_source_subnet_size: source_nodes.len(),
            });
        }

        for node_id in &payload.destination_node_ids {
            if !source_nodes.contains(node_id) {
                return Err(PayloadValidationError::UnknownNodeId(*node_id));
            }
        }

        if source_subnet_record
            .chain_key_config
            .as_ref()
            .is_some_and(|chain_key_config| !chain_key_config.key_configs.is_empty())
        {
            return Err(PayloadValidationError::SourceSubnetIsSigningSubnet);
        }

        let routing_table = self.get_routing_table_or_panic(registry_version);
        let source_subnet_ranges = routing_table.ranges(payload.source_subnet_id);

        if payload.destination_canister_ranges.is_empty() {
            return Err(PayloadValidationError::EmptyDestinationCanisterIdRanges);
        }

        // Check if all the canister ID ranges to be migrated are from the source subnet.
        if !is_subset_of(
            payload.destination_canister_ranges.iter(),
            source_subnet_ranges.iter(),
        ) {
            return Err(PayloadValidationError::UnhostedCanisterIds);
        }

        // Make sure we don't migrate all the canister ids from the source subnet.
        if is_subset_of(
            source_subnet_ranges.iter(),
            payload.destination_canister_ranges.iter(),
        ) {
            return Err(PayloadValidationError::EmptySourceCanisterIdRanges);
        }

        if self
            .get_canister_migrations(registry_version)
            .is_some_and(|migrations| {
                migrations
                    .iter()
                    .any(|(_, subnet_ids)| subnet_ids.contains(&payload.source_subnet_id))
            })
        {
            return Err(PayloadValidationError::SplitAlreadyInProgress);
        }

        let ranges_to_migrate =
            CanisterIdRanges::try_from(payload.destination_canister_ranges.clone())
                .map_err(PayloadValidationError::InvalidCanisterIdRanges)?;

        Ok((source_subnet_record, ranges_to_migrate))
    }

    /// Checks to make sure records did not change during the async call
    fn check_if_registry_changed_across_versions(
        &self,
        source_subnet_id: SubnetId,
        initial_registry_version: Version,
        current_registry_version: Version,
    ) -> Result<(), &str> {
        let record_changed_across_versions = |key: String| {
            let initial_record_version =
                self.get_record_version_as_of_registry_version(&key, initial_registry_version);
            let current_record_version =
                self.get_record_version_as_of_registry_version(&key, current_registry_version);

            initial_record_version != current_record_version
        };

        if record_changed_across_versions(make_subnet_record_key(source_subnet_id)) {
            return Err("Subnet changed");
        }

        if record_changed_across_versions(make_crypto_threshold_signing_pubkey_key(
            source_subnet_id,
        )) {
            return Err("Threshold signing public key changed");
        }

        if record_changed_across_versions(make_catch_up_package_contents_key(source_subnet_id)) {
            return Err("CUP changed");
        }

        if record_changed_across_versions(make_canister_migrations_record_key()) {
            return Err("Canister migrations changed");
        }

        Ok(())
    }

    fn get_record_version_as_of_registry_version(
        &self,
        record_key: &str,
        version: Version,
    ) -> Version {
        self.get(record_key.as_bytes(), version)
            .map(|record| record.version)
            .unwrap_or_else(|| {
                panic!("Record for {record_key} not found in registry");
            })
    }
}

#[derive(Debug, CandidType, Deserialize, Serialize)]
pub struct SplitSubnetPayload {
    pub destination_canister_ranges: Vec<CanisterIdRange>,
    pub destination_node_ids: Vec<NodeId>,
    pub source_subnet_id: SubnetId,
}

impl std::fmt::Display for PayloadValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadValidationError::FailedToGetSourceSubnetRecord(err) => write!(
                f,
                "Failed to get the subnet record of the source subnet: {err}"
            ),
            PayloadValidationError::UnknownNodeId(node_id) => write!(
                f,
                "The node with id {node_id} is not a member of the source subnet"
            ),
            PayloadValidationError::UnequalSplit {
                proposed_destination_subnet_size,
                current_source_subnet_size,
            } => write!(
                f,
                "The proposed split would result in subnets with uneven sizes. \
                Current source subnet size: {current_source_subnet_size} vs \
                proposed destination subnet size: {proposed_destination_subnet_size}"
            ),
            PayloadValidationError::DisallowedSourceSubnetType(subnet_type) => write!(
                f,
                "Subnets of type {subnet_type:?} is not allowed to be split"
            ),
            PayloadValidationError::SourceSubnetIsSigningSubnet => {
                write!(f, "Signing subnets are not allowed to be split")
            }
            PayloadValidationError::UnhostedCanisterIds => write!(
                f,
                "Some the canister id ranges are not hosted by the source subnet"
            ),
            PayloadValidationError::SplitAlreadyInProgress => {
                write!(f, "Currently we allow only one subnet splitting at a time")
            }
            PayloadValidationError::EmptyDestinationCanisterIdRanges => {
                write!(f, "We expect at least one canister range to be migrated")
            }
            PayloadValidationError::EmptySourceCanisterIdRanges => {
                write!(
                    f,
                    "We don't allow migrating all canisters from the source subnet"
                )
            }
            PayloadValidationError::NotEnabled => {
                write!(f, "Subnet Splitting is not yet enabled on the IC")
            }
            PayloadValidationError::DuplcateDestinationNodeIds => {
                write!(f, "The payload contains duplicate destination node ids")
            }
            PayloadValidationError::InvalidCanisterIdRanges(error) => {
                write!(
                    f,
                    "The payload contains invalid canister id ranges: {error:?}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::test_helpers::{
            add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
            prepare_registry_with_nodes,
        },
        mutations::routing_table::routing_table_into_registry_mutation,
    };
    use ic_management_canister_types_private::{EcdsaCurve, EcdsaKeyId, MasterPublicKeyId};
    use ic_protobuf::registry::{
        crypto::v1::PublicKey,
        subnet::v1::{ChainKeyConfig as ChainKeyConfigPb, KeyConfig as KeyConfigPb},
    };
    use ic_protobuf::types::v1::MasterPublicKeyId as MasterPublicKeyIdPb;
    use ic_registry_routing_table::RoutingTable;
    use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
    use ic_types_test_utils::ids::{
        NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, SUBNET_1, SUBNET_2, SUBNET_3, SUBNET_4, SUBNET_5,
        canister_test_id,
    };
    use rstest::rstest;
    use std::collections::BTreeMap;

    const FAKE_NODE_IDS_IN_THE_REGISTRY: &[NodeId; 4] = &[NODE_1, NODE_2, NODE_3, NODE_4];

    #[rstest]
    #[case::happy_path(
        SubnetInfo {
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            ..invariants_compliant_payload()
        },
        Ok(())
    )]
    #[case::unknown_source_subnet_id(
        SubnetInfo {
            subnet_id: SUBNET_1,
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            source_subnet_id: SUBNET_2,
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::FailedToGetSourceSubnetRecord(
            format!("Subnet record for {SUBNET_2} not found in the registry.")
        )),
    )]
    #[case::cannot_split_system_subnet(
        SubnetInfo {
            subnet_type: SubnetType::System,
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::DisallowedSourceSubnetType(SubnetType::System))
    )]
    #[case::too_few_nodes_on_the_destination_subnet(
        SubnetInfo {
            nodes: vec![NODE_1, NODE_2, NODE_3, NODE_4],
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            destination_node_ids: vec![NODE_2],
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::UnequalSplit {
            proposed_destination_subnet_size: 1,
            current_source_subnet_size: 4,
        })
    )]
    #[case::too_many_nodes_on_the_destination_subnet(
        SubnetInfo {
            nodes: vec![NODE_1, NODE_2, NODE_3, NODE_4],
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            destination_node_ids: vec![NODE_2, NODE_3, NODE_4],
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::UnequalSplit {
            proposed_destination_subnet_size: 3,
            current_source_subnet_size: 4,
        })
    )]
    #[case::unknown_node_id(
        SubnetInfo {
            nodes: vec![NODE_1, NODE_2, NODE_3, NODE_4],
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            destination_node_ids: vec![NODE_4, NODE_5],
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::UnknownNodeId(NODE_5))
    )]
    #[case::unhosted_canister_ids(
        SubnetInfo {
            canister_id_ranges: vec![CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(10),
            }],
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            destination_canister_ranges: vec![CanisterIdRange {
                start: canister_test_id(5),
                end: canister_test_id(15),
            }],
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::UnhostedCanisterIds)
    )]
    #[case::empty_canister_ranges(
        SubnetInfo {
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            destination_canister_ranges: vec![],
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::EmptyDestinationCanisterIdRanges)
    )]
    #[case::trying_to_migrate_all_canister_ranges(
        SubnetInfo {
            canister_id_ranges: vec![CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(10),
            }],
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            destination_canister_ranges: vec![CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(10),
            }],
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::EmptySourceCanisterIdRanges)
    )]
    #[case::cannot_split_signing_subnet(
        SubnetInfo {
            is_signing: true,
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::SourceSubnetIsSigningSubnet)
    )]
    #[case::cannot_split_a_subnet_already_being_split(
        SubnetInfo {
            is_already_being_split: true,
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::SplitAlreadyInProgress)
    )]
    #[case::duplicate_destination_node_ids(
        SubnetInfo {
            is_already_being_split: true,
            ..invariants_compliant_subnet_info()
        },
        SplitSubnetPayload {
            destination_node_ids: vec![NODE_4, NODE_4],
            ..invariants_compliant_payload()
        },
        Err(PayloadValidationError::DuplcateDestinationNodeIds)
    )]
    #[case::non_disjoint_canister_ranges(
            SubnetInfo {
                canister_id_ranges: vec![CanisterIdRange {
                    start: canister_test_id(0),
                    end: canister_test_id(20),
                }],
                ..invariants_compliant_subnet_info()
            },
            SplitSubnetPayload {
                destination_canister_ranges: vec![
                    CanisterIdRange {
                        start: canister_test_id(5),
                        end: canister_test_id(10),
                    },
                    CanisterIdRange {
                        start: canister_test_id(5),
                        end: canister_test_id(15),
                    },
                ],
                ..invariants_compliant_payload()
            },
            Err(PayloadValidationError::InvalidCanisterIdRanges(
                WellFormedError::CanisterIdRangeNotSortedOrNotDisjoint(
                    "previous_end qaa6y-5yaaa-aaaaa-aaafa-cai >= current_start rno2w-sqaaa-aaaaa-aaacq-cai".into()
                )
            )),
        )]
    fn payload_validation_test(
        #[case] source_subnet_info: SubnetInfo,
        #[case] payload: SplitSubnetPayload,
        #[case] expected_result: Result<(), PayloadValidationError>,
    ) {
        let (registry, node_infos) = set_up_registry(source_subnet_info);
        // Warning: hack ahead! When we set up the registry, we create public keys of the nodes, and
        // then derive the subnet ids from these public keys. Since, we can't know a priori what the
        // subnet ids will look like, we are remapping the static subnet ids provided as an input
        // (e.g. SUBNET_1, SUBNET_2) to the dynamically created ones. This simplifies slightly
        // setting up the test cases.
        let payload_node_ids = payload
            .destination_node_ids
            .iter()
            .map(|node_id| node_infos.get(node_id).map(|(id, _)| id).unwrap_or(node_id))
            .copied()
            .collect();
        let payload = SplitSubnetPayload {
            destination_canister_ranges: payload.destination_canister_ranges,
            destination_node_ids: payload_node_ids,
            source_subnet_id: payload.source_subnet_id,
        };

        let validation_result = registry
            .validate_subnet_splitting_payload(&payload, registry.latest_version())
            .map(|_| ());
        assert_eq!(validation_result, expected_result);
    }

    #[derive(Debug)]
    struct SubnetInfo {
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        nodes: Vec<NodeId>,
        canister_id_ranges: Vec<CanisterIdRange>,
        is_signing: bool,
        is_already_being_split: bool,
    }

    fn invariants_compliant_subnet_info() -> SubnetInfo {
        SubnetInfo {
            subnet_id: SUBNET_1,
            subnet_type: SubnetType::Application,
            nodes: vec![NODE_1, NODE_2, NODE_3, NODE_4],
            canister_id_ranges: vec![CanisterIdRange {
                start: canister_test_id(0),
                end: canister_test_id(10),
            }],
            is_signing: false,
            is_already_being_split: false,
        }
    }

    fn invariants_compliant_payload() -> SplitSubnetPayload {
        SplitSubnetPayload {
            destination_canister_ranges: vec![CanisterIdRange {
                start: canister_test_id(3),
                end: canister_test_id(6),
            }],
            destination_node_ids: vec![NODE_2, NODE_3],
            source_subnet_id: SUBNET_1,
        }
    }

    fn set_up_registry(
        source_subnet_info: SubnetInfo,
    ) -> (Registry, BTreeMap<NodeId, (NodeId, PublicKey)>) {
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, source_node_ids_and_dkg_pks) =
            prepare_registry_with_nodes(1, FAKE_NODE_IDS_IN_THE_REGISTRY.len() as u64);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_infos: BTreeMap<_, _> = FAKE_NODE_IDS_IN_THE_REGISTRY
            .iter()
            .copied()
            .zip(source_node_ids_and_dkg_pks)
            .collect();

        // Add subnets to the registry
        let mut subnet_list_record = registry.get_subnet_list_record();
        let mut source_subnet_record = get_invariant_compliant_subnet_record(
            source_subnet_info
                .nodes
                .iter()
                .map(|node_id| node_infos.get(node_id).unwrap().0)
                .collect(),
        );
        source_subnet_record.subnet_type = source_subnet_info.subnet_type.into();

        if source_subnet_info.is_signing {
            let key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "foo-bar".to_string(),
            });
            source_subnet_record.chain_key_config = Some(ChainKeyConfigPb {
                key_configs: vec![KeyConfigPb {
                    key_id: Some(MasterPublicKeyIdPb::from(&key_id)),
                    pre_signatures_to_create_in_advance: key_id
                        .requires_pre_signatures()
                        .then_some(100),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                }],
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
                max_parallel_pre_signature_transcripts_in_creation: None,
            });
        }

        let subnet_mutations = add_fake_subnet(
            source_subnet_info.subnet_id,
            &mut subnet_list_record,
            source_subnet_record,
            &source_subnet_info
                .nodes
                .iter()
                .map(|test_node_id| node_infos.get(test_node_id).unwrap().clone())
                .collect(),
        );
        registry.maybe_apply_mutation_internal(subnet_mutations);

        // Add canister id ranges to the routing table
        let mut routing_table = RoutingTable::new();
        routing_table
            .assign_ranges(
                source_subnet_info.canister_id_ranges.try_into().unwrap(),
                source_subnet_info.subnet_id,
            )
            .unwrap();

        registry.maybe_apply_mutation_internal(routing_table_into_registry_mutation(
            &registry,
            routing_table,
        ));

        // Some other subnet is currently being split
        registry.maybe_apply_mutation_internal(vec![registry.migrate_canister_ranges_mutation(
            1,
            CanisterIdRanges::default(),
            SUBNET_4,
            SUBNET_5,
        )]);

        if source_subnet_info.is_already_being_split {
            let mutation = registry.migrate_canister_ranges_mutation(
                1,
                CanisterIdRanges::try_from(vec![CanisterIdRange {
                    start: canister_test_id(1),
                    end: canister_test_id(3),
                }])
                .unwrap(),
                source_subnet_info.subnet_id,
                SUBNET_3,
            );

            registry.maybe_apply_mutation_internal(vec![mutation]);
        }

        (registry, node_infos)
    }
}
