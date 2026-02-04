use crate::registry::Registry;
use candid::{CandidType, Encode};
use dfn_core::call;
use ic_base_types::SubnetId;
use ic_management_canister_types_private::{SetupInitialDKGArgs, SetupInitialDKGResponse};
use ic_protobuf::registry::subnet::v1::{self as pb, CatchUpPackageContents, SubnetRecord};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges, is_subset_of};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, update};
use ic_types::{
    CanisterId, NodeId, PrincipalId, RegistryVersion, node_id_into_protobuf,
    subnet_id_into_protobuf,
};
use on_wire::bytes;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryFrom};

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
    SimultaneousSubnetSplittingNotAllowed,
}

const SUBNET_SPLITTING_ENABLED: bool = true;

const SUPPORTED_SUBNET_TYPES: [SubnetType; 2] =
    [SubnetType::Application, SubnetType::VerifiedApplication];

impl Registry {
    /// Validates the payload and applies the mutation derived from the payload to the registry.
    pub async fn split_subnet(&mut self, payload: SplitSubnetPayload) -> Result<(), String> {
        assert!(
            SUBNET_SPLITTING_ENABLED,
            "Subnet splitting is not yet enabled"
        );

        let mut source_subnet_record = self
            .validate_subnet_splitting_payload(&payload)
            .map_err(|err| format!("Failed to validate the payload: {err}"))?;
        let mut destination_subnet_record = source_subnet_record.clone();
        let source_nodes: Vec<NodeId> = source_subnet_record
            .membership
            .iter()
            .map(|bytes| {
                NodeId::from(PrincipalId::try_from(bytes).expect("Malformed registry entry"))
            })
            .filter(|node_id| !payload.destination_node_ids.contains(&node_id))
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
                SetupInitialDKGArgs::new(nodes, RegistryVersion::new(self.latest_version()));
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
        let destination_subnet_id = destination_cup_contents.1.fresh_subnet_id;
        source_cup_contents.0.split_args = Some(pb::SubnetSplittingArgs {
            destination_subnet_id: Some(subnet_id_into_protobuf(
                destination_cup_contents.1.fresh_subnet_id,
            )),
            destination_subnet_node_ids: payload
                .destination_node_ids
                .iter()
                .map(|node_id| node_id_into_protobuf(*node_id))
                .collect(),
        });

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

        let ranges_to_migrate =
            CanisterIdRanges::try_from(payload.destination_canister_ranges).expect("FIXME");

        mutations.push(self.migrate_canister_ranges_mutation(
            self.latest_version(),
            ranges_to_migrate.clone(),
            payload.source_subnet_id,
            destination_subnet_id,
        ));

        mutations.extend(self.add_subnet_to_routing_table_and_reroute(
            self.latest_version(),
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
    ) -> Result<SubnetRecord, PayloadValidationError> {
        let source_subnet_record = self
            .get_subnet(payload.source_subnet_id, self.latest_version())
            .map_err(PayloadValidationError::FailedToGetSourceSubnetRecord)?;

        let source_nodes: HashSet<NodeId> = source_subnet_record
            .membership
            .iter()
            .map(|bytes| {
                NodeId::from(PrincipalId::try_from(bytes).expect("Malformed registry entry"))
            })
            .collect();

        if 2 * payload.destination_node_ids.len() != source_nodes.len() {
            return Err(PayloadValidationError::UnequalSplit {
                proposed_destination_subnet_size: payload.destination_node_ids.len(),
                current_source_subnet_size: source_nodes.len(),
            });
        }

        for node_id in &payload.destination_node_ids {
            if !source_nodes.contains(&node_id) {
                return Err(PayloadValidationError::UnknownNodeId(*node_id));
            }
        }

        let source_subnet_type = SubnetType::try_from(source_subnet_record.subnet_type)
            .expect("Malformed registry entry");

        if !SUPPORTED_SUBNET_TYPES.contains(&source_subnet_type) {
            return Err(PayloadValidationError::DisallowedSourceSubnetType(
                source_subnet_type,
            ));
        }

        if source_subnet_record
            .chain_key_config
            .as_ref()
            .is_some_and(|chain_key_config| !chain_key_config.key_configs.is_empty())
        {
            return Err(PayloadValidationError::SourceSubnetIsSigningSubnet);
        }

        let routing_table = self.get_routing_table_or_panic(self.latest_version());
        let source_subnet_ranges = routing_table.ranges(payload.source_subnet_id);

        // Check if all the canister ID ranges to be migrated are from the source subnet.
        if !is_subset_of(
            payload.destination_canister_ranges.iter(),
            source_subnet_ranges.iter(),
        ) {
            return Err(PayloadValidationError::UnhostedCanisterIds);
        }

        if self
            .get_canister_migrations(self.latest_version())
            .is_some()
        {
            return Err(PayloadValidationError::SimultaneousSubnetSplittingNotAllowed);
        }

        Ok(source_subnet_record)
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
            PayloadValidationError::SimultaneousSubnetSplittingNotAllowed => {
                write!(f, "Currently we allow only one subnet splitting at a time")
            }
        }
    }
}
