use crate::{
    are_fulfill_subnet_rental_request_proposals_enabled,
    governance::Environment,
    pb::v1::{governance_error::ErrorType, FulfillSubnetRentalRequest, GovernanceError},
};
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::{REGISTRY_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID};
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use registry_canister::mutations::do_create_subnet::{
    CanisterCyclesCostSchedule, CreateSubnetPayload, NewSubnet,
};
use serde::Serialize;
use std::sync::Arc;

const ABSURDLY_LARGE_NUMBER_OF_NODES_IN_A_SUBNET: usize = 1000;

impl FulfillSubnetRentalRequest {
    /// Enforces the following:
    ///
    /// * user - Must be Some.
    ///
    /// * node_ids - Must be nonempty.
    ///
    /// * replica_version_id - Must be a potential full git commit ID
    ///   (hexidecimal strgint of length 40).
    ///
    /// Note that passing this validation does NOT mean that the proposal will
    /// excute successfully. E.g. if replica_version_id is not a blessed replica
    /// version, then the proposal will fail at execution. In principle, these
    /// things could be checked at proposal creation time, but they are not
    /// because that would require calling other canisters, which makes
    /// validation code fraught with peril.
    pub(crate) fn validate(&self) -> Result<(), GovernanceError> {
        if !are_fulfill_subnet_rental_request_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "FulfillSubnetRentalRequest proposals are not enabled yet.".to_string(),
            ));
        }

        let Self {
            user,
            node_ids,
            replica_version_id,
        } = self;

        let mut defects = vec![];

        if user.is_none() {
            defects.push("The `user` field is null.".to_string());
        }

        if node_ids.is_empty() {
            defects.push("The `node_ids` field is empty.".to_string());
        } else if node_ids.len() >= ABSURDLY_LARGE_NUMBER_OF_NODES_IN_A_SUBNET {
            defects.push(format!(
                "The `node_ids` field has too many elements (had {}).",
                node_ids.len(),
            ));
        }

        if !is_potential_full_git_commit_id(replica_version_id) {
            defects.push(format!(
                "The `replica_version_id` is not a 40 character hexidecimal string (it was {:?})",
                replica_version_id,
            ));
        }

        if !defects.is_empty() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "FulfillSubnetRentalRequest is invalid for the following reason(s):\n  - {}",
                    defects.join("\n  - "),
                ),
            ));
        }

        Ok(())
    }

    pub(crate) async fn execute(
        &self,
        proposal_id: ProposalId,
        env: &Arc<dyn Environment>,
    ) -> Result<(), GovernanceError> {
        if !are_fulfill_subnet_rental_request_proposals_enabled() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "FulfillSubnetRentalRequest proposals are not enabled yet.".to_string(),
            ));
        }

        // The last step also does this, but we do this first to avoid creating
        // a subnet (in the next step) that needs to be immediately "disbanded"
        // due to it being "orphaned" (i.e. nobody can create canisters in it).
        self.verify_rental_request_exists(env).await?;

        let new_subnet_id = self.create_subnet(env).await?;
        self.notify_subnet_rental_canister_that_the_subnet_has_been_created(
            new_subnet_id,
            proposal_id,
            env,
        )
        .await
    }

    async fn verify_rental_request_exists(
        &self,
        env: &Arc<dyn Environment>,
    ) -> Result<(), GovernanceError> {
        let Some(user) = self.user else {
            // I am pretty sure that this is unreachable, because of validation
            // at proposal creation time, but if we do get to this point, it is
            // not so bad; there is no indication that there is some "mess"
            // needs to be "cleaned up" (other than fixing validation).
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "FulfillSubnetRentalRequest does not have a user, but user is required."
                    .to_string(),
            ));
        };

        let rental_requests = env
            .call_canister_method(
                SUBNET_RENTAL_CANISTER_ID,
                "list_rental_requests",
                Encode!().unwrap(),
            )
            .await
            .map_err(|(code, message)| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Unable to verify that user {} has a rental request, because \
                         unable call SubnetRentalCanister.list_rental_requests \
                         (while executing a FulfillSubnetRentalRequest proposal): {:?}: {}",
                        user, code, message,
                    ),
                )
            })?;

        // TODO(NNS1-3965): Source definition from an official Subnet Rental
        // canister library.
        #[derive(CandidType, Deserialize, Serialize)]
        struct RentalRequest {
            user: Principal,
            // The real thing actually has a bunch of other fields, but we only
            // use `user`, so this is good enough for our purposes...
        }
        let rental_requests = Decode!(&rental_requests, Vec<RentalRequest>).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Unable to verify that user {} has a rental request, because \
                     unable to decode SubnetRentalCanister.list_rental_requests response: {}",
                    user, err,
                ),
            )
        })?;

        let exists = rental_requests
            .into_iter()
            .any(|rental_request| PrincipalId::from(rental_request.user) == user);

        if !exists {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "The user ({}) of this FulfillSubnetRentalRequest proposal \
                     is not the user of any existing rental request in the Subnet\
                     Rental canister. Thus, we cannot proceed with executing this \
                     FulfillSubnetRentalRequest proposal.",
                    user,
                ),
            ));
        }

        Ok(())
    }

    async fn create_subnet(&self, env: &Arc<dyn Environment>) -> Result<SubnetId, GovernanceError> {
        // Construct create_subnet request.
        let create_subnet_payload = Encode!(&CreateSubnetPayload {
            // This is the main thing that distinguishes this subnet from "normal" subnets.
            canister_cycles_cost_schedule: Some(CanisterCyclesCostSchedule::Free),

            // Copy values from self.
            node_ids: self
                .node_ids
                .iter()
                .map(|principal_id| NodeId::from(*principal_id))
                .collect(),
            replica_version_id: self.replica_version_id.clone(),

            // Remaining fields contain standard values.
            // TODO(NNS1-3931): Confirm that the hard-coded values used
            // below are appropriate for rented subnets. (I ripped these
            // from a create_subnet proposal.)
            features: SubnetFeatures {
                canister_sandboxing: false,
                http_requests: true,
                sev_enabled: None,
            },

            subnet_type: SubnetType::Application,
            subnet_id_override: None,
            start_as_nns: false,
            is_halted: false,
            chain_key_config: None,

            // Sizes
            max_ingress_bytes_per_message: 2 << 20, // 2 MiB
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 << 20,
            unit_delay_millis: 1000,
            initial_notary_delay_millis: 300,
            dkg_dealings_per_block: 1,
            dkg_interval_length: 499,
            max_number_of_canisters: 0,

            // Authorization.
            ssh_backup_access: vec![],
            ssh_readonly_access: vec![],

            // Obsolete
            ingress_bytes_per_block_soft_cap: 0,
            gossip_max_artifact_streams_per_peer: 0,
            gossip_max_chunk_wait_ms: 0,
            gossip_max_duplicity: 0,
            gossip_max_chunk_size: 0,
            gossip_receive_check_cache_size: 0,
            gossip_pfn_evaluation_period_ms: 0,
            gossip_registry_poll_period_ms: 0,
            gossip_retransmission_request_ms: 0,
        })
        .unwrap();

        // Send request.
        let result = env
            .call_canister_method(REGISTRY_CANISTER_ID, "create_subnet", create_subnet_payload)
            .await
            .map_err(|(code, message)| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Unable to call the Registry.create_subnet: {:?}: {}",
                        code, message,
                    ),
                )
            })?;

        // Decode response.
        let NewSubnet { new_subnet_id } = Decode!(&result, NewSubnet).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Unable to decode the response from Registry.create_subnet: {}",
                    err,
                ),
            )
        })?;

        // Convert to return type.
        let new_subnet_id = new_subnet_id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::External,
                "Registry.create_subnet decoded, but the new_subnet_id field was not populated."
                    .to_string(),
            )
        })?;
        SubnetId::try_from(new_subnet_id).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Was able to decode Registry.create_subnet response, but the new_subnet_id \
                 value could not be converted into a SubnetId: {}",
                    err,
                ),
            )
        })
    }

    async fn notify_subnet_rental_canister_that_the_subnet_has_been_created(
        &self,
        new_subnet_id: SubnetId,
        proposal_id: ProposalId,
        env: &Arc<dyn Environment>,
    ) -> Result<(), GovernanceError> {
        // Gather components of the request that will be made to the Subnet Rental canister.
        let user = self.user.ok_or_else(|| {
            // This is probably unreachable, because user is checked during
            // proposal submission.
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "FulfillSubnetRentalRequest proposal lacks a value for `user`.".to_string(),
            )
        })?;
        let user = Principal::from(user);
        let subnet_id = Principal::from(new_subnet_id.get());
        let proposal_id = proposal_id.id;

        // Assemble the request.
        // TODO(NNS1-3965): Source definition from an official Subnet Rental
        // canister library.
        #[derive(CandidType, Deserialize, Serialize)]
        struct CreateRentalAgreementPayload {
            user: Principal,
            subnet_id: Principal,
            proposal_id: u64,
        }
        let request = Encode!(&CreateRentalAgreementPayload {
            user,
            subnet_id,
            proposal_id,
        })
        .unwrap();

        // Send the request.
        env.call_canister_method(
            SUBNET_RENTAL_CANISTER_ID,
            "execute_create_rental_agreement",
            request,
        )
        .await
        // Handle call error.
        .map_err(|(code, message)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Unable to call SubnetRentalCanister.execute_create_rental_agreement: {:?}: {}",
                    code, message,
                ),
            )
        })?;

        // Let the caller know that all seems to have gone well.
        Ok(())
    }
}

/// Full git commit IDs are SHA-1s, which are hexidecimal strings of length 40.
fn is_potential_full_git_commit_id(s: &str) -> bool {
    if s.len() != 40 {
        return false;
    }

    s.chars().all(|character| character.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;
