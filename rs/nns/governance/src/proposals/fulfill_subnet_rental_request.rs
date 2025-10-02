use crate::{
    governance::{Environment, LOG_PREFIX},
    pb::v1::{FulfillSubnetRentalRequest, GovernanceError, governance_error::ErrorType},
};
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
#[allow(unused)]
use ic_cdk::println;
use ic_limits::{
    DKG_DEALINGS_PER_BLOCK, DKG_INTERVAL_HEIGHT, INITIAL_NOTARY_DELAY, MAX_BLOCK_PAYLOAD_SIZE,
    MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET, MAX_INGRESS_MESSAGES_PER_BLOCK,
    UNIT_DELAY_APP_SUBNET,
};
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
                "The `replica_version_id` is not a 40 character hexidecimal string (it was {replica_version_id:?})",
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
                        "Unable to verify that user {user} has a rental request, because \
                         unable call SubnetRentalCanister.list_rental_requests \
                         (while executing a FulfillSubnetRentalRequest proposal): {code:?}: {message}",
                    ),
                )
            })?;

        // This is a partial copy n' paste from the subnet-rental-canister repo.
        // Trying to depend on that creates a bunch of headaches, and maybe
        // requires a different set of hack(s). In particular, it slightly grows
        // the sizes of a couple of wasms. Therefore, leaving this piece of
        // "code schrapnel in the body" seems like the least harmful thing, but
        // if you find a way to do it, more power to you.
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
                    "Unable to verify that user {user} has a rental request, because \
                     unable to decode SubnetRentalCanister.list_rental_requests response: {err}",
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
                    "The user ({user}) of this FulfillSubnetRentalRequest proposal \
                     is not the user of any existing rental request in the Subnet\
                     Rental canister. Thus, we cannot proceed with executing this \
                     FulfillSubnetRentalRequest proposal.",
                ),
            ));
        }

        Ok(())
    }

    async fn create_subnet(&self, env: &Arc<dyn Environment>) -> Result<SubnetId, GovernanceError> {
        // Construct create_subnet request.
        let unit_delay_millis = u64::try_from(UNIT_DELAY_APP_SUBNET.as_millis()).unwrap_or_else(|err| {
            println!(
                "{}WARNING: unable to convert UNIT_DELAY_APP_SUBNET ({:?}) to u64 (in ms); falling back to 1_000 ms: {}",
                LOG_PREFIX, UNIT_DELAY_APP_SUBNET, err,
            );
            1_000
        });
        let initial_notary_delay_millis = u64::try_from(INITIAL_NOTARY_DELAY.as_millis()).unwrap_or_else(|err| {
            println!(
                "{}WARNING: unable to convert INITIAL_NOTARY_DELAY ({:?}) to u64 (in ms); falling back to 300 ms: {}",
                LOG_PREFIX, INITIAL_NOTARY_DELAY, err,
            );
            300
        });
        let dkg_dealings_per_block = u64::try_from(DKG_DEALINGS_PER_BLOCK).unwrap_or_else(|err| {
            println!(
                "{}WARNING: unable to convert DKG_DEALINGS_PER_BLOCK ({:?}) to u64; falling back to 1: {}",
                LOG_PREFIX, DKG_DEALINGS_PER_BLOCK, err,
            );
            1
        });
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

            // Remaining fields contain standard values. If the value is not
            // from an ic_limits constant, then, I most likely grabbed the value
            // seen here from an adopted create application subnet NNS proposal.
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
            max_ingress_bytes_per_message: MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET,
            max_ingress_messages_per_block: MAX_INGRESS_MESSAGES_PER_BLOCK,
            max_block_payload_size: MAX_BLOCK_PAYLOAD_SIZE,
            unit_delay_millis,
            initial_notary_delay_millis,
            dkg_dealings_per_block,
            dkg_interval_length: DKG_INTERVAL_HEIGHT,
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
                    format!("Unable to call the Registry.create_subnet: {code:?}: {message}",),
                )
            })?;

        // Decode response.
        let NewSubnet { new_subnet_id } = Decode!(&result, Result<NewSubnet, String>)
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Unable to decode the response from Registry.create_subnet: {err}",),
                )
            })?
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("create_subnet reply from the Registry canister was an Err: {err}",),
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
                 value could not be converted into a SubnetId: {err}",
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
        // This is a partial copy n' paste from the subnet-rental-canister repo.
        // Trying to depend on that creates a bunch of headaches, and maybe
        // requires a different set of hack(s). In particular, it slightly grows
        // the sizes of a couple of wasms. Therefore, leaving this piece of
        // "code shrapnel in the body" seems like the least harmful thing, but
        // if you find a way to do it, more power to you.
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
                    "Unable to call SubnetRentalCanister.execute_create_rental_agreement: {code:?}: {message}",
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
