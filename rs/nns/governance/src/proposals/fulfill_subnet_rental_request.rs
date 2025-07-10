use crate::{
    are_fulfill_subnet_rental_request_proposals_enabled,
    pb::v1::{governance_error::ErrorType, FulfillSubnetRentalRequest, GovernanceError},
};

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
}

/// Full git commit IDs are SHA-1s, which are hexidecimal strings of length 40.
fn is_potential_full_git_commit_id(s: &str) -> bool {
    if s.len() != 40 {
        return false;
    }

    s.chars().all(|character| character.is_ascii_hexdigit())
}
