//! The upgrade permit protocol for the Phase-2 rolling GuestOS reboots.

use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::upgrade::InvalidUpgradePayloadReason;
use ic_logger::{ReplicaLogger, warn};
use ic_types::consensus::UpgradePermitAuthorizationShare;
use ic_types::{Height, NodeId, RegistryVersion};
use std::collections::BTreeSet;

pub mod pool_manager;

pub(crate) struct SubnetMembership {
    /// Current members staying even at the new CUP.
    pub staying_members: BTreeSet<NodeId>,
}

impl SubnetMembership {
    /// Is the node a current member staying even at the new CUP?
    pub fn staying(&self, node: &NodeId) -> bool {
        self.staying_members.contains(node)
    }
}

/// Subnet membership at the block height and registry version.
pub(crate) fn subnet_membership(
    membership: &Membership,
    block_height: Height,
    block_registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> SubnetMembership {
    let registry_at_height: BTreeSet<NodeId> = membership
        .get_nodes_at_version(block_registry_version)
        .map(|nodes| nodes.into_iter().collect())
        .unwrap_or_default();
    let current_members: BTreeSet<NodeId> = match membership.get_nodes(block_height) {
        Ok(nodes) => nodes.into_iter().collect(),
        Err(e) => {
            warn!(
                logger,
                "upgrade_payload: couldn't determine the committee at height {block_height:?}: {e:?}"
            );
            registry_at_height.clone()
        }
    };
    let staying_members = current_members
        .intersection(&registry_at_height)
        .cloned()
        .collect();
    SubnetMembership { staying_members }
}

/// Check a share's content, staying signer, and signature. Returns the
/// signer.
pub(crate) fn validate_share(
    share: &UpgradePermitAuthorizationShare,
    requestor: NodeId,
    request_height: Height,
    membership: &SubnetMembership,
    registry_version: RegistryVersion,
    crypto: &dyn ConsensusCrypto,
) -> Result<NodeId, InvalidUpgradePayloadReason> {
    let signer = share.signature.signer;
    if share.content.requestor != requestor || share.content.request_height != request_height {
        return Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer });
    }
    if !membership.staying(&signer) {
        return Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer });
    }
    crypto
        .verify_basic_sig(
            &share.signature.signature,
            &share.content,
            signer,
            registry_version,
        )
        .map_err(|_| InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer })?;
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_mocks::crypto::MockCrypto;
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::consensus::UpgradePermitAuthorizationRequest;
    use ic_types::crypto::{BasicSig, BasicSigOf, CryptoError};
    use ic_types::signature::BasicSignature;

    const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

    fn share(signer: u64, requestor: u64, request_height: u64) -> UpgradePermitAuthorizationShare {
        UpgradePermitAuthorizationShare {
            content: UpgradePermitAuthorizationRequest {
                requestor: node_test_id(requestor),
                request_height: Height::from(request_height),
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: node_test_id(signer),
            },
        }
    }

    fn membership(staying: &[NodeId]) -> SubnetMembership {
        SubnetMembership {
            staying_members: staying.iter().copied().collect(),
        }
    }

    #[test]
    fn test_rejects_requestor_mismatch() {
        let share = share(2, 3, 10);
        let membership = membership(&[node_test_id(1), node_test_id(2)]);
        // No verify expectation: the share is rejected before verification.
        let result = validate_share(
            &share,
            node_test_id(4),
            Height::from(10),
            &membership,
            REGISTRY_VERSION,
            &MockCrypto::new(),
        );
        assert_eq!(
            result,
            Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare {
                signer: node_test_id(2)
            })
        );
    }

    #[test]
    fn test_rejects_request_height_mismatch() {
        let share = share(2, 3, 10);
        let membership = membership(&[node_test_id(1), node_test_id(2)]);
        let result = validate_share(
            &share,
            node_test_id(3),
            Height::from(11),
            &membership,
            REGISTRY_VERSION,
            &MockCrypto::new(),
        );
        assert_eq!(
            result,
            Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare {
                signer: node_test_id(2)
            })
        );
    }

    #[test]
    fn test_rejects_non_staying_signer() {
        let share = share(2, 3, 10);
        let membership = membership(&[node_test_id(1)]);
        let result = validate_share(
            &share,
            node_test_id(3),
            Height::from(10),
            &membership,
            REGISTRY_VERSION,
            &MockCrypto::new(),
        );
        assert_eq!(
            result,
            Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare {
                signer: node_test_id(2)
            })
        );
    }

    #[test]
    fn test_rejects_invalid_signature() {
        let share = share(2, 3, 10);
        let membership = membership(&[node_test_id(1), node_test_id(2)]);
        let mut crypto = MockCrypto::new();
        crypto
            .expect_verify_basic_sig_upgrade_permit_auth()
            .returning(|_, _, _, _| {
                Err(CryptoError::TransientInternalError {
                    internal_error: "boom".to_string(),
                })
            });
        let result = validate_share(
            &share,
            node_test_id(3),
            Height::from(10),
            &membership,
            REGISTRY_VERSION,
            &crypto,
        );
        assert_eq!(
            result,
            Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare {
                signer: node_test_id(2)
            })
        );
    }
}
