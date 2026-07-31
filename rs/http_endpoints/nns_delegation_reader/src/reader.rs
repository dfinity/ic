use ic_logger::ReplicaLogger;
use ic_types::{
    CanisterId,
    messages::{CertificateDelegation, CertificateDelegationMetadata},
};
use std::sync::Arc;
use tokio::sync::watch;

use crate::builder::{NNSDelegationBuilder, metadata_for};

#[derive(Clone, Copy, Debug)]
/// Filter for the canister ranges in the NNS delegation.
pub enum CanisterRangesFilter {
    /// Keep the `/subnet/<subnet_id>/canister_ranges` leaf and purge
    /// the whole `/canister_ranges` subtree.
    Flat,
    /// Keep only the `/canister_ranges/<subnet_id>/<canister_id_lower_bound>` leaf,
    /// where `canister_id_lower_bound` is the largest label in the `/canister_ranges/<subnet_id>/`
    /// subtree which is not greater than `CanisterId`, and purge all other leaves under
    /// `/canister_ranges/<subnet_id>` and the `/subnet/<subnet_id>/canister_ranges` leaf.
    Tree(CanisterId),
    /// Purge both the `/canister_ranges` subtree and the `/subnet/<subnet_id>/canister_ranges`
    /// leaf.
    None,
}

#[derive(Clone)]
/// Wrapper around [`tokio::sync::watch::Receiver`] with some utility methods.
// TODO(CON-1487): Consider caching the delegations per canister range.
pub struct NNSDelegationReader {
    receiver: watch::Receiver<Option<Arc<NNSDelegationBuilder>>>,
    logger: ReplicaLogger,
}

impl NNSDelegationReader {
    pub fn new(
        receiver: watch::Receiver<Option<Arc<NNSDelegationBuilder>>>,
        logger: ReplicaLogger,
    ) -> Self {
        Self { receiver, logger }
    }

    /// Returns a snapshot of the most recent NNS delegation known to the replica.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    ///
    /// The snapshot is immutable, so it can be used to verify the delegation against a
    /// certified state and to build exactly the verified delegation (see
    /// [`NNSDelegationBuilder::build_verified`]), without having to worry about the
    /// delegation being concurrently replaced.
    pub fn builder(&self) -> Option<Arc<NNSDelegationBuilder>> {
        self.receiver.borrow().clone()
    }

    /// Returns the most recent NNS delegation known to the replica.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    pub fn get_delegation(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> Option<CertificateDelegation> {
        self.builder()
            .map(|builder| builder.build_or_original(canister_ranges_filter, &self.logger))
    }

    /// Returns the most recent NNS delegation known to the replica together with some metadata.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    pub fn get_delegation_with_metadata(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> Option<(CertificateDelegation, CertificateDelegationMetadata)> {
        self.builder().map(|builder| {
            (
                builder.build_or_original(canister_ranges_filter, &self.logger),
                metadata_for(canister_ranges_filter),
            )
        })
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_certification::verify_delegation_certificate;
    use ic_crypto_tree_hash::{LabeledTree, lookup_path};
    use ic_logger::no_op_logger;
    use ic_nns_delegation_reader_test_utils::create_fake_certificate_delegation;
    use ic_test_utilities_types::ids::SUBNET_0;
    use ic_types::{SubnetId, messages::Certificate};

    fn parse_labeled_tree(delegation: &CertificateDelegation) -> LabeledTree<Vec<u8>> {
        let parsed_delegation: Certificate =
            serde_cbor::from_slice(&delegation.certificate).unwrap();

        LabeledTree::try_from(parsed_delegation.tree.clone()).unwrap()
    }

    fn path_exists(delegation: &CertificateDelegation, path: &[&[u8]]) -> bool {
        lookup_path(&parse_labeled_tree(delegation), path).is_some()
    }

    fn create_reader(
        delegation: Option<CertificateDelegation>,
        subnet_id: SubnetId,
    ) -> NNSDelegationReader {
        let builder = delegation.map(|delegation| {
            Arc::new(
                NNSDelegationBuilder::try_new(delegation.certificate, subnet_id, &no_op_logger())
                    .unwrap(),
            )
        });
        let (_sender, receiver) = watch::channel(builder);

        NNSDelegationReader::new(receiver, no_op_logger())
    }

    #[test]
    fn no_ranges_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(0), CanisterId::from(10)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let reader = create_reader(Some(full_delegation), SUBNET_0);

        let delegation = reader
            .get_delegation(CanisterRangesFilter::None)
            .expect("Should succeed");

        assert!(
            !path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should have been purged"
        );
        assert!(
            !path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "Old canister ranges should have been purged"
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            None,
            /*use_signature_cache=*/ false,
        )
        .expect("The delegation should still be verifiable");
    }

    #[test]
    fn flat_ranges_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(0), CanisterId::from(10)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let reader = create_reader(Some(full_delegation), SUBNET_0);

        let delegation = reader
            .get_delegation(CanisterRangesFilter::Flat)
            .expect("Should succeed");

        assert!(
            !path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should have been purged"
        );
        assert!(
            path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "Old canister ranges should NOT have been purged"
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            Some(&CanisterId::from(150)),
            /*use_signature_cache=*/ false,
        )
        .expect("The delegation should still be verifiable");
    }

    #[test]
    fn tree_ranges_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(0), CanisterId::from(10)),
                (CanisterId::from(11), CanisterId::from(20)),
                (CanisterId::from(21), CanisterId::from(30)),
                (CanisterId::from(31), CanisterId::from(31)),
                (CanisterId::from(41), CanisterId::from(41)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let reader = create_reader(Some(full_delegation), SUBNET_0);

        let delegation = reader
            .get_delegation(CanisterRangesFilter::Tree(CanisterId::from(150)))
            .expect("Should succeed");

        assert!(
            path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should NOT have been purged"
        );
        assert!(
            !path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "Old canister ranges should have been purged"
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            Some(&CanisterId::from(150)),
            /*use_signature_cache=*/ false,
        )
        .expect(
            "Should succeed because 150 is within the range [100, 200] which \
            should not have been pruned",
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            Some(&CanisterId::from(5)),
            /*use_signature_cache=*/ false,
        )
        .expect_err("Should fail because the range [0, 10] should have been pruned from the tree");
    }

    #[test]
    fn canister_out_of_range_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(1), CanisterId::from(10)),
                (CanisterId::from(11), CanisterId::from(20)),
                (CanisterId::from(21), CanisterId::from(30)),
                (CanisterId::from(31), CanisterId::from(31)),
                (CanisterId::from(41), CanisterId::from(41)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let reader = create_reader(Some(full_delegation), SUBNET_0);

        let delegation = reader
            .get_delegation(CanisterRangesFilter::Tree(CanisterId::from(0)))
            .expect("Should succeed");

        assert!(
            !path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should have been purged because no leaf contains the \
            specified canister id"
        );
        assert!(
            !path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "Old canister ranges should have been purged"
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            None,
            /*use_signature_cache=*/ false,
        )
        .expect("The delegation should still be verifiable");
    }
}
