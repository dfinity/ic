use ic_logger::ReplicaLogger;
use ic_registry_routing_table::CanisterIdRanges;
use ic_types::{
    CanisterId, SubnetId,
    messages::{CertificateDelegation, CertificateDelegationFormat, CertificateDelegationMetadata},
};
use tokio::sync::watch;

use crate::{
    builder::NNSDelegationBuilder,
    validation::{CanisterRangesCheck, DelegationValidationError},
};

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
    receiver: watch::Receiver<Option<NNSDelegationBuilder>>,
    logger: ReplicaLogger,
}

impl NNSDelegationReader {
    pub fn new(
        receiver: watch::Receiver<Option<NNSDelegationBuilder>>,
        logger: ReplicaLogger,
    ) -> Self {
        Self { receiver, logger }
    }

    /// Returns the most recent NNS delegation known to the replica.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    pub fn get_delegation(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> Option<CertificateDelegation> {
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.build_or_original(canister_ranges_filter, &self.logger))
    }

    /// Returns the most recent NNS delegation known to the replica together with some metadata.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    pub fn get_delegation_with_metadata(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> Option<(CertificateDelegation, CertificateDelegationMetadata)> {
        let metadata = CertificateDelegationMetadata {
            format: match canister_ranges_filter {
                CanisterRangesFilter::Flat => CertificateDelegationFormat::Flat,
                CanisterRangesFilter::Tree(_canister_id) => CertificateDelegationFormat::Tree,
                CanisterRangesFilter::None => CertificateDelegationFormat::Pruned,
            },
        };

        self.receiver.borrow().as_ref().map(|builder| {
            (
                builder.build_or_original(canister_ranges_filter, &self.logger),
                metadata,
            )
        })
    }

    /// Checks whether the most recent NNS delegation known to the replica is consistent
    /// with the given view of the subnet information recorded in a replicated state.
    ///
    /// `state_view_for_subnet` should resolve the threshold public key and the canister
    /// ranges which the state assigns to the delegated subnet, e.g.
    /// ```ignore
    /// |subnet_id| {
    ///     network_topology
    ///         .subnets_for_certification()
    ///         .get(&subnet_id)
    ///         .map(|topology| (
    ///             topology.public_key.clone(),
    ///             network_topology.routing_table_for_certification().ranges(subnet_id),
    ///         ))
    /// }
    /// ```
    /// Resolving to `None` maps to [`DelegationValidationError::UnknownSubnet`].
    /// `ranges_check` specifies what to check the certified canister ranges against
    /// (see [`CanisterRangesCheck`]).
    ///
    /// Returns `Ok(true)` if no delegation is present (on the NNS subnet, or when the
    /// delegation has not been fetched yet). Otherwise see
    /// [`NNSDelegationBuilder::is_consistent_with`] for the exact semantics.
    pub fn is_consistent_with(
        &self,
        state_view_for_subnet: impl FnOnce(SubnetId) -> Option<(Vec<u8>, CanisterIdRanges)>,
        ranges_check: CanisterRangesCheck,
    ) -> Result<bool, DelegationValidationError> {
        match self.receiver.borrow().as_ref() {
            None => Ok(true),
            Some(builder) => {
                let subnet_id = builder.subnet_id();
                let (public_key, subnet_ranges) = state_view_for_subnet(subnet_id)
                    .ok_or(DelegationValidationError::UnknownSubnet(subnet_id))?;
                builder.is_consistent_with(&public_key, &subnet_ranges, ranges_check)
            }
        }
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use ic_certification::verify_delegation_certificate;
    use ic_crypto_tree_hash::{LabeledTree, lookup_path};
    use ic_logger::no_op_logger;
    use ic_nns_delegation_reader_test_utils::create_fake_certificate_delegation;
    use ic_registry_routing_table::CanisterIdRange;
    use ic_test_utilities_types::ids::SUBNET_0;
    use ic_types::messages::Certificate;

    fn parse_labeled_tree(delegation: &CertificateDelegation) -> LabeledTree<Vec<u8>> {
        let parsed_delegation: Certificate =
            serde_cbor::from_slice(&delegation.certificate).unwrap();

        LabeledTree::try_from(parsed_delegation.tree.clone()).unwrap()
    }

    fn path_exists(delegation: &CertificateDelegation, path: &[&[u8]]) -> bool {
        lookup_path(&parse_labeled_tree(delegation), path).is_some()
    }

    pub fn create_reader(
        delegation: Option<CertificateDelegation>,
        subnet_id: SubnetId,
    ) -> NNSDelegationReader {
        let builder = delegation.map(|delegation| {
            NNSDelegationBuilder::try_new(delegation.certificate, subnet_id, &no_op_logger())
                .unwrap()
        });
        let (_sender, receiver) = watch::channel(builder);

        NNSDelegationReader {
            receiver,
            logger: no_op_logger(),
        }
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

    /// The canister ranges the consistency check fixture's delegation certifies.
    const RANGES: &[(u64, u64)] = &[(0, 10), (100, 200)];

    /// The canister ranges a state assigns to a subnet.
    fn subnet_ranges(ranges: &[(u64, u64)]) -> CanisterIdRanges {
        CanisterIdRanges::try_from(
            ranges
                .iter()
                .map(|(start, end)| CanisterIdRange {
                    start: CanisterId::from(*start),
                    end: CanisterId::from(*end),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    /// Creates a reader holding a fake delegation for `SUBNET_0` certifying [`RANGES`],
    /// and returns it together with the public key certified in the delegation.
    fn create_consistency_check_fixture() -> (NNSDelegationReader, Vec<u8>) {
        let (full_delegation, _root_public_key) = create_fake_certificate_delegation(
            &RANGES
                .iter()
                .map(|(start, end)| (CanisterId::from(*start), CanisterId::from(*end)))
                .collect(),
            SUBNET_0,
        );
        // Extract the public key certified in the delegation so that the consistency
        // check on it can succeed.
        let tree = parse_labeled_tree(&full_delegation);
        let certified_public_key =
            match lookup_path(&tree, &[b"subnet", SUBNET_0.get().as_ref(), b"public_key"]) {
                Some(LabeledTree::Leaf(public_key)) => public_key.clone(),
                _ => panic!("The fake delegation should certify a public key"),
            };

        (
            create_reader(Some(full_delegation), SUBNET_0),
            certified_public_key,
        )
    }

    #[test]
    fn matching_delegation_is_consistent_with_state() {
        let (reader, public_key) = create_consistency_check_fixture();

        assert_matches!(
            reader.is_consistent_with(
                |_subnet_id| Some((public_key.clone(), subnet_ranges(RANGES))),
                CanisterRangesCheck::AllSubnetRanges,
            ),
            Ok(true)
        );
    }

    #[test]
    fn delegation_with_mismatching_public_key_is_inconsistent_with_state() {
        let (reader, _public_key) = create_consistency_check_fixture();

        assert_matches!(
            reader.is_consistent_with(
                |_subnet_id| Some((vec![9, 9, 9], subnet_ranges(RANGES))),
                CanisterRangesCheck::AllSubnetRanges,
            ),
            Ok(false)
        );
    }

    #[test]
    fn delegation_with_mismatching_ranges_is_inconsistent_with_state() {
        let (reader, public_key) = create_consistency_check_fixture();

        assert_matches!(
            reader.is_consistent_with(
                // The state assigns an extra range to the subnet which is not certified
                // in the delegation.
                |_subnet_id| Some((
                    public_key.clone(),
                    subnet_ranges(&[(0, 10), (100, 200), (300, 400)]),
                )),
                CanisterRangesCheck::AllSubnetRanges,
            ),
            Ok(false)
        );
    }

    #[test]
    fn unknown_subnet_is_an_error() {
        let (reader, _public_key) = create_consistency_check_fixture();

        assert_matches!(
            reader.is_consistent_with(|_subnet_id| None, CanisterRangesCheck::AllSubnetRanges),
            Err(DelegationValidationError::UnknownSubnet(subnet_id)) if subnet_id == SUBNET_0
        );
    }

    #[test]
    fn missing_delegation_is_consistent_with_state() {
        let reader = create_reader(None, SUBNET_0);

        // There is no delegation (e.g. on the NNS subnet), so there is nothing to
        // compare the state against.
        assert_matches!(
            reader.is_consistent_with(|_subnet_id| None, CanisterRangesCheck::AllSubnetRanges),
            Ok(true)
        );
    }
}
